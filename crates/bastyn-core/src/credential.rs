//! Shared "does this look like a hardcoded credential?" logic.
//!
//! Originally written for `BAS-INFRA-006` (used by both the Dockerfile
//! `ENV`/`ARG` and Docker Compose `environment:` checks -- one judgment,
//! applied in two file formats, rather than two independently-drifting
//! heuristics), and promoted from `infra::credential` to this crate-root
//! module so the generic hardcoded-credential rules in `rules/secrets.yml`
//! (`BAS-ZT1-010`/`BAS-ZT1-011`) can be authored, and checked in tests,
//! against the exact same word lists rather than a hand-drifted YAML-regex
//! copy. The YAML rule engine has no way to call this code at match time --
//! `metavariable_matches`/`metavariable_not_matches` are plain regexes -- so
//! the reuse is: this module's constants are the source of truth, the YAML
//! regexes are a hand-checked translation of them (see the comment above
//! `BAS-ZT1-010` in `rules/secrets.yml`), and `tests_secrets.rs` asserts the
//! two agree on the same value vectors these functions' own tests use.

/// Env-var / build-arg name fragments — matched after stripping `_`/`-` and
/// upper-casing — that mark a variable as holding a credential rather than
/// ordinary configuration.
///
/// Deliberately does not include `KEY` alone (far too broad: `S3_BUCKET_KEY`,
/// `PRIMARY_KEY`, `SORT_KEY` are all real, harmless config names) or `AUTH`
/// alone (`AUTH_ENABLED`, `AUTH_MODE` are booleans/enums, not secrets).
const CREDENTIAL_KEY_FRAGMENTS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "APIKEY",
    "PRIVATEKEY",
    "ACCESSKEY",
    "CREDENTIAL",
];

/// True if `name` (an env var or build-arg name) looks like it holds a
/// credential, judged from the name alone.
pub(crate) fn looks_like_credential_key(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    CREDENTIAL_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

/// Value tokens that name a storage backend, mode, or format rather than
/// holding a credential -- matched exactly (case-insensitively) against the
/// *whole* trimmed value, never a substring, so a real secret that merely
/// contains one of these words (`localpass123`) still fires. Measured
/// 2026-09-24: `SECRETKEY_STORAGE_TYPE: local` in a real docker-compose.yml
/// -- the key matches `SECRET`, so every other signal here said "secret",
/// but the value is a mode setting a deployment chooses from a small fixed
/// set, not something anyone types in as a password.
///
/// Deliberately excludes database/cloud-provider product names
/// (`postgres`, `mysql`, `redis`, `s3`, ...) and generic words like
/// `default`/`standard`/`basic`/`simple`, even though some real deployments
/// do use them as a mode/backend selector: those same words are also
/// extremely common real default passwords (`POSTGRES_PASSWORD: postgres`
/// ships in the official Postgres image's own README as a "for local dev"
/// example people routinely forget to change). This list stays limited to
/// words that could never plausibly be typed as an actual credential value.
const ENUM_MODE_VALUES: &[&str] = &[
    "local", "remote", "memory", "disk", "file", "none", "disabled", "enabled",
];

/// Value fragments — matched case-insensitively — that mark a value as an
/// obvious documentation placeholder rather than something a real deployment
/// would run with. Deliberately narrow: a genuinely weak password
/// (`password`, `admin123`) must still fire, because that is a real default
/// a `docker compose up` will actually use. Only markers that say "this is a
/// template, fill me in" are excluded.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "your_password",
    "your-password",
    "yourpassword",
    "insert_your",
    "insert-your",
    // A general "replace ..." placeholder shape, not just the narrower
    // "replace_with"/"replace-with" this subsumes: a bare `REPLACE_ME` or
    // `REPLACEME` (no "with") is just as common a placeholder and was
    // missed by the two entries below alone. Safe as a bare substring for
    // the same reason "your" is below -- the English word "replace" inside
    // a real high-entropy secret is astronomically unlikely.
    "replace",
    "xxx",
    "todo",
    "fixme",
    "example.com",
    // A general "your-...-here"/"your_..."-style placeholder shape, not just
    // the password-specific "your_password"/"your-password"/"yourpassword"
    // above: `sk-your-key-here`, `REPLACE_WITH_YOUR_ACTUAL_STRIPE_KEY`, and
    // similar template text all use "your" to mean "put your own value
    // here", regardless of which credential it is. Safe as a bare substring
    // for the same reason this file already treats "at-least"/"minimum" as
    // safe general fragments: the word "your" inside a real generated
    // secret's own random characters is astronomically unlikely, unlike a
    // broad word such as "key" or "secret" that a real secret's *name*
    // might legitimately contain.
    "your",
    // A value scrubbed *before* being written out (a log line, a persisted
    // copy of upstream API data) rather than a leaked secret -- the opposite
    // of what this check exists to catch. Measured 2026-08-31:
    // `private_repo["accessToken"] = "[REDACTED]"` in a redaction routine.
    "redacted",
    "scrubbed",
    "masked",
    // Calibration turned up two false positives of the same shape, both a
    // project's own documented local-demo secret -- and both spell out a
    // length *requirement* rather than holding secret content:
    // "...with-at-least-32-characters-long",
    // "...-secret-key-minimum-32-chars". A real secret's own text does not
    // describe how long it has to be. Narrow to that shape rather than
    // excluding any value containing "secret"/"token", which would also
    // exclude a real leaked secret that happens to name itself.
    "at-least",
    "at_least",
    "minimum",
    "characters-long",
    "chars-long",
];

/// True if `value` is a hardcoded credential literal worth reporting: not an
/// interpolation reading from the real environment, not empty, not a
/// boolean/numeric flag that merely happens to sit on a credential-named key
/// (`MYSQL_ALLOW_EMPTY_PASSWORD: yes`), and not an obvious documentation
/// placeholder.
pub(crate) fn is_hardcoded_credential_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    // `${DB_PASSWORD}` / `$DB_PASSWORD` -- the correct pattern, read from the
    // real environment at deploy time rather than committed to source.
    if trimmed.starts_with('$') {
        return false;
    }
    // A templating placeholder no real deployment runs with verbatim:
    // `{{ .Values.password }}`, `<your-password>`, `%(password)s`.
    if trimmed.starts_with("{{") || (trimmed.starts_with('<') && trimmed.ends_with('>')) {
        return false;
    }
    // A filesystem path, not a literal credential -- `GOOGLE_APPLICATION_
    // CREDENTIALS=/tmp/gcp_creds.json` points at a file mounted separately
    // (a bind mount in the same Compose service, in the real false positive
    // this excludes). Measured 2026-08-28: the only false positive this rule
    // produced across 65 real repositories that was not the length-
    // requirement shape above.
    if trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with("~/")
    {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off"
    ) {
        return false;
    }
    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    if ENUM_MODE_VALUES.contains(&lower.as_str()) {
        return false;
    }
    // `OPENAI_API_KEY_NAME=OPENAI_API_KEY` -- a SCREAMING_SNAKE_CASE value is
    // the shape of an env-var *name*, not a secret. A real secret practically
    // never comes out this way (no lowercase, no punctuation), and this is
    // the exact false positive BAS-ZT1-002's sibling check in application
    // config already excludes for the same reason.
    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && trimmed.chars().any(|ch| ch.is_ascii_uppercase())
    {
        return false;
    }
    // A credential the vendor publishes on purpose. Not a placeholder and
    // not a mistake: these keys are documented as safe to embed in
    // client-side code, so reporting one is a false positive no entropy or
    // naming heuristic can avoid -- it has every surface property of a
    // secret and is not one. See PUBLIC_BY_DESIGN_PREFIXES.
    if is_public_by_design_credential(trimmed) {
        return false;
    }
    !PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Value prefixes that identify a credential the issuing vendor publishes
/// deliberately.
///
/// These are not placeholders and not weak secrets — they are real,
/// high-entropy, correctly-named keys that are *documented as public*. A
/// `PostHog` `phc_` project key and a Stripe `pk_` publishable key are both
/// meant to ship inside a browser bundle; flagging one tells a developer to
/// rotate a credential that was never secret.
///
/// This list is the only mechanism that can exclude them. Every other signal
/// this module has says "secret": the name ends in `_API_KEY`, the value is
/// long and random, and it is assigned to a literal. Measured 2026-08-28
/// against 65 real repositories, a `PostHog` `phc_` key was the single false
/// positive `BAS-ZT1-011` produced.
///
/// Kept deliberately short. A prefix earns a place here only when the vendor
/// documents the key as publishable — never merely because a key *looks*
/// low-risk.
const PUBLIC_BY_DESIGN_PREFIXES: &[&str] = &[
    // `PostHog` project API key: write-only, documented for client-side use.
    "phc_", // Stripe publishable key, and its test-mode form.
    "pk_live_", "pk_test_",
];

/// Whether `value` is a credential its vendor publishes on purpose.
///
/// Case-sensitive on purpose: these prefixes are emitted by the vendors in
/// exactly this form, and matching case-insensitively would widen the
/// exclusion beyond what is documented.
pub(crate) fn is_public_by_design_credential(value: &str) -> bool {
    PUBLIC_BY_DESIGN_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

/// True if `value` has the shape of a provider API key.
///
/// This is `BAS-ZT1-003`'s `^sk-[A-Za-z0-9_-]{16,}$` written out, not a second
/// opinion about what a secret looks like: the same shape decides in a
/// Dockerfile, in a `.env` file, or in TypeScript source, so one config
/// cannot be a credential in one file and a harmless string in another.
/// Anchored at both ends, which is what keeps `sk-tools/bin` — a path that
/// merely starts the same way — out.
///
/// Originally private to `infra::dockerfile` (`BAS-INFRA-002`'s check); moved
/// here once `dotenv` (`BAS-ZT1-021`) needed the identical shape check on a
/// second file format.
///
/// Unlike [`is_hardcoded_credential_value`], the shape check alone used to be
/// the whole story here -- no [`PLACEHOLDER_MARKERS`] check at all. That let
/// `sk-your-key-here-1234567890abcdef` and
/// `sk-REPLACE_WITH_YOUR_ACTUAL_STRIPE_KEY` both through: 16+ characters
/// after `sk-`, every one alphanumeric/`_`/`-`, so the shape check alone
/// cannot tell a placeholder from a real key. Measured directly against a
/// user report: both values produced a `BAS-ZT1-021` finding in a genuine,
/// partially-filled-in `.env` file, not just an `.env.example`. The same
/// placeholder check `is_hardcoded_credential_value` already runs is applied
/// here too, so both callers (`dotenv`'s `BAS-ZT1-021`, `infra::dockerfile`'s
/// `BAS-INFRA-002`) get it at once.
pub(crate) fn is_provider_key_literal(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("sk-") else {
        return false;
    };
    if rest.len() < 16
        || !rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Name fragments — matched the same way as [`CREDENTIAL_KEY_FRAGMENTS`],
/// after stripping `_`/`-` and upper-casing — that identify a cloud-provider
/// or platform access credential by name alone, regardless of what the
/// value looks like. `ACCESSKEYID`/`SECRETACCESSKEY`/`SESSIONTOKEN` is the
/// AWS convention that every S3-compatible provider (Cloudflare R2, `MinIO`,
/// ...) also uses, which is why `R2_SECRET_ACCESS_KEY` matches the same
/// fragment as `AWS_SECRET_ACCESS_KEY`.
const CLOUD_PROVIDER_KEY_FRAGMENTS: &[&str] = &["ACCESSKEYID", "SECRETACCESSKEY", "SESSIONTOKEN"];

/// True if `value` has the shape of a generated secret rather than a
/// password a person typed by hand: long (20+ characters) and mixing
/// letters with digits. A human picking a "strong-looking" password by hand
/// essentially never lands here; a generated API key or service token
/// (`svc_4f8a1c62d90b47e3a5216fbc8de07394`) always does.
fn looks_high_entropy(value: &str) -> bool {
    if value.chars().count() < 20 {
        return false;
    }
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    has_digit && has_alpha
}

/// How much an attacker actually gains from one hardcoded credential --
/// `BAS-INFRA-006`'s severity, not just whether it fires.
///
/// Measured 2026-08-28 against 65 real repositories: 23 findings, every one
/// a genuine literal credential -- [`is_hardcoded_credential_value`]'s
/// placeholder rejection is sound and is not what this function is about --
/// but they split into two populations an attacker experiences very
/// differently. A leaked cloud-provider access key or a long generated
/// service token hands an attacker something usable directly and remotely.
/// A well-known weak default (`postgres`, `password`, `admin`) or a short,
/// obviously throwaway dev value (`pw`, `<project>_dev`) is still a real
/// finding -- CWE-798, and a real deployment could run with it unchanged --
/// but calling both `Critical` teaches a reader to stop trusting the
/// severity field. This is a severity split only: every hardcoded
/// credential [`is_hardcoded_credential_value`] accepts is still reported,
/// unconditionally, as a `BAS-INFRA-006` observation.
///
/// Two independent signals, either enough to call it [`Severity::Critical`]:
/// the *name* identifies a cloud-provider/platform credential
/// ([`CLOUD_PROVIDER_KEY_FRAGMENTS`]) regardless of the value's shape, or
/// the *value* itself [`looks_high_entropy`]. Neither firing downgrades to
/// [`Severity::High`] -- never lower: every credential here is still a real
/// one a deployment would actually run with, per
/// [`is_hardcoded_credential_value`]'s own contract, so `Medium` ("should be
/// fixed") would understate even the weak-default population.
///
/// Deliberately not a filename/path signal ("this is docker-compose.yml so
/// it must be dev"): a production Compose file exists, and a weak value's
/// severity does not depend on which file it sits in.
pub(crate) fn credential_severity(name: &str, value: &str) -> crate::finding::Severity {
    use crate::finding::Severity;

    let normalized_name: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if CLOUD_PROVIDER_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized_name.contains(fragment))
    {
        return Severity::Critical;
    }

    if looks_high_entropy(value.trim()) {
        Severity::Critical
    } else {
        Severity::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_shaped_names_are_recognised() {
        for name in [
            "MYSQL_PASSWORD",
            "MYSQL_ROOT_PASSWORD",
            "DB_PASSWD",
            "SERVICE_TOKEN",
            "API_SECRET",
            "OPENAI_API_KEY",
            "STRIPE_PRIVATE_KEY",
            "AWS_ACCESS_KEY",
            "DB_CREDENTIAL",
        ] {
            assert!(looks_like_credential_key(name), "{name} should match");
        }
    }

    #[test]
    fn ordinary_config_names_are_not_credential_shaped() {
        for name in [
            "MYSQL_DATABASE",
            "MYSQL_USER",
            "NODE_ENV",
            "PORT",
            "S3_BUCKET_KEY",
            "PRIMARY_KEY",
            "AUTH_ENABLED",
            "LOG_LEVEL",
        ] {
            assert!(!looks_like_credential_key(name), "{name} should not match");
        }
    }

    #[test]
    fn an_interpolated_value_is_not_hardcoded() {
        for value in ["${DB_PASSWORD}", "$DB_PASSWORD", "${DB_PASSWORD:-}"] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn an_empty_value_is_not_hardcoded() {
        assert!(!is_hardcoded_credential_value(""));
        assert!(!is_hardcoded_credential_value("   "));
    }

    #[test]
    fn a_boolean_or_numeric_flag_is_not_hardcoded() {
        for value in ["yes", "no", "true", "false", "on", "off", "3600", "0"] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_storage_backend_mode_word_is_not_hardcoded() {
        for value in ["local", "LOCAL", "memory", "disk", "file", "disabled"] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_database_or_cloud_provider_name_is_a_real_weak_credential() {
        // Regression for the ENUM_MODE_VALUES over-exclusion: these words are
        // also extremely common real default passwords (`POSTGRES_PASSWORD:
        // postgres` ships in the official Postgres image's own README as a
        // "for local dev" example), so they must NOT be excluded just
        // because they also name a database/cloud product. `local` -- the
        // original motivating case (a mode setting, not a password) -- must
        // still be excluded.
        for value in ["postgres", "mysql", "redis", "default", "basic"] {
            assert!(is_hardcoded_credential_value(value), "{value}");
        }
        assert!(!is_hardcoded_credential_value("local"));
    }

    #[test]
    fn a_value_merely_containing_an_enum_word_still_fires() {
        // The exclusion is exact-match, not substring -- a real credential
        // that happens to start with a mode word must not be swallowed.
        for value in ["localpass123", "redis-svc-4f8a1c62d90b47e3a5216fbc8de07394"] {
            assert!(is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_vendor_published_public_key_is_not_a_hardcoded_credential() {
        // PostHog project keys and Stripe publishable keys are documented as
        // safe to embed in client-side code. Every other signal here says
        // "secret" -- correct name, high entropy, string literal -- so the
        // prefix is the only thing that can tell them apart. The phc_ shape
        // was the single false positive BAS-ZT1-011 produced during
        // calibration; the key below is a stand-in built to that shape.
        assert!(!is_hardcoded_credential_value(
            "phc_Rq7dKm2xTnW9pLv4bYs6HcJ3fZg8Qe5AtUi1oNr0MdX"
        ));
        assert!(!is_hardcoded_credential_value("pk_live_51H8xKjKcqL2mNpQr"));
        assert!(!is_hardcoded_credential_value("pk_test_51H8xKjKcqL2mNpQr"));
    }

    #[test]
    fn a_secret_key_sharing_a_public_prefixs_vendor_still_fires() {
        // The exclusion is per-prefix, not per-vendor. Stripe's *secret* key
        // uses sk_, and PostHog's personal API key uses phx_ -- neither is
        // published and neither may be swallowed by the pk_/phc_ carve-out.
        assert!(is_hardcoded_credential_value("sk_51H8xKjKcqL2mNpQr"));
        assert!(is_hardcoded_credential_value("phx_7c4e0a91b6d35f28e0b1"));
    }

    #[test]
    fn a_documented_placeholder_is_not_hardcoded() {
        for value in [
            "changeme",
            "CHANGE_ME",
            "your_password_here",
            "<your-password>",
            "{{ .Values.password }}",
            "REPLACE_WITH_YOUR_TOKEN",
            "xxx",
        ] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_general_replace_or_your_shaped_placeholder_is_not_hardcoded() {
        // Regression for the false-positive report's own named examples: a
        // bare "REPLACE..." with no "_WITH_" in it, and a general
        // "your-...-here"-style placeholder for a credential other than a
        // password. Before this fix, PLACEHOLDER_MARKERS only had the
        // password-specific "your_password"/"your-password"/"yourpassword"
        // and the narrower "replace_with"/"replace-with", so none of these
        // shapes were excluded.
        for value in [
            "REPLACE_ME",
            "REPLACEME",
            "replace-me",
            "your-key-here",
            "your_api_key",
            "your-openai-key",
        ] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_screaming_snake_case_value_reads_as_a_variable_name_not_a_secret() {
        for value in ["OPENAI_API_KEY", "DB_PASSWORD", "SECRET_KEY_2025"] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_path_to_a_mounted_credentials_file_is_not_a_hardcoded_credential() {
        // GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp_creds.json -- a false
        // positive measured directly against a real repository: the value is
        // where a bind-mounted file lives, not a credential.
        for value in [
            "/tmp/gcp_creds.json",
            "./secrets/token.json",
            "../shared/creds.pem",
            "~/.config/gcloud/application_default_credentials.json",
        ] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_value_that_spells_out_a_length_requirement_is_a_placeholder() {
        // Calibration turned up two false positives of this shape, one of
        // them an open-source project's own publicly documented local-demo
        // secret. Both described a length *requirement* rather than holding
        // secret content, which is the shape these stand-ins reproduce.
        for value in [
            "super-secret-jwt-token-with-at-least-32-characters-long",
            "acme-app-dev-secret-key-minimum-32-chars",
        ] {
            assert!(!is_hardcoded_credential_value(value), "{value}");
        }
    }

    #[test]
    fn a_real_or_weak_literal_credential_is_hardcoded() {
        // The whole point: a weak default is still a real credential a
        // deployment will actually run with, not documentation.
        for value in [
            "password",
            "aa123456",
            "svc_4f8a1c62d90b47e3a5216fbc8de07394",
            "Sup3rWeakPass!",
        ] {
            assert!(is_hardcoded_credential_value(value), "{value}");
        }
    }

    // -------------------------------------------------------------------
    // `credential_severity` -- BAS-INFRA-006's severity split, exercised
    // against the value shapes calibration turned up in real code. The
    // literals below are stand-ins written to match those shapes, not
    // copies of anything observed; what matters is that each one is a
    // value `is_hardcoded_credential_value` accepts, so this is a severity
    // judgment, not a detection one.
    // -------------------------------------------------------------------

    #[test]
    fn a_well_known_weak_default_is_high_not_critical() {
        // The low-value population: real CWE-798 findings, but a well-known
        // weak default or an obviously short/throwaway dev value, not a
        // usable leaked secret.
        for (key, value) in [
            ("POSTGRES_PASSWORD", "postgres"),
            ("POSTGRES_PASSWORD", "password"),
            ("POSTGRES_PASSWORD", "pw"),
            ("POSTGRES_PASSWORD", "acmeapp_dev"),
            ("POSTGRES_PASSWORD", "acmecorp"),
            ("DB_PASSWORD", "acme123"),
            ("GF_SECURITY_ADMIN_PASSWORD", "admin"),
        ] {
            assert_eq!(
                credential_severity(key, value),
                crate::finding::Severity::High,
                "{key}={value}"
            );
        }
    }

    #[test]
    fn a_cloud_provider_access_key_is_critical_regardless_of_its_value() {
        // The name alone says what it unlocks -- AWS and every
        // S3-compatible provider (R2, MinIO, ...) share this naming
        // convention.
        for (key, value) in [
            ("AWS_SECRET_ACCESS_KEY", "short"),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("R2_SECRET_ACCESS_KEY", "short"),
        ] {
            assert_eq!(
                credential_severity(key, value),
                crate::finding::Severity::Critical,
                "{key}={value}"
            );
        }
    }

    #[test]
    fn a_high_entropy_generated_token_is_critical() {
        // A long, generated-looking value is critical even when the key
        // name gives no hint of what it unlocks.
        assert_eq!(
            credential_severity("SERVICE_TOKEN", "svc_4f8a1c62d90b47e3a5216fbc8de07394"),
            crate::finding::Severity::Critical
        );
    }

    #[test]
    fn a_short_value_on_an_ordinary_key_is_high_not_critical() {
        assert_eq!(
            credential_severity("API_TOKEN", "Sup3rWeakPass!"),
            crate::finding::Severity::High
        );
    }

    #[test]
    fn a_provider_key_literal_is_recognised_by_shape() {
        for value in [
            "sk-proj-9f2b7d41c6a8e35019bd",
            "sk-proj-7f3a9c1eAbCdEfGh1234",
        ] {
            assert!(is_provider_key_literal(value), "{value}");
        }
    }

    #[test]
    fn a_value_that_merely_starts_with_sk_dash_is_not_a_provider_key() {
        for value in ["sk-tools/bin", "sk-short", "not-a-key"] {
            assert!(!is_provider_key_literal(value), "{value}");
        }
    }

    #[test]
    fn a_provider_key_shaped_placeholder_is_not_reported() {
        // Regression: `is_provider_key_literal` used to be shape-only (the
        // `sk-` prefix, 16+ characters, alphanumeric/`_`/`-`), with no
        // [`PLACEHOLDER_MARKERS`] check at all -- unlike its sibling
        // `is_hardcoded_credential_value`. Both of these satisfy the shape
        // check and, before this fix, were reported as leaked keys even in
        // a genuine, non-example `.env` file or Dockerfile.
        for value in [
            "sk-your-key-here-1234567890",
            "sk-REPLACE_WITH_YOUR_ACTUAL_KEY_1234567890",
            "sk-REPLACE_ME_1234567890123456",
            "sk-openai-your_api_key-000000",
        ] {
            assert!(!is_provider_key_literal(value), "{value}");
        }
    }

    #[test]
    fn a_genuine_looking_provider_key_still_fires_after_the_placeholder_fix() {
        // The fix above must not become so broad that it starts rejecting a
        // real, correctly-shaped key that merely has no placeholder text.
        assert!(is_provider_key_literal("sk-proj-Ab3xR9kLm2Qw7ZvN4tYh8sJ"));
    }
}
