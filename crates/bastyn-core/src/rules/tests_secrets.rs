//! Tests for `rules/secrets.yml`: hardcoded credentials, provider keys, and
//! secret-shaped literals in source. Run against the real, embedded rule
//! file (not an ad-hoc rule string), so a typo in the shipped YAML fails the
//! same test a rewrite of the pattern would -- see `rules::tests`' JS/TS
//! twin tests for the precedent this file follows.
//!
//! Every rule gets a positive test (fires on the vulnerable shape) and a
//! negative test (does not fire on an environment-read, an empty value, or
//! an interpolation placeholder) -- the negative test is the one that
//! matters, per this crate's own precision history.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::*;

fn ruleset() -> RuleSet {
    RuleSet::embedded().unwrap()
}

fn ids(findings: &[crate::finding::Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

// ---------------------------------------------------------------------
// BAS-LLM02-001 / BAS-LLM02-002 -- LLM provider API key passed as a
// literal to the client constructor.
// ---------------------------------------------------------------------

#[test]
fn bas_llm02_001_flags_a_provider_key_passed_to_a_client_constructor() {
    let ruleset = ruleset();
    let source = "client = OpenAI(api_key=\"sk-proj-AbCd1234EfGh5678\")\n";

    let findings = scan_source(&ruleset, Path::new("agent.py"), source);

    assert!(ids(&findings).contains(&"BAS-LLM02-001"), "{findings:?}");
}

#[test]
fn bas_llm02_001_ignores_a_key_read_from_the_environment() {
    let ruleset = ruleset();
    let source = "client = OpenAI(api_key=os.environ[\"OPENAI_API_KEY\"])\n";

    let findings = scan_source(&ruleset, Path::new("agent.py"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-001"), "{findings:?}");
}

#[test]
fn bas_llm02_001_ignores_an_obviously_fake_placeholder_key() {
    let ruleset = ruleset();
    let source = "client = OpenAI(api_key=\"sk-test-xxxxxxxxxxxxxxxx\")\n";

    let findings = scan_source(&ruleset, Path::new("agent.py"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-001"), "{findings:?}");
}

#[test]
fn bas_llm02_002_flags_a_provider_key_passed_to_a_js_client_constructor() {
    let ruleset = ruleset();
    let source = "const client = new OpenAI({ apiKey: \"sk-proj-AbCd1234EfGh5678\" });\n";

    let findings = scan_source(&ruleset, Path::new("agent.ts"), source);

    assert!(ids(&findings).contains(&"BAS-LLM02-002"), "{findings:?}");
}

#[test]
fn bas_llm02_002_ignores_a_js_key_read_from_the_environment() {
    let ruleset = ruleset();
    let source = "const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n";

    let findings = scan_source(&ruleset, Path::new("agent.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-002"), "{findings:?}");
}

#[test]
fn bas_llm02_002_ignores_an_obviously_fake_placeholder_key() {
    let ruleset = ruleset();
    let source = "const client = new OpenAI({ apiKey: \"sk-test-xxxxxxxxxxxxxxxx\" });\n";

    let findings = scan_source(&ruleset, Path::new("agent.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-002"), "{findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM02-004 / BAS-LLM02-005 -- hardcoded bearer token in tool/skill
// implementation code.
// ---------------------------------------------------------------------

#[test]
fn bas_llm02_004_flags_a_hardcoded_bearer_token() {
    let ruleset = ruleset();
    let source =
        "headers = {\"Authorization\": \"Bearer sk-live-9f2b7d41c6a8e35019bd41a9f7c2e6b8\"}\n";

    let findings = scan_source(&ruleset, Path::new("skill.py"), source);

    assert!(ids(&findings).contains(&"BAS-LLM02-004"), "{findings:?}");
}

#[test]
fn bas_llm02_004_ignores_an_interpolated_bearer_token() {
    let ruleset = ruleset();
    let source = "headers = {\"Authorization\": f\"Bearer {token}\"}\n";

    let findings = scan_source(&ruleset, Path::new("skill.py"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-004"), "{findings:?}");
}

#[test]
fn bas_llm02_004_ignores_a_placeholder_bearer_token() {
    let ruleset = ruleset();
    let source = "headers = {\"Authorization\": \"Bearer test-placeholder-token-value\"}\n";

    let findings = scan_source(&ruleset, Path::new("skill.py"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-004"), "{findings:?}");
}

#[test]
fn bas_llm02_004_ignores_a_mustache_template_placeholder_bearer_token() {
    // Measured 2026-08-31: a *plain* string literal (not an f-string) whose
    // content is itself unexpanded template syntax, substituted by the
    // application's own templating layer at execution time -- no secret is
    // embedded. Same judgment `credential::is_hardcoded_credential_value`
    // already applies to a leading `{{`.
    let ruleset = ruleset();
    let source = "headers = {\"Authorization\": \"Bearer {{env.DAST_AUTH_TOKEN}}\"}\n";

    let findings = scan_source(&ruleset, Path::new("skill.py"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-004"), "{findings:?}");
}

#[test]
fn bas_llm02_004_ignores_a_shell_style_variable_placeholder_bearer_token() {
    let ruleset = ruleset();
    let source = "headers = {\"Authorization\": \"Bearer ${DAST_AUTH_TOKEN}\"}\n";

    let findings = scan_source(&ruleset, Path::new("skill.py"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-004"), "{findings:?}");
}

#[test]
fn bas_llm02_005_flags_a_hardcoded_bearer_token_js() {
    let ruleset = ruleset();
    let source =
        "const headers = { Authorization: \"Bearer sk-live-9f2b7d41c6a8e35019bd41a9f7c2e6b8\" };\n";

    let findings = scan_source(&ruleset, Path::new("skill.ts"), source);

    assert!(ids(&findings).contains(&"BAS-LLM02-005"), "{findings:?}");
}

#[test]
fn bas_llm02_005_ignores_an_interpolated_bearer_token_js() {
    let ruleset = ruleset();
    let source = "const headers = { Authorization: `Bearer ${token}` };\n";

    let findings = scan_source(&ruleset, Path::new("skill.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-005"), "{findings:?}");
}

#[test]
fn bas_llm02_005_ignores_a_mustache_template_placeholder_bearer_token_js() {
    let ruleset = ruleset();
    let source = "const headers = { Authorization: \"Bearer {{env.DAST_AUTH_TOKEN}}\" };\n";

    let findings = scan_source(&ruleset, Path::new("skill.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-LLM02-005"), "{findings:?}");
}

// ---------------------------------------------------------------------
// BAS-ZT1-010 / BAS-ZT1-011 -- generic hardcoded credential-shaped literal.
// ---------------------------------------------------------------------

#[test]
fn bas_zt1_010_flags_a_generic_credential_shaped_assignment() {
    let ruleset = ruleset();
    let source = "stripe_secret_key = \"sk_9d2a4f7c1b6e3a58d0\"\n";

    let findings = scan_source(&ruleset, Path::new("config.py"), source);

    assert!(ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_flags_a_generic_credential_shaped_dict_entry() {
    let ruleset = ruleset();
    let source = "config = {\"api_key\": \"AbCdEf123456xyz789\"}\n";

    let findings = scan_source(&ruleset, Path::new("config.py"), source);

    assert!(ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_a_key_read_from_the_environment() {
    let ruleset = ruleset();
    let source = "api_key = os.environ[\"OPENAI_API_KEY\"]\n";

    let findings = scan_source(&ruleset, Path::new("config.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_an_empty_password() {
    let ruleset = ruleset();
    let source = "password = \"\"\n";

    let findings = scan_source(&ruleset, Path::new("config.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_an_interpolation_placeholder() {
    let ruleset = ruleset();
    let source = "token = \"${TOKEN}\"\n";

    let findings = scan_source(&ruleset, Path::new("config.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_a_prose_string_that_merely_names_a_credential() {
    let ruleset = ruleset();
    let source = "password_prompt = \"Please enter your password\"\n";

    let findings = scan_source(&ruleset, Path::new("config.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_a_self_referential_storage_key_name() {
    // Measured 2026-08-28: the largest false-positive cluster on real
    // code. The value is the *name* of a token/cookie/header, not a
    // secret -- a human-typed identifier with no digit and no uppercase
    // letter, not a generated credential.
    for source in [
        "token_name = \"owly-token\"\n",
        "access_token_key = \"mike_token\"\n",
        "api_keys_storage_key = \"openscribe_api_keys\"\n",
    ] {
        let ruleset = ruleset();
        let findings = scan_source(&ruleset, Path::new("auth.py"), source);
        assert!(
            !ids(&findings).contains(&"BAS-ZT1-010"),
            "{source}: {findings:?}"
        );
    }
}

#[test]
fn bas_zt1_010_ignores_a_plain_url_but_flags_one_with_embedded_credentials() {
    let ruleset = ruleset();

    for source in [
        "info[\"token_uri\"] = \"https://oauth2.provider.invalid/token\"\n",
        "TOKEN_URI = \"https://oauth2.provider.invalid/token\"\n",
        "config = {\"secret_manager_url\": \"https://secrets.provider.invalid/v1/resolve\"}\n",
    ] {
        let findings = scan_source(&ruleset, Path::new("auth.py"), source);
        assert!(
            !ids(&findings).contains(&"BAS-ZT1-010"),
            "{source}: {findings:?}"
        );
    }

    let source = "database_password_url = \"https://Zx9fQ2mLp4Rt8Vw3@db.provider.invalid/main\"\n";
    let findings = scan_source(&ruleset, Path::new("auth.py"), source);
    assert!(ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");

    let source =
        "api_token_url = \"https://api.provider.invalid/v1/hook?api_key=Zx9fQ2mLp4Rt8Vw3Kd7\"\n";
    let findings = scan_source(&ruleset, Path::new("auth.py"), source);
    assert!(ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_an_nlp_format_token_not_an_auth_token() {
    // "token" is exceptionally overloaded in an AI codebase: a
    // tokenization/format-string sense has nothing to do with
    // authentication, and shares no shape with a real secret.
    let ruleset = ruleset();
    let source = "max_new_tokens = \"max_new_tokens\"\n";

    let findings = scan_source(&ruleset, Path::new("model.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_a_smoke_test_fixture_secret() {
    let ruleset = ruleset();
    let source = "secret = \"acme-smoke-secret-v1\"\n";

    let findings = scan_source(&ruleset, Path::new("orchestrator.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_a_value_scrubbed_before_persisting() {
    // Measured 2026-08-31: private_repo["accessToken"] = "[REDACTED]" is a
    // redaction routine scrubbing a secret before writing it out, the
    // opposite of a leaked credential. $KEY binds the whole subscript
    // expression (its text contains "Token"), and "[REDACTED]" clears the
    // 8+ character length gate, so only the placeholder-word exclusion can
    // stop this from firing.
    let ruleset = ruleset();
    let source = "private_repo[\"accessToken\"] = \"[REDACTED]\"\n";

    let findings = scan_source(&ruleset, Path::new("intake_engine.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_010_ignores_a_strftime_format_string() {
    // Measured 2026-08-28: DATE_FORMAT_TOKENS = "%Y-%m-%d" survived the
    // no-digit/no-uppercase gate on the strength of a single uppercase
    // "Y" -- a strftime directive, not a credential.
    let ruleset = ruleset();
    let source = "date_format_tokens = \"%Y-%m-%d\"\n";

    let findings = scan_source(&ruleset, Path::new("sec_filings.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-010"), "{findings:?}");
}

#[test]
fn bas_zt1_011_flags_a_generic_credential_shaped_assignment_js() {
    let ruleset = ruleset();
    let source = "const stripeSecretKey = \"sk_9d2a4f7c1b6e3a58d0\";\n";

    let findings = scan_source(&ruleset, Path::new("config.ts"), source);

    assert!(ids(&findings).contains(&"BAS-ZT1-011"), "{findings:?}");
}

#[test]
fn bas_zt1_011_flags_a_generic_credential_shaped_object_property_js() {
    let ruleset = ruleset();
    let source = "const config = { apiKey: \"AbCdEf123456xyz789\" };\n";

    let findings = scan_source(&ruleset, Path::new("config.ts"), source);

    assert!(ids(&findings).contains(&"BAS-ZT1-011"), "{findings:?}");
}

#[test]
fn bas_zt1_011_ignores_a_key_read_from_the_environment_js() {
    let ruleset = ruleset();
    let source = "const apiKey = process.env.OPENAI_API_KEY;\n";

    let findings = scan_source(&ruleset, Path::new("config.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-011"), "{findings:?}");
}

#[test]
fn bas_zt1_011_ignores_an_interpolation_placeholder_js() {
    let ruleset = ruleset();
    let source = "const token = \"${TOKEN}\";\n";

    let findings = scan_source(&ruleset, Path::new("config.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-011"), "{findings:?}");
}

#[test]
fn bas_zt1_011_ignores_a_vendored_librarys_own_unrelated_key_constant() {
    // Bootstrap.js's own `DATA_API_KEY` -- a CSS selector, not a
    // credential. Measured 2026-08-28: 14 identical false positives from
    // one vendored file, duplicated across bundle formats.
    let ruleset = ruleset();
    let source = "const DATA_API_KEY = '.data-api';\n";

    let findings = scan_source(&ruleset, Path::new("vendor/bootstrap.js"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-011"), "{findings:?}");
}

#[test]
fn bas_zt1_011_ignores_a_single_title_case_word() {
    // header_mapping = {"token": "Authorization"} in the wild: a header
    // *name*, not a secret value.
    let ruleset = ruleset();
    let source = "const headerMapping = { token: \"Authorization\" };\n";

    let findings = scan_source(&ruleset, Path::new("config.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-011"), "{findings:?}");
}

// ---------------------------------------------------------------------
// BAS-ZT1-012 / BAS-ZT1-013 -- weak/default admin password seeded in a
// setup or init script.
// ---------------------------------------------------------------------

#[test]
fn bas_zt1_012_flags_a_weak_default_admin_password() {
    let ruleset = ruleset();
    let source =
        "create_user(email=\"admin@example.com\", password=\"changeme123\", role=\"admin\")\n";

    let findings = scan_source(&ruleset, Path::new("scripts/seed.py"), source);

    assert!(ids(&findings).contains(&"BAS-ZT1-012"), "{findings:?}");
}

#[test]
fn bas_zt1_012_ignores_a_password_read_from_the_environment() {
    let ruleset = ruleset();
    let source = "create_user(email=\"admin@example.com\", password=os.environ[\"SEED_PASSWORD\"], role=\"admin\")\n";

    let findings = scan_source(&ruleset, Path::new("scripts/seed.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-012"), "{findings:?}");
}

#[test]
fn bas_zt1_012_ignores_a_strong_random_password() {
    let ruleset = ruleset();
    let source = "create_user(email=\"admin@example.com\", password=\"Xk9$mQ2vLp8Rz!TqW\", role=\"admin\")\n";

    let findings = scan_source(&ruleset, Path::new("scripts/seed.py"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-012"), "{findings:?}");
}

#[test]
fn bas_zt1_013_flags_a_weak_default_admin_password_js() {
    let ruleset = ruleset();
    let source = "createUser({ email: \"admin@example.com\", password: \"changeme123\", role: \"admin\" });\n";

    let findings = scan_source(&ruleset, Path::new("scripts/seed.ts"), source);

    assert!(ids(&findings).contains(&"BAS-ZT1-013"), "{findings:?}");
}

#[test]
fn bas_zt1_013_ignores_a_strong_random_password_js() {
    let ruleset = ruleset();
    let source = "createUser({ email: \"admin@example.com\", password: \"Xk9$mQ2vLp8Rz!TqW\", role: \"admin\" });\n";

    let findings = scan_source(&ruleset, Path::new("scripts/seed.ts"), source);

    assert!(!ids(&findings).contains(&"BAS-ZT1-013"), "{findings:?}");
}

// ---------------------------------------------------------------------
// Parity check: BAS-ZT1-010/011's VALUE exclusion list is a hand-checked
// translation of `crate::credential::is_hardcoded_credential_value`'s
// placeholder exclusions -- see that module's doc comment. Assert both
// agree on the same value vectors so the two representations cannot
// silently drift.
// ---------------------------------------------------------------------

#[test]
fn a_vendor_published_public_key_does_not_fire_either_rule() {
    // A PostHog project key, which the vendor documents as write-only and
    // safe in client-side code, was the single false positive BAS-ZT1-011
    // produced during calibration. The key below is a stand-in built to
    // that shape: it has every surface property of a secret, so the vendor
    // prefix is the only thing that can exclude it -- and the YAML regex
    // must agree with crate::credential, which is what this asserts on
    // both sides.
    let ruleset = ruleset();
    let public = "phc_Rq7dKm2xTnW9pLv4bYs6HcJ3fZg8Qe5AtUi1oNr0MdX";
    assert!(!crate::credential::is_hardcoded_credential_value(public));

    let python = format!("POSTHOG_API_KEY = \"{public}\"\n");
    assert!(
        !ids(&scan_source(&ruleset, Path::new("app.py"), &python)).contains(&"BAS-ZT1-010"),
        "python rule should not report a vendor-published public key"
    );

    let js = format!("const POSTHOG_API_KEY = '{public}';\n");
    assert!(
        !ids(&scan_source(&ruleset, Path::new("app.js"), &js)).contains(&"BAS-ZT1-011"),
        "js rule should not report a vendor-published public key"
    );
}

#[test]
fn a_real_secret_key_still_fires_despite_the_public_key_carve_out() {
    // The carve-out is per-prefix, not per-vendor: Stripe's secret key uses
    // sk_ and must still be reported. A carve-out that swallowed it would
    // be worse than no carve-out at all.
    //
    // The name is STRIPE_SECRET_KEY, not STRIPE_KEY, because the rule's name
    // gate deliberately does not accept a bare `key`: that is the fragment
    // that matched a vendored `DATA_API_KEY = '.data-api'` CSS selector 14
    // times when this rule was first measured. `STRIPE_KEY = "sk_live_..."`
    // is therefore a known false negative, accepted because widening the
    // name gate to bare `key` costs far more precision than it buys recall.
    let ruleset = ruleset();
    let source = "STRIPE_SECRET_KEY = \"sk_7b3e1a95c204f86d\"\n";
    assert!(
        ids(&scan_source(&ruleset, Path::new("app.py"), source)).contains(&"BAS-ZT1-010"),
        "a real secret key must still be reported"
    );
}

#[test]
fn generic_credential_rule_agrees_with_credential_module_on_placeholders() {
    let ruleset = ruleset();
    let placeholders = [
        "changeme",
        "CHANGE_ME",
        "your_password_here",
        "REPLACE_WITH_YOUR_TOKEN",
        "xxx",
        "OPENAI_API_KEY",
        "[REDACTED]",
    ];
    for value in placeholders {
        assert!(
            !crate::credential::is_hardcoded_credential_value(value),
            "credential module: {value} should read as a placeholder"
        );
        let source = format!("api_key = \"{value}\"\n");
        let findings = scan_source(&ruleset, Path::new("config.py"), &source);
        assert!(
            !ids(&findings).contains(&"BAS-ZT1-010"),
            "rule should agree {value} is a placeholder: {findings:?}"
        );
    }

    let real = ["svc_4f8a1c62d90b47e3a5216fbc8de07394", "Sup3rWeakPass!"];
    for value in real {
        assert!(
            crate::credential::is_hardcoded_credential_value(value),
            "credential module: {value} should read as a real credential"
        );
        let source = format!("api_key = \"{value}\"\n");
        let findings = scan_source(&ruleset, Path::new("config.py"), &source);
        assert!(
            ids(&findings).contains(&"BAS-ZT1-010"),
            "rule should agree {value} is a real credential: {findings:?}"
        );
    }
}
