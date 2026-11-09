//! Dependency CVE checking: parse a manifest, look up every pinned
//! dependency against [`OSV.dev`](https://osv.dev), and report vulnerable
//! ones as [`Finding`](crate::Finding)s.
//!
//! Two design decisions shape this module more than anything else:
//!
//! 1. **A version we cannot pin exactly is never guessed at.** A range like
//!    `>=2.0` or `^1.2.3` cannot be checked against a specific advisory
//!    without picking a version out of the air; [`parse_manifest`] reports
//!    it as an [`UnresolvedDependency`] instead of matching it against
//!    OSV.dev's data for whatever version happens to be latest.
//! 2. **A network problem is not a clean bill of health.** If the lookup
//!    cannot reach OSV.dev — DNS failure, timeout, non-2xx response — that
//!    is reported through [`CveStatus::Unreachable`](crate::report::CveStatus::Unreachable) with zero findings and
//!    no `Err`. Silently returning zero findings because the network call
//!    failed would render as "no vulnerabilities found", which is the worst
//!    possible failure mode for a security tool. See [`check`] for the full
//!    contract, including the `--offline` and no-manifest cases.
//!
//! # `BAS-LLM04-001`, alongside but not through OSV
//!
//! A wildcard-version pin on a known agent/MCP-ecosystem package is a
//! second, unrelated check living in this module because it reads the same
//! [`UnresolvedDependency`] values [`parse_manifest`] already produces. It
//! needs no network call and runs unconditionally, including under
//! `--offline` — it is a structural read of the version string a manifest
//! declares, not a CVE lookup.

mod framework;
mod lockfile;
mod manifest;
mod osv;
mod reconcile;

pub use lockfile::{LockError, LockKind, Lockfile, UnresolvedSource, is_lockfile, parse_lockfile};
pub use manifest::{
    Dependency, Ecosystem, Error, Result, UnresolvedDependency, is_manifest, manifest_ecosystem,
    parse_manifest,
};
pub use osv::check;
pub use reconcile::{ManifestInput, Reconciled, reconcile};

pub(crate) use framework::check as check_wildcard_framework_dependencies;
