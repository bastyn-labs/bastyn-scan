//! Core engine for [Bastyn](https://bastyn.ai).
//!
//! Everything that is not tied to a terminal: traversal, rules, MCP config
//! inspection, container configuration inspection, CVE lookup, and the report
//! model. The `bastyn` binary is a thin presentation layer over this API.
//!
//! The design rule that shapes all of it: say less, be right. A missing control
//! is an [`finding::Kind::Observation`], never a defect, because the repository
//! cannot show whether its absence is wrong.

pub mod category;
pub mod compliance;
pub mod cve;
pub mod finding;
pub mod infra;
pub mod instructions;
pub mod mcp;
pub mod observe;
pub mod render;
pub mod report;
pub mod reporting;
pub mod rules;
pub mod scan;
pub mod skill;

mod credential;
mod dotenv;
mod error;
pub(crate) mod flow;
mod generated;
mod test_path;
mod walk;

pub use category::{Category, Layer, Ring};
pub use compliance::{Control, Crosswalk, Framework, Group, crosswalk};
pub use error::{Error, Result};
pub use finding::{Confidence, Finding, Kind, Location, Severity};
pub use observe::{Observer, Phase, Silent};
pub use report::{Coverage, CoveredSkip, CveStatus, Report, Summary};
pub use scan::{ScanOptions, scan, scan_observed};
pub use walk::{Traversal, WalkOptions, collect_files};

/// The version of this crate, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
