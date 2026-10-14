//! Command-line entry point for Bastyn.
//!
//! Thin by design: parse arguments, call into [`bastyn_core`], render the
//! result, and map the outcome onto the exit-code contract. All analysis lives
//! in the core crate.

mod cli;
mod commands;
mod exit;
mod progress;

use std::io::Write as _;
use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match &cli.command {
        Command::Scan(args) => {
            commands::scan::run(args, &cli.global).map(commands::scan::Outcome::exit_code)
        }
        Command::ProjectId(args) => commands::project_id::run(args).map(|()| exit::CLEAN),
        Command::InspectServer(args) => commands::inspect_server::run(args).map(|()| exit::CLEAN),
    };

    match result {
        Ok(code) => exit::code(code),
        Err(error) => {
            report(&error);
            exit::code(exit::EXECUTION_ERROR)
        }
    }
}

/// Print an error and its causes to stderr, innermost cause last.
fn report(error: &anyhow::Error) {
    let mut stderr = std::io::stderr().lock();

    // Writing the error report is the last thing this process does; if stderr
    // is gone there is nowhere left to complain about it.
    let _ = writeln!(stderr, "error: {error}");
    for cause in error.chain().skip(1) {
        let _ = writeln!(stderr, "  caused by: {cause}");
    }
}
