//! Unit tests for `BAS-LLM04-002` (a package-manager install started as a
//! child process), run against the embedded rule set.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::*;
use crate::finding::Kind;

const RULE: &str = "BAS-LLM04-002";

fn hits(path: &str, source: &str) -> usize {
    let ruleset = RuleSet::embedded().unwrap();
    scan_source(&ruleset, Path::new(path), source)
        .iter()
        .filter(|f| f.rule_id == RULE)
        .count()
}

#[test]
fn it_is_an_observation() {
    let ruleset = RuleSet::embedded().unwrap();
    let findings = scan_source(
        &ruleset,
        Path::new("setup.js"),
        "spawnSync(\"npm\", [\"install\", \"left-pad\"], { stdio: \"inherit\" });\n",
    );
    let finding = findings.iter().find(|f| f.rule_id == RULE).unwrap();
    assert_eq!(finding.kind, Kind::Observation);
}

#[test]
fn argument_array_installs_are_flagged() {
    let sources = [
        "spawnSync(\"npm\", [\"install\", \"left-pad\"], { stdio: \"inherit\" });",
        "spawnSync(\"npm\", [\"install\"]);",
        "spawn('pnpm', ['add', 'left-pad']);",
        "spawn('yarn', ['add', '--exact', 'left-pad'], { cwd });",
        "execFile(\"bun\", [\"add\", \"left-pad\"], cb);",
        "execFileSync(\"npm\", [\"--silent\", \"i\", \"left-pad\"]);",
        "cp.spawnSync(\"npm\", [\"install\"]);",
        "child_process.execFileSync('npm', ['install']);",
    ];
    for source in sources {
        assert_eq!(hits("setup.js", source), 1, "{source}");
    }
}

#[test]
fn command_string_installs_are_flagged() {
    let sources = [
        "execSync(\"npm install left-pad\");",
        "exec('yarn add left-pad', cb);",
        "execSync(`pnpm install ${name}`);",
        "child_process.execSync(\"bun add left-pad\", { stdio: \"inherit\" });",
        "cp.exec(\"npm i left-pad\");",
    ];
    for source in sources {
        assert_eq!(hits("setup.js", source), 1, "{source}");
    }
}

#[test]
fn typescript_files_are_covered() {
    let source = "spawnSync(\"npm\", [\"install\", pkg as string]);\n";
    assert_eq!(hits("setup.ts", source), 1);
    assert_eq!(hits("setup.tsx", source), 1);
}

#[test]
fn near_misses_are_not_flagged() {
    let sources = [
        "spawnSync(\"npm\", [\"run\", \"build\"]);",
        "spawnSync(\"npm\", [\"ci\"]);",
        "spawnSync(\"git\", [\"add\", \"-A\"]);",
        "spawn(\"node\", [\"install.js\"]);",
        "execSync(\"npm test\");",
        "execSync(\"npm run install-docs\");",
        "execSync(\"git add .\");",
        "exec(\"npm\");",
        "pattern.exec(\"npm install left-pad\");",
        "console.log(\"npm install\");",
        "const hint = \"npm install foo\";",
        "// run: spawnSync(\"npm\", [\"install\"])\nconst a = 1;",
        "const npm = require(\"npm\");",
        "const label = [\"install\", \"add\"];",
    ];
    for source in sources {
        assert_eq!(hits("setup.js", source), 0, "{source}");
    }
}
