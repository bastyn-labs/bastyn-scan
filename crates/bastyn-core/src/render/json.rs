//! Our own JSON rendering.
//!
//! [`Report`] already derives `Serialize`, so this is pretty-printing it
//! directly — no bespoke wrapper shape, because the field names it produces
//! are a public contract other tools parse.

use crate::report::Report;

use super::error::Result;

/// Render `report` as pretty-printed JSON.
pub(crate) fn render(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::render;
    use crate::compliance::Framework;
    use crate::render::test_support::{empty_report, report_with};
    use crate::report::CveStatus;

    /// The exact bytes `report_with(CveStatus::NoManifest)` has always
    /// produced.
    ///
    /// Pinned in full rather than key-by-key because the thing being protected
    /// is the whole serialised shape: field names, field *order*, the tagged
    /// `cve` representation, the `UPPERCASE` category strings, and the fields
    /// that vanish when empty. Presentation work on the terminal renderer has
    /// no business changing any of it, and a diff here is the fastest way to
    /// notice that it did.
    const CONTRACT: &str = r#"{
  "bastyn_version": "0.1.0",
  "root": "/repo",
  "summary": {
    "files_scanned": 17,
    "files_skipped": 0,
    "defects": 1,
    "observations": 1
  },
  "cve": {
    "status": "no_manifest"
  },
  "findings": [
    {
      "rule_id": "BAS-LLM10-001",
      "title": "Model output executed as code",
      "kind": "defect",
      "severity": "critical",
      "confidence": "high",
      "categories": [
        "LLM10",
        "ZT4"
      ],
      "location": {
        "file": "src/agents.py",
        "line": 81,
        "column": 12
      },
      "snippet": "exec(response.text)",
      "description": "The model's raw output is passed straight to exec.",
      "remediation": "Parse the output as JSON and validate against a schema."
    },
    {
      "rule_id": "BAS-LLM06-001",
      "title": "No token ceiling on LLM call",
      "kind": "observation",
      "severity": "high",
      "confidence": "medium",
      "categories": [
        "LLM06"
      ],
      "location": {
        "file": "main.py",
        "line": 172,
        "column": 1
      },
      "snippet": "client.chat.completions.create(...)",
      "description": "No max_tokens ceiling is set on this call.",
      "remediation": "Set a token ceiling appropriate to the caller."
    }
  ],
  "coverage": {
    "mcp_manifests": [],
    "skill_files": [],
    "instruction_files": [],
    "skipped": []
  }
}"#;

    #[test]
    fn serialised_shape_is_byte_for_byte_the_published_contract() {
        assert_eq!(
            render(&report_with(CveStatus::NoManifest)).unwrap(),
            CONTRACT
        );
    }

    #[test]
    fn parses_back_with_expected_keys() {
        let report = report_with(CveStatus::NoManifest);
        let text = render(&report).unwrap();

        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(value.get("bastyn_version").is_some());
        assert!(value.get("root").is_some());
        assert!(value.get("summary").is_some());
        assert!(value.get("cve").is_some());

        let findings = value
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[0]
                .get("rule_id")
                .and_then(serde_json::Value::as_str),
            Some("BAS-LLM10-001")
        );

        let summary = value.get("summary").unwrap();
        assert_eq!(
            summary
                .get("files_scanned")
                .and_then(serde_json::Value::as_u64),
            Some(17)
        );
    }

    /// The bytes `skipped` has always carried, unchanged by the reason
    /// becoming data.
    ///
    /// `Report::skipped` is a published contract: other tools read this array
    /// and diff it between runs. The terminal now groups those entries by why
    /// they are there, which needed the reason to be structured — and a
    /// structure that leaked into the array would have broken every consumer
    /// to improve a layout. Pinned in full, and verified against a build of
    /// 39a517b over a tree exercising all six reasons.
    ///
    /// The entries are also the case a reader should be able to argue with:
    /// two of them carry nothing but a path, because "could not be read" and
    /// "could not be parsed" have always been written down the same way.
    const SKIPPED: &str = r#"[
    "vendor/ — excluded by pattern \"vendor/\"",
    "web/app.min.js — excluded by pattern \"*.min.js\"",
    ".bastynignore — honoured: paths matching its patterns were not scanned",
    "web/bundle.js — generated: minified, 65536 bytes per line on average over the first 65536 bytes",
    "assets/logo.py",
    "broken.py",
    "requirements.txt:18 — opentelemetry-api * is not pinned, so CVEs were not checked"
  ]"#;

    #[test]
    fn skipped_still_serialises_as_the_array_of_lines_it_always_was() {
        let mut report = report_with(CveStatus::NoManifest);
        report.skipped = crate::render::test_support::every_skip_reason();

        let text = render(&report).unwrap();
        let start = text
            .find("\"skipped\": ")
            .unwrap_or_else(|| unreachable!("no skipped key in:\n{text}"))
            + "\"skipped\": ".len();
        let end = text[start..]
            .find(']')
            .unwrap_or_else(|| unreachable!("unterminated array in:\n{text}"))
            + start
            + 1;
        assert_eq!(&text[start..end], SKIPPED);

        // And nothing else about the document moved.
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let contract: serde_json::Value = serde_json::from_str(CONTRACT).unwrap();
        for key in ["bastyn_version", "root", "summary", "cve", "findings"] {
            assert_eq!(value[key], contract[key], "{key} changed shape");
        }
    }

    /// An empty `skipped` still emits no key, so an empty array can never read
    /// as "nothing was left out" for a scan that never looked.
    #[test]
    fn an_empty_skipped_list_emits_no_key() {
        let value: serde_json::Value =
            serde_json::from_str(&render(&empty_report()).unwrap()).unwrap();
        assert!(value.get("skipped").is_none(), "{value}");
        // `coverage.skipped` is a different key and is always present.
        assert_eq!(value["coverage"]["skipped"], serde_json::json!([]));
    }

    /// A report carrying no crosswalk emits no key for one.
    ///
    /// The point of skipping an empty vector rather than serialising `[]`: an
    /// empty array is a claim that the frameworks were consulted and found
    /// nothing, which is not what an absent crosswalk means. The CLI fills the
    /// field on every scan, so this is the renderer's own contract — a
    /// [`crate::report::Report`] straight out of the engine.
    #[test]
    fn a_report_without_a_crosswalk_gains_no_key() {
        let text = render(&report_with(CveStatus::NoManifest)).unwrap();
        assert!(!text.contains("crosswalk"));
        assert_eq!(text, CONTRACT);
    }

    /// The grouping reaches the JSON, because the JSON is what a CI step and a
    /// compliance report generator actually consume.
    #[test]
    fn a_crosswalk_is_additive_and_carries_its_own_caveat() {
        let mut report = report_with(CveStatus::NoManifest);
        report.crosswalks = vec![crate::compliance::crosswalk(&report, Framework::EuAiAct)];

        let text = render(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        // Additive: every key the contract pinned is still there, unrenamed.
        for key in ["bastyn_version", "root", "summary", "cve", "findings"] {
            assert!(value.get(key).is_some(), "{key} was dropped");
        }
        let contract: serde_json::Value = serde_json::from_str(CONTRACT).unwrap();
        for key in ["bastyn_version", "root", "summary", "cve", "findings"] {
            assert_eq!(value[key], contract[key], "{key} changed shape");
        }

        let walks = value["crosswalks"].as_array().unwrap();
        assert_eq!(walks.len(), 1);
        let walk = &walks[0];
        assert_eq!(walk["framework"].as_str(), Some("eu-ai-act"));
        assert_eq!(walk["name"].as_str(), Some("EU AI Act"));
        assert_eq!(
            walk["disclaimer"].as_str(),
            Some(crate::compliance::DISCLAIMER)
        );
        // The complete reference, not the identifier the terminal table shows:
        // a consumer generating a compliance document needs the whole thing,
        // and has no width to run out of.
        assert_eq!(
            walk["citation"].as_str(),
            Some(Framework::EuAiAct.citation()),
            "the machine format keeps the full citation"
        );
        assert!(
            walk["citation"]
                .as_str()
                .unwrap()
                .contains("as amended by Regulation (EU) 2026/1744"),
            "including the amendment the terminal footnote carries instead"
        );
        assert!(
            walk["standing"]
                .as_str()
                .unwrap()
                .contains("2 December 2027")
        );

        // The defect maps to [LLM10, ZT4], both Art. 15; the LLM06
        // observation maps to nothing in this framework and must still show.
        let groups = walk["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["id"].as_str(), Some("Art. 15"));
        assert_eq!(
            groups[0]["title"].as_str(),
            Some("Accuracy, robustness and cybersecurity")
        );
        assert_eq!(groups[0]["findings"].as_array().unwrap().len(), 1);
        assert_eq!(groups[0]["defects"].as_u64(), Some(1));

        assert_eq!(
            walk["unmapped"]["findings"].as_array().unwrap(),
            &vec![serde_json::json!(1)],
            "a finding the framework has nothing to say about must not vanish"
        );
    }

    /// Indices in a crosswalk address the report's own `findings` array, so a
    /// consumer can resolve them without a second lookup table.
    #[test]
    fn crosswalk_indices_address_the_findings_array() {
        let mut report = report_with(CveStatus::NoManifest);
        report.crosswalks = vec![crate::compliance::crosswalk(&report, Framework::NistAiRmf)];

        let text = render(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let findings = value["findings"].as_array().unwrap();

        for group in value["crosswalks"][0]["groups"].as_array().unwrap() {
            for index in group["findings"].as_array().unwrap() {
                let index = usize::try_from(index.as_u64().unwrap()).unwrap();
                assert!(findings.get(index).is_some(), "index {index} is dangling");
            }
        }
    }

    /// Every framework the CLI offers renders, so none can be reachable from
    /// the command line but broken in the output a pipeline reads.
    #[test]
    fn every_framework_renders() {
        for framework in Framework::ALL {
            let mut report = report_with(CveStatus::NoManifest);
            report.crosswalks = vec![crate::compliance::crosswalk(&report, framework)];
            let text = render(&report).unwrap();
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                value["crosswalks"][0]["framework"].as_str(),
                Some(framework.id())
            );
            assert_ne!(
                value["crosswalks"][0]["groups"].as_array().unwrap().len(),
                0
            );
        }
    }

    /// The default scan's shape: every framework, in one array, in the order
    /// [`Framework::ALL`] declares.
    ///
    /// The order is asserted because the array is how a consumer addresses a
    /// framework positionally. If it depended on anything but the constant,
    /// a pipeline reading `crosswalks[1]` would get a different document
    /// depending on how the scan was invoked.
    #[test]
    fn every_framework_is_carried_at_once_and_in_a_fixed_order() {
        let mut report = report_with(CveStatus::NoManifest);
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crate::compliance::crosswalk(&report, *framework))
            .collect();

        let value: serde_json::Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        let walks = value["crosswalks"].as_array().unwrap();

        assert_eq!(walks.len(), 3);
        let ids: Vec<&str> = walks
            .iter()
            .map(|walk| walk["framework"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["eu-ai-act", "nist-ai-rmf", "nist-genai"]);

        // Each carries its own caveat, so a consumer that reads one entry out
        // of the array cannot read it without the caveat.
        for walk in walks {
            assert_eq!(
                walk["disclaimer"].as_str(),
                Some(crate::compliance::DISCLAIMER)
            );
            assert_ne!(walk["standing"].as_str().unwrap(), "");
        }
    }

    /// The findings array is one array, and every crosswalk indexes into it.
    ///
    /// Three crosswalks over one report is the case where an index that meant
    /// something else — a position within a framework's own list, say — would
    /// go unnoticed until a consumer resolved it to the wrong finding.
    #[test]
    fn indices_from_every_crosswalk_address_the_same_findings_array() {
        let mut report = report_with(CveStatus::NoManifest);
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crate::compliance::crosswalk(&report, *framework))
            .collect();

        let value: serde_json::Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        let findings = value["findings"].as_array().unwrap();

        for walk in value["crosswalks"].as_array().unwrap() {
            let framework = walk["framework"].as_str().unwrap();
            for group in walk["groups"].as_array().unwrap() {
                for index in group["findings"].as_array().unwrap() {
                    let index = usize::try_from(index.as_u64().unwrap()).unwrap();
                    assert!(
                        findings.get(index).is_some(),
                        "{framework} has a dangling index {index}"
                    );
                }
            }
            for index in walk["unmapped"]["findings"].as_array().unwrap() {
                let index = usize::try_from(index.as_u64().unwrap()).unwrap();
                assert!(findings.get(index).is_some(), "{framework}: {index}");
            }
        }
    }

    #[test]
    fn empty_report_renders_cleanly() {
        let text = render(&empty_report()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let findings = value
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(findings.as_slice(), Vec::<serde_json::Value>::new());
    }

    #[test]
    fn a_partial_cve_status_serialises_with_its_counts() {
        let report = report_with(CveStatus::Partial {
            dependencies: 9,
            incomplete: 2,
        });
        let value: serde_json::Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        assert_eq!(
            value["cve"],
            serde_json::json!({"status": "partial", "dependencies": 9, "incomplete": 2})
        );
    }

    #[test]
    fn coverage_skips_carry_the_reason_as_data() {
        let mut report = report_with(CveStatus::NoManifest);
        report.skipped = vec![
            crate::report::Skip::generated(
                "web/bundle.js".to_owned(),
                "minified, 65536 bytes per line on average over the first 65536 bytes".to_owned(),
            ),
            crate::report::Skip::unparseable("broken.py".to_owned()),
        ];
        report.coverage.skipped = report
            .skipped
            .iter()
            .map(crate::report::CoveredSkip::from)
            .collect();

        let value: serde_json::Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        let skipped = value["coverage"]["skipped"].as_array().unwrap();

        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0]["path"], "web/bundle.js");
        assert_eq!(skipped[0]["reason"], "generated");
        assert_ne!(skipped[0]["detail"].as_str().unwrap(), "");
        assert_eq!(
            skipped[1],
            serde_json::json!({"path": "broken.py", "reason": "unparseable"})
        );
        // The published array is untouched by the structured one.
        assert!(value["skipped"][1].is_string());
    }

    #[test]
    fn every_skip_reason_serialises_in_snake_case() {
        use crate::report::SkipReason;
        let reasons = [
            (SkipReason::Excluded, "excluded"),
            (SkipReason::IgnoreFile, "ignore_file"),
            (SkipReason::Generated, "generated"),
            (SkipReason::Unreadable, "unreadable"),
            (SkipReason::Unparseable, "unparseable"),
            (SkipReason::Unpinned, "unpinned"),
            (SkipReason::Unstated, "unstated"),
        ];
        for (reason, name) in reasons {
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
        }
    }

    #[test]
    fn a_report_without_a_coverage_key_still_deserialises() {
        let older: serde_json::Value = serde_json::from_str(CONTRACT).unwrap();
        let mut older = older;
        older.as_object_mut().unwrap().remove("coverage");

        let report: crate::report::Report = serde_json::from_value(older).unwrap();

        assert_eq!(report.coverage, crate::report::Coverage::default());
    }
}
