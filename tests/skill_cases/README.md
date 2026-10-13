# Skill cases

A labeled, reproducible set of synthetic agent skills that records what the scanner does with malicious and benign skill content. It is separate from the release gate (`tests/corpus`, `crates/bastyn-core/tests/corpus_gate.rs`) on purpose: the gate hard-caps known gaps and known false positives, while this suite deliberately records many misses and must not count against those caps.

The figures it prints are measured on these synthetic cases only. They are not detection or false-positive rates for real-world skills.

## Layout

- `malicious/<case-id>/` and `benign/<case-id>/`: one skill directory per case, with `SKILL.md` and, where the case needs them, `references/` and `scripts/`.
- `cases.toml`: one `[[case]]` per directory.
- `crates/bastyn-core/tests/skill_cases.rs`: the harness.

## Pairs (twins)

Every malicious case M01..M14 has one benign twin B11..B23 and B25 (B11 twins M01, and so on), linked by `pair` in `cases.toml` on both sides. A twin is a copy of the malicious skill (same frontmatter shape, files, pattern position and length) with the minimal edit that makes it benign, so the only difference is intent. Twins carry a different `name:` but the same topic.

| pair | the minimal edit in the twin |
|---|---|
| M01 / B11 | the description quotes an override phrase while describing a detector |
| M02 / B12 | the override line becomes a quoted example in a fenced block, plus a sentence to refuse it |
| M03 / B13 | the reworded override becomes guidance to refuse it and report it |
| M04 / B14 | the reference holds ordinary setup steps and one quoted override example marked for rejection |
| M05 / B15 | the reworded override in the reference becomes refuse-guidance |
| M06 / B16 | hidden tag characters become a legitimate subdivision flag emoji |
| M07 / B17 | zero-width and bidi-override characters become an Arabic phrase with an ordinary right-to-left mark |
| M08 / B18 | the base64 string decodes to a harmless sentence, shown to the user as an encoding example |
| M09 / B19 | reads `~/.aws/config` and lists profile names locally; nothing is uploaded |
| M10 / B20 | reads the public key and prints it; no network call |
| M11 / B21 | deletion requires asking for confirmation first |
| M12 / B22 | every deletion needs the operator's approval |
| M13 / B23 | the bypass wording becomes a quoted example to avoid, with a sentence saying never to follow it |
| M14 / B25 | the override phrase after a non-refusal negation becomes a sentence telling the agent never to follow it |

B06 (family emoji with zero-width joiners and accents) and B24 (a leading byte-order mark only) are unpaired benign cases for those two behaviours.

The harness checks that each pair has opposite labels, that both cases exist and that the link is symmetric, and prints a pair table on every run: both outcomes and whether the scanner separates the pair (malicious `detected` and twin `clean`), ending with `pairs separated: X of 14`.

## Labeling rules

- The `label` (`malicious` or `benign`) is what the content really is. It is never changed because the scanner misses or flags it.
- `outcome_now` is the scanner's current behaviour, recorded by running it (`bastyn scan <dir> --offline --format json --show-observations`).
- A case counts as `detected` or `flagged` when the scanner produces any finding, defect or observation, whose location is under the case directory.
- Attack strings are realistic and unsanitised, but inert text. Fixtures are synthetic: hosts are reserved example names (`collector.example`) and no file holds a real credential.

## Outcome vocabulary

| label | outcome_now | meaning |
|---|---|---|
| malicious | `detected` | true positive |
| malicious | `missed` | known detection gap |
| benign | `clean` | correct silence |
| benign | `flagged` | known false positive |

`expected_observation = true` marks a benign case whose observation is correct output (for example a format observation on a skill missing a required frontmatter field). For it, `flagged` is acceptable and not a false positive.

## Running

```sh
cargo test -p bastyn-core --test skill_cases --locked -- --nocapture
```

Every run prints a summary per class and overall. The test fails when:

- a case is worse than `outcome_now` (`detected` to `missed`, `clean` to `flagged`);
- a case stops producing a rule listed in its `rules`;
- a case directory has no `[[case]]` entry, or an entry points at a missing directory, or a label/outcome pair is inconsistent.

When a case improves (`missed` to `detected`, `flagged` to `clean`) or its rules change otherwise, the run passes and prints an "update cases.toml" notice. Update `outcome_now` and `rules` then; leave `label` alone.

## Files with special codepoints

- `benign/B06-emoji-zwj-and-accents/SKILL.md`: zero-width joiners (U+200D) in family emoji, accented text.
- `benign/B16-subdivision-flag-tag-characters/SKILL.md`: a subdivision flag emoji, a black flag (U+1F3F4) followed by tag characters and the cancel tag (U+E007F).
- `benign/B17-rtl-text-with-rtl-mark/references/format.md`: Arabic text and a right-to-left mark (U+200F).
- `benign/B24-benign-bom-only/SKILL.md`: a leading byte-order mark (U+FEFF) and nothing else.
- `malicious/M06-hidden-unicode-tag-characters-in-skill/SKILL.md`: an instruction encoded as Unicode tag characters (U+E0000 block).
- `malicious/M07-hidden-zero-width-in-reference/references/format.md`: zero-width spaces (U+200B) and a bidirectional override (U+202E, U+202C).

Check them with `xxd` or a script before editing, since editors may strip these characters.
