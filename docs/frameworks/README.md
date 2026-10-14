# Frameworks

Every Bastyn finding maps to at least one category from one of these two
frameworks. The mapping is a promise, so it is deliberately conservative: a rule
may only claim a category Bastyn can actually detect from source.

| File | Framework | Categories |
| --- | --- | --- |
| [`owasp-genai-top10.md`](owasp-genai-top10.md) | OWASP Top 10 for GenAI, 08/2026 | 10 |
| [`anthropic-zero-trust.md`](anthropic-zero-trust.md) | Anthropic Zero Trust for agents, 05/2026 | 9 |

Those two are the taxonomies a finding is *assigned to*. A third document,
[`compliance-crosswalk.md`](compliance-crosswalk.md), maps those categories
outward to the EU AI Act and the two NIST AI documents. It is a crosswalk, not
a compliance assessment, and a weaker kind of statement than the assignment
above. [Compliance crosswalk](#compliance-crosswalk) below sets out the
difference.

## What Bastyn detects

Of the 19 categories, 14 appear in `bastyn_core::Category`. The other five are
absent from the enum on purpose. They are process and lifecycle guidance with
no signal in source code, so a rule claiming them would be a lie the type system
now prevents.

| Verdict | What it means | Categories |
| --- | --- | --- |
| **Defect** | Wrong regardless of deployment | LLM01, LLM02, LLM03, LLM04, LLM08, LLM10, ZT1, ZT2, ZT3, ZT4 |
| **Observation** | A control is absent, and only context says whether that is wrong | LLM06, LLM09, ZT5, ZT6 |
| **Not detectable** | No code signal, not in the enum | LLM05, LLM07, ZT7, ZT8, ZT9 |

Observations are hidden unless `--show-observations` is passed, and never
exceed `note` level in SARIF. "No authentication" is not a bug in a public
chatbot; "no rate limiting" cannot be judged from a repository at all, because
the limiter is normally at the edge. Reporting those as defects is a large
source of noise.

`Category::is_context_dependent` marks the four observation-only categories, and
rule loading rejects any rule that pairs one with `kind: defect`.

### Detectable is not the same as implemented

The table above says whether a category is *representable* in Bastyn's model,
meaning whether the type system would even let a rule claim it. It says nothing
about whether a rule actually exists yet. Of the 14 categories in
`bastyn_core::Category`, 12 currently have a production detector behind them:

| Detector | What it means | Categories |
| --- | --- | --- |
| **Implemented** | A rule, CVE check, or infra/MCP analyser exists and is measured in the corpus gate | LLM01, LLM02, LLM03, LLM04, LLM06, LLM08, LLM10, ZT1, ZT2, ZT3, ZT4, ZT5 |
| **Detectable, not yet implemented** | In the enum, correctly typed, no detector written | LLM09, ZT6 |

LLM04 and ZT3 are implemented mostly outside `rules/bastyn.yml`: LLM04 by
`BAS-CVE-001`'s OSV lookup, ZT3 by the container/MCP-config analysers and by
two observation rules in `rules/mcp_transport.yml`. LLM02 is carried by `rules/secrets.yml` and ZT5 by
`rules/memory.yml`, which is why neither appears in `bastyn.yml` either.

LLM09 and ZT6 remain without one. Both are recorded as `[[known_gap]]`
entries in [`tests/corpus/expected.toml`](../../tests/corpus/expected.toml),
and each is a candidate for a future rule rather than a permanent absence the
way the five not-detectable categories are. `expected.toml` also carries
known gaps for LLM02 and ZT5, but those are narrower: they mark a specific
corpus case the shipped rules do not reach, not a category nothing inspects.

## Cross-framework mapping

Each OWASP GenAI category also names the other framework *families* that
discuss the same risk: NIST AI RMF, MITRE ATLAS, CWE, and so on. It is a
**category-to-framework-family** mapping, and it says only one thing: "this
risk category is also discussed in NIST AI RMF." It does not say which
control. It does not mean a Bastyn finding satisfies, violates, or maps to
anything inside that framework. `Category::framework_families()` returns this
list per category; see [`owasp-genai-top10.md`](owasp-genai-top10.md) for the
full table and [`anthropic-zero-trust.md`](anthropic-zero-trust.md) for why
Zero Trust categories return none.

This mapping exists to answer "does Bastyn's taxonomy line up with the risk
literature", a documentation and coverage question. It is not compliance
evidence, and it must never be read as such. That is why it stays out of
anywhere the claim could be mistaken for a promise:

- **It is not on findings.** No finding, JSON or terminal, carries a
  framework-family list. Only the category id does.
- **It is not in SARIF `tags`.** SARIF tags are how GitHub and GitLab index
  and filter a rule, and `rule_tags_are_the_category_ids_and_only_those` (in
  `crates/bastyn-core/src/render/sarif.rs`) pins every rule's tags to exactly
  its category ids. Adding framework names to `tags` would make GitHub's UI
  read a finding as "this violates NIST AI RMF", a control-level claim this
  project has no basis to make. That test stays as the guardrail against it.
- **It is per category, not per rule.** A category can carry a
  framework-family list without any rule behind it existing yet (LLM09, for
  instance). See "Detectable is not the same as implemented" above. The
  mapping describes the taxonomy, not Bastyn's detection surface.

## Compliance crosswalk

[`compliance-crosswalk.md`](compliance-crosswalk.md) maps each category to the
EU AI Act, NIST AI RMF 1.0, and the NIST Generative AI Profile, at the level of
named articles and subcategories rather than framework families. Every
`bastyn scan` regroups its report by all three, with no flag: summarised in the
terminal, in full in the JSON's `crosswalks` array, and as one SARIF
`taxonomies` entry each. `--group-by <taxonomy>` narrows that to one framework
and expands it into the findings under each of its areas.

It is a stronger mapping than the framework-family list above, and a much
weaker one than a compliance verdict:

- **It names specific identifiers**, each quoted from a primary source with a
  URL and access date. "Relevant to EU AI Act Art. 15 (accuracy, robustness
  and cybersecurity)" rather than "discussed in NIST AI RMF".
- **It is still per category**, so everything the "It is per category, not per
  rule" point above says applies here unchanged. LLM09 and ZT6 appear in the
  crosswalk table with no detector behind them.
- **It is never a verdict.** Bastyn cannot determine regulatory compliance.
  `bastyn_core::compliance::DISCLAIMER` says so, every `Crosswalk` value
  carries it, and every renderer that emits a grouping emits it too.
- **It does not go in SARIF `tags`.** Same reasoning as the framework families:
  it goes in `run.taxonomies` with `relevant` relationships instead, and
  `rule_tags_are_the_category_ids_and_only_those` still holds.

Two cells in that table are deliberately empty, with the reasoning recorded:
LLM06 has no EU AI Act article about cost or token ceilings, and none of the
twelve NIST Generative AI Profile risks is about audit trails, so ZT6 has no
entry there.

## Layers

The two frameworks are not two flat lists of equals. The OWASP categories name
threats, and those threats sit in concentric rings: an attacker gets in through
an entry vector, the foothold is magnified by the agent's own machinery, and it
lands as an impact. The Zero Trust categories name the defenses that break that
chain. `Category::layer` records which ring a category is on.

| Layer | Categories | Why it is where it is |
| --- | --- | --- |
| Entry | LLM01, LLM04 | The two ways in: text the attacker wrote, and code someone else wrote that the build pulled in |
| Amplifier | LLM08, LLM09 | The context window working against its owner. A foothold reads more, or reaches further, than it should |
| Impact | LLM02, LLM06 | What the attacker leaves with: data, or someone else's bill |
| Cross-layer | LLM03, LLM10 | Genuinely present at more than one ring, not a hedge |
| Defense (perimeter) | ZT3, ZT4 | Keep the agent in; keep instructions and data apart |
| Defense (machinery) | ZT1, ZT2, ZT5 | Identity, authority, and memory |
| Defense (impact mitigation) | ZT6 | Stops nothing; bounds how long the damage runs |

The terminal report groups defects by layer in that order, so it argues what to
fix first rather than only what is wrong: close the entry vector and the impacts
downstream of it never happen. A finding mapping to more than one category is
printed once, under the earliest layer it names. `[LLM01, ZT4]` is an entry
vector, not a missing defense. The layer is a presentation concern only: it
never appears in the JSON or SARIF output.

## The gap: per-rule CWE identifiers

Bastyn has no per-rule CWE identifiers anywhere. The `eval()`-on-LLM-output
rule does not carry `CWE-94`; the hardcoded-credential rules do not carry
`CWE-798`. `Category::framework_families()` says LLM10 is *also discussed in*
the CWE family as a whole. It does not, and cannot, say which CWE number.
That is a real gap, and a more valuable piece of work than the
category-to-framework mapping this document covers:

- **It is precise instead of coarse.** "LLM10 is discussed in CWE" is a
  taxonomy-coverage statement about a whole risk category. "This rule detects
  CWE-94, Improper Control of Generation of Code" is a claim about one rule's
  actual behaviour, the kind of claim a reader can act on and the kind
  SARIF's own tagging conventions expect.
- **It is per rule, not per category.** A single OWASP category can cover
  several distinct CWEs (LLM02 alone touches exposure-of-sensitive-data CWEs
  and hardcoded-credential CWEs, which are not the same weakness). Only a
  per-rule identifier can say which one a given `ast-grep` pattern actually
  catches; the category-level mapping in this document structurally cannot.
- **It is what tooling consumes.** GitHub code scanning, SARIF viewers, and
  most compliance pipelines key off CWE ids at the rule level, not off
  framework-family names at the category level. Category-family coverage is
  documentation; per-rule CWE ids are what downstream tooling would actually
  index.

Doing it properly means extending the rule schema (`rules/schema.rs`) with a
`cwe:` field, threading it through the engine (`rules/engine.rs`) and every
rule definition in `rules/*.yml`, deciding how it surfaces in SARIF (most
plausibly SARIF's own `properties.cwe` convention, not `tags`, for the same
reason framework families do not belong in `tags`: `tags` is what indexes and
filters a rule, not what documents it), and auditing every existing rule to
assign a correct id rather than a plausible-looking one. Inventing a CWE
number to fill the field would be exactly the overclaiming this document
exists to avoid. That is schema, engine, and rule-content work across the
whole rule set, not a documentation change, which is why it is out of scope
here and left as the next concrete step.
