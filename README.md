# atr-conformance

A stdlib-only Python CLI that (1) checks ATR rule files against the rule-format
rules in `SPEC.md` and (2) scores rules against a labelled JSONL stream.

It exists because the upstream [agent-threat-rules](https://github.com/Santhosh595/agent-threat-rules)
conformance runner is a Node/TypeScript tool that needs `npm install`, a build
step and an engine CLI. This tool runs from a checkout with just Python. It does
**not** replace that runner: it answers a different question — "are these rule
files well formed, and what do they do on my own labelled data?"

No network calls, no model calls, no third-party packages at runtime.

## Install

```bash
pip install -e .
```

Or run directly from a checkout: `python3 -m atr_conformance ...`

## Validate rule files

```bash
atr-conformance validate /path/to/agent-threat-rules/rules
atr-conformance validate rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml --json
```

Checks (all from `SPEC.md` §4–§6 and `spec/schema/rule.schema.json`):

- required fields present;
- `id`, `schema_version`, `date` formats;
- `status`, `severity`, `detection_tier`, `maturity` enums; `tags.category`;
- `agent_source.type`, `response.actions`;
- detection conditions have a valid shape and a known operator;
- regex values compile (as a **warning** — Python `re` is not ECMAScript, so a
  warning means "verify by hand", not "invalid");
- test cases use `input` + `expected: triggered|not_triggered`, with the counts
  the spec requires for each maturity.

Exit codes: `0` no errors, `1` at least one error, `2` tool error.

## Score against a labelled stream

Each JSONL line needs a text field and a label of `attack` or `benign`:

```json
{"text": "ignore previous instructions", "label": "attack"}
```

```bash
atr-conformance score \
  --rules /path/to/agent-threat-rules/rules \
  --stream examples/atr-2026-00030.jsonl \
  --rule ATR-2026-00030
```

Measured output on this checkout (10 real test cases taken from rule
`ATR-2026-00030` in the upstream corpus):

```text
rules found: 843  evaluated: 1
lines read: 10  evaluated: 10

rule                    tp    fp    fn    tn      precision         recall            fpr
ATR-2026-00030           5     0     0     5         100.0%         100.0%           0.0%
```

`--json` prints a machine-readable report. A denominator of zero prints
`not available` in text mode and `null` in JSON; nothing is reported as 0% when
there was no evidence.

### What scoring does and does not do

- Supported operators: `regex`, `contains`, `equals`, `matches` (glob).
  Leading `(?i)`, `(?m)`, `(?s)` and `(?x)` flag groups are handled per SPEC §6.4;
  `m`, `s` and `x` have no effect, as the spec requires.
- Rules with `ml_classifier`, `ast`, `bytecode`, behavioral conditions or
  boolean-expression combinators are **excluded and listed by name with the
  reason**. They are never silently counted as non-matches.
- The tool evaluates the stream's `text` value against every condition. It does
  not reconstruct a structured `AgentEvent`, so `field:` selectors are not
  resolved against a real event object. Precision/recall from this tool are a
  check on rule text, **not** an engine conformance result.
- Malformed JSON, missing text and unknown labels are counted in `lines_skipped`.

## Measured validation of the upstream corpus

On 2026-11-23, against a local sparse clone of upstream `main` (843 rule files):

- 843 / 843 files parsed by the built-in reader;
- 799 findings across 174 files, with no YAML parse errors.

The largest classes were `test-case-shape` (543), `test-cases-count` (132) and
`verdict-legacy` (73). These are findings in the upstream corpus, not in this
tool: for example `test_cases` entries using `content:` instead of the
schema-required `input:`, and `maturity: stable` rules with fewer than five
examples per side. Upstream `main` moves; rerun the command to get current
numbers rather than trusting these.

## Tests

```bash
python3 -m pytest tests/ -q
```

Measured on this checkout: `24 passed in 0.08s`. CI runs the same suite on
Python 3.11 and 3.12.

## Licence

MIT
