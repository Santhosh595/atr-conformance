# Plain-language explanation

## `atr_conformance/yaml_lite.py`

**What it does.** Reads the small subset of YAML used by ATR rule files into
Python dictionaries and lists, using only the standard library.

**How it works.** It walks lines in order, using indentation to decide whether
a block is a mapping or a list. It understands quoted strings (including ones
that span lines), literal/folded block scalars (`|`, `>-`), flow lists and maps,
and plain scalars that wrap onto later lines. If a line does not fit the subset,
it raises `YAMLError`; callers turn that into an explicit "unreadable" finding
instead of guessing.

**Likely viva questions**

1. *Why not use PyYAML?* The project promises zero runtime dependencies, so a
   checkout runs with plain Python. The cost is that this is a subset parser;
   anything it cannot read is reported, not silently skipped.
2. *What happens with a valid YAML feature you do not support?* The file gets a
   `yaml-parse` finding. That is honest but means a false positive is possible
   on unusual YAML.
3. *How did you test it?* Against hand-written cases and against all 843 rule
   files in the upstream corpus; all 843 parse.

## `atr_conformance/validate.py`

**What it does.** Turns a rule file into a list of findings (`error` or
`warning`) based on SPEC.md §4–§6 and the normative rule schema.

**How it works.** It checks required fields, ID/date formats, enums, the shape
of each detection condition, operator names, regex compilation, and test-case
counts and verdict tokens. Regex compilation is only a warning because Python
`re` and ECMAScript regex are different dialects.

**Likely viva questions**

1. *Where do the rules come from?* The upstream `SPEC.md` and
   `spec/schema/rule.schema.json`; nothing is invented here.
2. *Why is a regex that fails to compile only a warning?* Because a pattern can
   be valid ECMAScript and invalid in Python. A warning means "check by hand".
3. *Does the tool modify rules?* No. It reads and reports only.

## `atr_conformance/score.py`

**What it does.** Measures what each rule does on a labelled JSONL stream and
reports true/false positives and negatives, precision, recall and false-positive
rate.

**How it works.** For each observation and rule it evaluates the detection
conditions against the `text` value, combines them with `any` or `all`, then
adds the result to the confusion matrix using the `attack`/`benign` label.
Unsupported operators produce an entry in `rules_unsupported` and the rule is
removed from the scored set. Zero denominators become `None`, printed as
`not available`.

**Likely viva questions**

1. *Is this an engine conformance result?* No. There is no structured
   `AgentEvent` here, only text. It is a rule-text check.
2. *What about ML or behavioral rules?* They are excluded and named, so a
   reader can see exactly what was not measured.
3. *How are false positives defined?* A benign observation that the rule
   matches. The rate is `fp / (fp + tn)`.

## `atr_conformance/cli.py` and `__main__.py`

**What it does.** Exposes `validate` and `score` as commands, prints text or
JSON, and sets exit codes so CI can use it.

**How it works.** `argparse` defines the two subcommands. `main()` catches I/O
and value errors and returns `2`. `__main__.py` turns that return value into the
process exit status.

**Likely viva questions**

1. *Why two subcommands?* Validation and scoring answer different questions and
   have different failure semantics.
2. *Why exit code 2?* It means the run was inconclusive (bad path or I/O error),
   not that a rule failed.
3. *Why JSON output?* So a CI job or another script can consume the report
   without parsing terminal text.

## `tests/` and `examples/`

**What they do.** `tests/` holds 24 assertions covering the YAML reader,
validator, scorer and CLI. `examples/atr-2026-00030.jsonl` holds ten real test
cases copied from upstream rule `ATR-2026-00030` (five attack, five benign).

**How they work.** Tests use temporary directories for rule files and streams,
and check exact values rather than just "did not crash". The example stream is
used for the measured command in the README.

**Likely viva questions**

1. *Is the example data invented?* No. It comes from the upstream rule's
   `test_cases` field.
2. *Can the tests fail?* Yes — they assert exact counts and codes; a change to
   any operator or check breaks them.
3. *Why keep an example stream in the repo?* So the README's numbers can be
   reproduced by anyone without downloading the upstream corpus.

## `.github/workflows/ci.yml`

**What it does.** Runs the test suite on Python 3.11 and 3.12 for every push and
pull request to `main`.

**How it works.** It installs pytest (the only development dependency) and runs
`python -m pytest tests/ -q`. Third-party actions are pinned to full commit
SHAs, matching the practice in the other repos.

**Likely viva questions**

1. *Is pytest a runtime dependency?* No. The tool itself needs no packages.
2. *Why pin actions by SHA?* Tags can be moved; a SHA is immutable.
3. *Why two Python versions?* To catch syntax or stdlib differences early.
