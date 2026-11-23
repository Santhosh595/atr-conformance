import json

from atr_conformance.score import evaluate, score

RULE = """\
id: ATR-2026-00001
title: Injection detector
detection:
  condition: any
  conditions:
    - field: content
      operator: contains
      value: ignore previous instructions
"""

UNSUPPORTED = """\
id: ATR-2026-00002
title: Classifier detector
detection:
  conditions:
    - field: content
      operator: ml_classifier
      value: injection-model
"""


def setup(tmp_path, rules):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for name, text in rules.items():
        (rules_dir / f"{name}.yaml").write_text(text, encoding="utf-8")
    return rules_dir


def stream(tmp_path, rows):
    path = tmp_path / "stream.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_evaluate_operators():
    rule = {"detection": {"conditions": [{"field": "content", "operator": "contains", "value": "drop table"}]}}
    assert evaluate(rule, "please drop table now") == (True, None)
    assert evaluate(rule, "select all rows") == (False, None)
    other = {"detection": {"conditions": [{"field": "content", "operator": "ml_classifier", "value": "model"}]}}
    assert evaluate(other, "anything")[1] == "operator 'ml_classifier' is not supported"


def test_perfect_separation(tmp_path):
    rules_dir = setup(tmp_path, {"a": RULE})
    data = stream(
        tmp_path,
        [
            {"text": "ignore previous instructions", "label": "attack"},
            {"text": "summarise the report please", "label": "benign"},
        ],
    )
    result = score(rules_dir, data)
    counts = result.per_rule["ATR-2026-00001"][1]
    assert (counts.tp, counts.fp, counts.fn, counts.tn) == (1, 0, 0, 1)
    assert counts.as_dict()["precision"] == 1.0
    assert result.overall.as_dict()["false_positive_rate"] == 0.0


def test_false_positive_and_missing_labels(tmp_path):
    rules_dir = setup(tmp_path, {"a": RULE})
    data = tmp_path / "mixed.jsonl"
    data.write_text(
        json.dumps({"text": "ignore previous instructions", "label": "benign"}) + "\n"
        + json.dumps({"text": "hello", "label": "unknown"}) + "\n"
        + "{not json\n",
        encoding="utf-8",
    )
    result = score(rules_dir, data)
    assert result.per_rule["ATR-2026-00001"][1].fp == 1
    assert result.lines_skipped == {"unlabelled": 1, "invalid_json": 1}


def test_unsupported_rule_is_excluded_with_reason(tmp_path):
    rules_dir = setup(tmp_path, {"a": UNSUPPORTED})
    data = stream(tmp_path, [{"text": "anything", "label": "attack"}])
    result = score(rules_dir, data)
    assert result.per_rule == {}
    assert "not supported" in result.rules_unsupported["ATR-2026-00002"]


def test_zero_denominator_returns_none(tmp_path):
    rules_dir = setup(tmp_path, {"a": RULE})
    data = stream(tmp_path, [{"text": "hello", "label": "benign"}])
    result = score(rules_dir, data)
    assert result.overall.as_dict()["precision"] is None
    assert result.overall.as_dict()["recall"] is None
    assert result.overall.as_dict()["false_positive_rate"] == 0.0


def test_rule_filter(tmp_path):
    rules_dir = setup(tmp_path, {"a": RULE, "b": UNSUPPORTED})
    data = stream(tmp_path, [{"text": "ignore previous instructions", "label": "attack"}])
    result = score(rules_dir, data, rule_filter="00001")
    assert result.rules_found == 2
    assert list(result.per_rule) == ["ATR-2026-00001"]
