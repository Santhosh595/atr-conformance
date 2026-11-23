from atr_conformance.validate import validate_rule

VALID = """\
schema_version: "0.1"
id: ATR-2026-00001
title: A valid detection rule
status: stable
description: This description is definitely longer than twenty characters.
author: Test Author
date: 2026/01/01
severity: high
detection_tier: pattern
maturity: experimental
tags:
  category: prompt-injection
agent_source:
  type: llm_io
detection:
  condition: any
  conditions:
    - field: content
      operator: contains
      value: ignore previous instructions
response:
  actions:
    - log_alert
test_cases:
  true_positives:
    - input: ignore previous instructions
      expected: triggered
  true_negatives:
    - input: please summarise the report
      expected: not_triggered
"""


def write_rule(tmp_path, text=VALID):
    path = tmp_path / "rule.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_rule_has_no_findings(tmp_path):
    assert validate_rule(write_rule(tmp_path)) == []


def test_missing_required_field(tmp_path):
    text = VALID.replace("author: Test Author\n", "")
    findings = validate_rule(write_rule(tmp_path, text))
    assert [item.code for item in findings] == ["field-missing"]


def test_bad_id_and_enum(tmp_path):
    text = VALID.replace("ATR-2026-00001", "ATR-ABC").replace("severity: high", "severity: severe")
    codes = {item.code for item in validate_rule(write_rule(tmp_path, text))}
    assert codes == {"id-invalid", "severity-invalid"}


def test_unknown_operator_and_condition_shape(tmp_path):
    bad_operator = VALID.replace("operator: contains", "operator: magic")
    bad_shape = VALID.replace(
        """    - field: content
      operator: contains
      value: ignore previous instructions""",
        """    - metric: tool_calls
      operator: magic
      threshold: 10""",
    )
    first = tmp_path / "first.yaml"
    first.write_text(bad_operator, encoding="utf-8")
    second = tmp_path / "second.yaml"
    second.write_text(bad_shape, encoding="utf-8")
    assert "operator-unknown" in {item.code for item in validate_rule(first)}
    assert "operator-unknown" in {item.code for item in validate_rule(second)}


def test_legacy_verdict_is_a_warning(tmp_path):
    text = VALID.replace("expected: triggered", "expected: trigger")
    findings = validate_rule(write_rule(tmp_path, text))
    assert [(item.code, item.severity) for item in findings] == [("verdict-legacy", "warning")]


def test_stable_rule_needs_five_examples(tmp_path):
    text = VALID.replace("maturity: experimental", "maturity: stable")
    findings = validate_rule(write_rule(tmp_path, text))
    assert len([item for item in findings if item.code == "test-cases-count"]) == 2


def test_broken_yaml_is_reported(tmp_path):
    findings = validate_rule(write_rule(tmp_path, "title: ok\n  stray: x\n"))
    assert [item.code for item in findings] == ["yaml-parse"]
