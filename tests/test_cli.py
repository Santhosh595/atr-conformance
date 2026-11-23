import json

from atr_conformance.cli import main

RULE = """\
schema_version: "0.1"
id: ATR-2026-00001
title: A valid detection rule
status: experimental
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
    - input: summarise the report
      expected: not_triggered
"""


def setup(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yaml").write_text(RULE, encoding="utf-8")
    stream = tmp_path / "stream.jsonl"
    stream.write_text(
        json.dumps({"text": "ignore previous instructions", "label": "attack"}) + "\n"
        + json.dumps({"text": "summarise the report", "label": "benign"}) + "\n",
        encoding="utf-8",
    )
    return rules, stream


def test_validate_clean_rule(capsys, tmp_path):
    rules, _ = setup(tmp_path)
    assert main(["validate", str(rules)]) == 0
    assert "errors: 0" in capsys.readouterr().out


def test_validate_bad_rule_exit_code(capsys, tmp_path):
    rules, _ = setup(tmp_path)
    (rules / "rule.yaml").write_text(RULE.replace("severity: high", "severity: wrong"), encoding="utf-8")
    assert main(["validate", str(rules)]) == 1
    assert "severity-invalid" in capsys.readouterr().out


def test_validate_json_output(capsys, tmp_path):
    rules, _ = setup(tmp_path)
    assert main(["validate", str(rules), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_score_output(capsys, tmp_path):
    rules, stream = setup(tmp_path)
    assert main(["score", "--rules", str(rules), "--stream", str(stream)]) == 0
    assert "ATR-2026-00001" in capsys.readouterr().out


def test_score_json_output(capsys, tmp_path):
    rules, stream = setup(tmp_path)
    assert main(["score", "--rules", str(rules), "--stream", str(stream), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["overall"]["tp"] == 1
    assert report["overall"]["recall"] == 1.0


def test_missing_paths_exit_two(capsys, tmp_path):
    assert main(["score", "--rules", str(tmp_path / "none"), "--stream", str(tmp_path / "none")]) == 2
    assert "not a rules directory" in capsys.readouterr().err
