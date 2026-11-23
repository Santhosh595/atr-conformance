from atr_conformance.yaml_lite import YAMLError, parse


def test_nested_mapping_and_list_of_mappings():
    data = parse(
        """\
tags:
  category: prompt-injection
detection:
  conditions:
    - field: content
      operator: contains
      value: "ignore: all"
    - field: content
      operator: regex
      value: '(?i)delete\\s+all'
"""
    )
    assert data["tags"]["category"] == "prompt-injection"
    assert data["detection"]["conditions"][0]["value"] == "ignore: all"
    assert data["detection"]["conditions"][1]["operator"] == "regex"


def test_block_scalars_and_flow_values():
    data = parse(
        """\
description: |
  line one
  line two
tags: [prompt-injection, agent-manipulation]
response: {actions: [log_alert]}
"""
    )
    assert data["description"] == "line one\nline two"
    assert data["tags"] == ["prompt-injection", "agent-manipulation"]
    assert data["response"]["actions"] == ["log_alert"]


def test_multiline_quoted_and_plain_scalars():
    data = parse(
        """\
title: "A title that
  continues here"
description: 'quoted text
  spanning lines'
notes: plain text that
  also spans lines
"""
    )
    assert data["title"] == "A title that continues here"
    assert data["description"] == "quoted text spanning lines"
    assert data["notes"] == "plain text that also spans lines"


def test_sequence_at_parent_indent():
    data = parse(
        """\
references:
  cve:
  - CVE-2026-0001
  cwe:
  - CWE-200
"""
    )
    assert data["references"]["cve"] == ["CVE-2026-0001"]
    assert data["references"]["cwe"] == ["CWE-200"]


def test_bad_indentation_is_reported():
    try:
        parse("title: ok\n  stray: value\n")
    except YAMLError as exc:
        assert "unexpected indentation" in str(exc)
    else:
        raise AssertionError("expected YAMLError")
