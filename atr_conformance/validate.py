"""Structural checks for ATR rule documents.

The rules come from SPEC.md sections 4, 5 and 6 of agent-threat-rules. Each
check maps to a finding code so a CI job can fail on a specific class of error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .yaml_lite import YAMLError, parse

REQUIRED_FIELDS = (
    "schema_version",
    "id",
    "title",
    "status",
    "description",
    "author",
    "date",
    "severity",
    "detection_tier",
    "maturity",
    "tags",
    "agent_source",
    "detection",
    "response",
)
STATUSES = {"draft", "experimental", "stable", "deprecated"}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
TIERS = {"pattern", "behavioral", "protocol", "classifier"}
MATURITIES = ("draft", "experimental", "test", "stable", "deprecated")
CATEGORIES = {
    "prompt-injection",
    "agent-manipulation",
    "skill-compromise",
    "context-exfiltration",
    "tool-poisoning",
    "privilege-escalation",
    "model-abuse",
    "excessive-autonomy",
    "model-security",
    "data-poisoning",
}
PATTERN_OPERATORS = {"regex", "contains", "equals", "matches", "ml_classifier", "ast", "bytecode"}
BEHAVIORAL_OPERATORS = {"gt", "lt", "gte", "lte", "eq"}
VERDICTS = {"triggered", "not_triggered"}
LEGACY_VERDICTS = {"trigger", "no_trigger"}
ID_RE = re.compile(r"^ATR-\d{4}-\d{5}$")
VERSION_RE = re.compile(r"^\d+\.\d+$")
DATE_RE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")
FLAG_GROUP_RE = re.compile(r"^\(\?([imsux]+)\)")


@dataclass(frozen=True)
class Finding:
    path: str
    severity: str
    code: str
    message: str
    line: int = 0

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "line": self.line,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }


def _finding(path: str, severity: str, code: str, message: str, line: int = 0) -> Finding:
    return Finding(path, severity, code, message, line)


def _regex_check(value: str) -> str | None:
    flags = 0
    match = FLAG_GROUP_RE.match(value)
    if match:
        if "i" in match.group(1):
            flags = re.IGNORECASE
        value = value[match.end() :]
    try:
        re.compile(value, flags)
    except re.error as exc:
        return str(exc)
    return None


def _check_detection(path: str, detection) -> list[Finding]:
    findings = []
    if not isinstance(detection, dict):
        return [_finding(path, "error", "detection-type", "detection must be a mapping")]
    conditions = detection.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        return [_finding(path, "error", "conditions-missing", "detection.conditions must be a non-empty list")]
    combinator = detection.get("condition", "any")
    if not isinstance(combinator, str) or not combinator.strip():
        findings.append(_finding(path, "error", "combinator-type", "detection.condition must be a string"))
    elif combinator not in ("any", "all") and not re.search(r"\b(AND|OR|NOT)\b", combinator):
        findings.append(
            _finding(path, "error", "combinator-value", "detection.condition is not any, all or a boolean expression")
        )
    for index, condition in enumerate(conditions):
        label = f"condition[{index}]"
        if not isinstance(condition, dict):
            findings.append(_finding(path, "error", "condition-shape", f"{label} must be a mapping"))
            continue
        is_pattern = {"field", "operator", "value"} <= condition.keys()
        is_behavioral = {"metric", "operator", "threshold"} <= condition.keys()
        if is_pattern == is_behavioral:
            findings.append(
                _finding(path, "error", "condition-shape", f"{label} is neither a pattern nor a behavioral condition")
            )
            continue
        operator = condition.get("operator")
        if is_pattern and operator not in PATTERN_OPERATORS:
            findings.append(_finding(path, "error", "operator-unknown", f"{label} has unknown operator {operator!r}"))
        if is_behavioral and operator not in BEHAVIORAL_OPERATORS:
            findings.append(
                _finding(path, "error", "operator-unknown", f"{label} has unknown numeric operator {operator!r}")
            )
        if is_pattern and operator == "regex":
            value = condition.get("value")
            if not isinstance(value, str):
                findings.append(_finding(path, "error", "regex-type", f"{label} regex value must be a string"))
            elif error := _regex_check(value):
                findings.append(
                    _finding(
                        path,
                        "warning",
                        "regex-python-compat",
                        f"{label} does not compile with Python re ({error}); verify ECMAScript validity by hand",
                    )
                )
    return findings


def _check_test_cases(path: str, rule: dict) -> list[Finding]:
    findings = []
    cases = rule.get("test_cases")
    if cases is None:
        if rule.get("maturity") in ("experimental", "test", "stable"):
            findings.append(
                _finding(path, "error", "test-cases-missing", "test_cases required at experimental maturity or above")
            )
        return findings
    if not isinstance(cases, dict):
        return [_finding(path, "error", "test-cases-type", "test_cases must be a mapping")]
    counts = {}
    for name in ("true_positives", "true_negatives"):
        entries = cases.get(name)
        if not isinstance(entries, list):
            findings.append(_finding(path, "error", "test-cases-type", f"test_cases.{name} must be a list"))
            continue
        counts[name] = len(entries)
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or "input" not in entry:
                findings.append(
                    _finding(path, "error", "test-case-shape", f"{name}[{index}] needs an input field")
                )
                continue
            verdict = entry.get("expected")
            if verdict in LEGACY_VERDICTS:
                findings.append(
                    _finding(path, "warning", "verdict-legacy", f"{name}[{index}] uses deprecated verdict {verdict!r}")
                )
            elif verdict not in VERDICTS:
                findings.append(
                    _finding(path, "error", "verdict-invalid", f"{name}[{index}] has invalid expected {verdict!r}")
                )
    maturity = rule.get("maturity")
    minimum = 5 if maturity == "stable" else 1
    if maturity in ("experimental", "test", "stable"):
        for name, needed in (("true_positives", minimum), ("true_negatives", minimum)):
            if counts.get(name, 0) < needed:
                findings.append(
                    _finding(
                        path,
                        "error",
                        "test-cases-count",
                        f"{name} has {counts.get(name, 0)} entries, needs at least {needed} for {maturity}",
                    )
                )
    return findings


def validate_rule(path: Path) -> list[Finding]:
    name = str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [_finding(name, "error", "unreadable", str(exc))]
    try:
        rule = parse(text)
    except YAMLError as exc:
        return [_finding(name, "error", "yaml-parse", str(exc), getattr(exc, "line", 0))]
    findings = []
    for field in REQUIRED_FIELDS:
        if field not in rule or rule[field] is None:
            findings.append(_finding(name, "error", "field-missing", f"missing required field {field!r}"))
    checks = (
        ("schema_version", VERSION_RE.fullmatch, "invalid schema_version, expected major.minor"),
        ("id", ID_RE.fullmatch, "invalid rule id, expected ATR-YYYY-NNNNN"),
        ("date", DATE_RE.fullmatch, "invalid date, expected YYYY-MM-DD or YYYY/MM/DD"),
    )
    for field, matcher, message in checks:
        value = rule.get(field)
        if value is not None and (not isinstance(value, str) or not matcher(value)):
            findings.append(_finding(name, "error", f"{field}-invalid", message))
    for field, minimum in (("title", 5), ("description", 20), ("author", 1)):
        value = rule.get(field)
        if value is not None and (not isinstance(value, str) or len(value.strip()) < minimum):
            findings.append(
                _finding(name, "error", f"{field}-short", f"{field} must be a string of at least {minimum} characters")
            )
    enums = (("status", STATUSES), ("severity", SEVERITIES), ("detection_tier", TIERS), ("maturity", set(MATURITIES)))
    for field, allowed in enums:
        value = rule.get(field)
        if value is not None and value not in allowed:
            findings.append(_finding(name, "error", f"{field}-invalid", f"{field} must be one of {sorted(allowed)}"))
    tags = rule.get("tags")
    if tags is not None and (not isinstance(tags, dict) or "category" not in tags):
        findings.append(_finding(name, "error", "tags-invalid", "tags must contain a category"))
    elif isinstance(tags, dict) and tags.get("category") not in CATEGORIES:
        findings.append(_finding(name, "error", "category-invalid", f"unknown canonical category {tags.get('category')!r}"))
    source = rule.get("agent_source")
    if source is not None and (not isinstance(source, dict) or "type" not in source):
        findings.append(_finding(name, "error", "agent-source-invalid", "agent_source must contain a type"))
    response = rule.get("response")
    if response is not None and (
        not isinstance(response, dict) or not isinstance(response.get("actions"), list) or not response["actions"]
    ):
        findings.append(_finding(name, "error", "response-invalid", "response.actions must be a non-empty list"))
    findings.extend(_check_detection(name, rule.get("detection")))
    findings.extend(_check_test_cases(name, rule))
    return findings


def rule_files(paths: list[Path]) -> list[Path]:
    found = []
    for path in paths:
        if path.is_file():
            found.append(path)
        elif path.is_dir():
            found.extend(sorted(path.rglob("*.yaml")))
            found.extend(sorted(path.rglob("*.yml")))
        else:
            found.append(path)
    return found
