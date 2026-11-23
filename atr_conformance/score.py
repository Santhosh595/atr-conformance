"""Score ATR rules against a labelled JSONL observation stream.

The stream is a local file, one JSON object per line, with a text field and a
label of \"attack\" or \"benign\". No network access and no model calls happen
here: a rule either matches the text or it does not. Rules whose operators
cannot be represented by this engine are reported as unsupported rather than
silently counted as non-matches.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .validate import FLAG_GROUP_RE
from .yaml_lite import YAMLError, parse

SUPPORTED_PATTERN_OPERATORS = {"regex", "contains", "equals", "matches"}


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, predicted: bool, attack: bool) -> None:
        if attack and predicted:
            self.tp += 1
        elif attack:
            self.fn += 1
        elif predicted:
            self.fp += 1
        else:
            self.tn += 1

    def as_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn, **metrics(self)}


def metrics(counts: Counts) -> dict:
    precision = counts.tp / (counts.tp + counts.fp) if counts.tp + counts.fp else None
    recall = counts.tp / (counts.tp + counts.fn) if counts.tp + counts.fn else None
    fpr = counts.fp / (counts.fp + counts.tn) if counts.fp + counts.tn else None
    return {"precision": precision, "recall": recall, "false_positive_rate": fpr}


def _regex_match(pattern: str, text: str) -> bool:
    flags = 0
    match = FLAG_GROUP_RE.match(pattern)
    if match:
        if "i" in match.group(1):
            flags = re.IGNORECASE
        pattern = pattern[match.end() :]
    return re.search(pattern, text, flags) is not None


def evaluate(rule: dict, text: str) -> tuple[bool | None, str | None]:
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return None, "detection is not a mapping"
    conditions = detection.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        return None, "no detection conditions"
    combinator = detection.get("condition", "any")
    if combinator not in ("any", "all"):
        return None, f"combinator {combinator!r} is not supported"
    results = []
    for condition in conditions:
        if not isinstance(condition, dict):
            return None, "invalid condition shape"
        operator = condition.get("operator")
        if {"field", "operator", "value"} <= condition.keys():
            if operator not in SUPPORTED_PATTERN_OPERATORS:
                return None, f"operator {operator!r} is not supported"
            value = condition["value"]
            if not isinstance(value, str):
                return None, f"operator {operator!r} needs a string value"
            if operator == "regex":
                try:
                    results.append(_regex_match(value, text))
                except re.error as exc:
                    return None, f"regex did not compile: {exc}"
            elif operator == "contains":
                results.append(value in text)
            elif operator == "equals":
                results.append(value == text)
            else:
                results.append(fnmatch.fnmatch(text, value))
        elif {"metric", "operator", "threshold"} <= condition.keys():
            return None, "behavioral conditions need runtime metrics, not text"
        else:
            return None, "invalid condition shape"
    return (any(results) if combinator == "any" else all(results)), None


@dataclass
class ScoreResult:
    rules_found: int = 0
    rules_evaluated: int = 0
    rules_unsupported: dict[str, str] = field(default_factory=dict)
    lines_read: int = 0
    observations_evaluated: int = 0
    lines_skipped: dict[str, int] = field(default_factory=dict)
    per_rule: dict[str, Counts] = field(default_factory=dict)
    overall: Counts = field(default_factory=Counts)

    def as_dict(self) -> dict:
        return {
            "rules_found": self.rules_found,
            "rules_evaluated": self.rules_evaluated,
            "rules_unsupported": self.rules_unsupported,
            "lines_read": self.lines_read,
            "observations_evaluated": self.observations_evaluated,
            "lines_skipped": self.lines_skipped,
            "per_rule": {
                rule_id: {"title": title, **counts.as_dict()}
                for rule_id, (title, counts) in self.per_rule.items()
            },
            "overall": self.overall.as_dict(),
        }


def _load_rules(directory: Path, rule_filter: str | None, result: ScoreResult) -> list[tuple[str, dict]]:
    rules = []
    for path in sorted(directory.rglob("*.yaml")):
        result.rules_found += 1
        try:
            rule = parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, YAMLError) as exc:
            result.rules_unsupported[path.name] = f"unreadable: {exc}"
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str):
            result.rules_unsupported[path.name] = "no rule id"
            continue
        if rule_filter and rule_filter not in rule_id:
            continue
        if rule_id in result.per_rule:
            result.rules_unsupported[rule_id] = "duplicate rule id"
            continue
        result.per_rule[rule_id] = (str(rule.get("title", "")), Counts())
        rules.append((rule_id, rule))
    result.rules_evaluated = len(rules)
    return rules


def score(rules_dir: Path, stream: Path, rule_filter: str | None = None,
          text_field: str = "text", label_field: str = "label") -> ScoreResult:
    result = ScoreResult()
    rules = _load_rules(rules_dir, rule_filter, result)
    with stream.open(encoding="utf-8") as handle:
        for line in handle:
            result.lines_read += 1
            if not line.strip():
                continue
            try:
                observation = json.loads(line)
            except json.JSONDecodeError:
                result.lines_skipped["invalid_json"] = result.lines_skipped.get("invalid_json", 0) + 1
                continue
            if not isinstance(observation, dict):
                result.lines_skipped["not_an_object"] = result.lines_skipped.get("not_an_object", 0) + 1
                continue
            label = str(observation.get(label_field, "")).lower()
            if label not in ("attack", "benign"):
                result.lines_skipped["unlabelled"] = result.lines_skipped.get("unlabelled", 0) + 1
                continue
            text = observation.get(text_field)
            if not isinstance(text, str):
                result.lines_skipped["no_text"] = result.lines_skipped.get("no_text", 0) + 1
                continue
            result.observations_evaluated += 1
            for rule_id, rule in rules:
                predicted, reason = evaluate(rule, text)
                if predicted is None:
                    result.rules_unsupported.setdefault(rule_id, reason or "unsupported")
                    continue
                counts = result.per_rule[rule_id][1]
                counts.add(predicted, label == "attack")
                result.overall.add(predicted, label == "attack")
    for rule_id in result.rules_unsupported:
        if rule_id in result.per_rule:
            del result.per_rule[rule_id]
            result.rules_evaluated -= 1
    return result
