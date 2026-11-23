"""Command-line interface for atr-conformance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .score import score
from .validate import rule_files, validate_rule


def _percent(value: float | None) -> str:
    return "not available" if value is None else f"{value:.1%}"


def _print_findings(findings, files: list[Path]) -> None:
    errors = sum(item.severity == "error" for item in findings)
    warnings = len(findings) - errors
    print(f"files: {len(files)}  errors: {errors}  warnings: {warnings}")
    for item in findings:
        location = f"{item.path}:{item.line}" if item.line else item.path
        print(f"{item.severity:7} {item.code:24} {location}  {item.message}")
    if not findings:
        print("no findings")


def _print_score(result) -> None:
    print(f"rules found: {result.rules_found}  evaluated: {result.rules_evaluated}")
    print(f"lines read: {result.lines_read}  evaluated: {result.observations_evaluated}")
    if result.rules_unsupported:
        print(f"unsupported rules: {len(result.rules_unsupported)}")
    if result.lines_skipped:
        print(f"skipped lines: {result.lines_skipped}")
    if not result.per_rule:
        print("no rule could be scored; metrics are not available")
        return
    print()
    print(f"{'rule':<20} {'tp':>5} {'fp':>5} {'fn':>5} {'tn':>5} {'precision':>14} {'recall':>14} {'fpr':>14}")
    for rule_id, (_, counts) in sorted(result.per_rule.items()):
        print(
            f"{rule_id:<20} {counts.tp:>5} {counts.fp:>5} {counts.fn:>5} {counts.tn:>5} "
            f"{_percent(counts.as_dict()['precision']):>14} "
            f"{_percent(counts.as_dict()['recall']):>14} "
            f"{_percent(counts.as_dict()['false_positive_rate']):>14}"
        )
    overall = result.overall.as_dict()
    print()
    print("overall (per rule/observation pair):")
    print(f"  tp={overall['tp']} fp={overall['fp']} fn={overall['fn']} tn={overall['tn']}")
    print(f"  precision={_percent(overall['precision'])}")
    print(f"  recall={_percent(overall['recall'])}")
    print(f"  false_positive_rate={_percent(overall['false_positive_rate'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atr-conformance", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="check ATR rule files against the spec")
    validate.add_argument("paths", nargs="+", type=Path, help="rule files or directories")
    validate.add_argument("--json", action="store_true", help="emit a JSON report")
    validate.add_argument("--warnings-as-errors", action="store_true")

    measure = commands.add_parser("score", help="score rules against a labelled JSONL stream")
    measure.add_argument("--rules", required=True, type=Path, help="directory of ATR rule YAML files")
    measure.add_argument("--stream", required=True, type=Path, help="labelled JSONL observations")
    measure.add_argument("--rule", help="only score rule IDs containing this text")
    measure.add_argument("--text-field", default="text")
    measure.add_argument("--label-field", default="label")
    measure.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            files = rule_files(args.paths)
            findings = [item for path in files for item in validate_rule(path)]
            if args.json:
                print(json.dumps([item.as_dict() for item in findings], indent=2))
            else:
                _print_findings(findings, files)
            errors = sum(item.severity == "error" for item in findings)
            if args.warnings_as_errors:
                errors += len(findings) - sum(item.severity == "error" for item in findings)
            return 1 if errors else 0

        if not args.rules.is_dir():
            raise ValueError(f"not a rules directory: {args.rules}")
        if not args.stream.is_file():
            raise ValueError(f"not a stream file: {args.stream}")
        result = score(args.rules, args.stream, args.rule, args.text_field, args.label_field)
        if args.json:
            print(json.dumps(result.as_dict(), indent=2))
        else:
            _print_score(result)
        return 0
    except (OSError, ValueError) as exc:
        print(f"atr-conformance: {exc}", file=sys.stderr)
        return 2
