"""Write build/sentinel_rules.json: an ARM template of every rule for Sentinel to import."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel_detections.arm import build_template
from sentinel_detections.rules import RuleFileError, load_rules, rule_set_errors

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    """Validate every rule and write the ARM template."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "build" / "sentinel_rules.json")
    args = parser.parse_args()

    try:
        rules = load_rules(REPO_ROOT / "rules")
    except RuleFileError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    problems = rule_set_errors(rules)
    if problems:
        print("Fix these before exporting:", *problems, sep="\n  ", file=sys.stderr)
        return 1

    try:
        template = build_template(rules)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {len(template['resources'])} rules to {output.relative_to(REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
