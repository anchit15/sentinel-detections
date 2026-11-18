"""Write docs/coverage.json: an ATT&CK Navigator layer built from the rule files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel_detections.layer import build_layer
from sentinel_detections.rules import RuleFileError, load_rules, rule_set_errors

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    """Validate every rule and write the Navigator layer."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "docs" / "coverage.json")
    args = parser.parse_args()

    try:
        rules = load_rules(REPO_ROOT / "rules")
    except RuleFileError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    problems = rule_set_errors(rules)
    if problems:
        print("Fix these before building the layer:", *problems, sep="\n  ", file=sys.stderr)
        return 1

    layer = build_layer(rules, REPO_ROOT)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(
        f"Wrote {len(layer['techniques'])} techniques from {len(rules)} rules "
        f"to {output.relative_to(REPO_ROOT).as_posix()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
