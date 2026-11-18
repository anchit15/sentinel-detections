"""Write docs/results.md: attack hits, cross-hits and false positives for every rule.

Needs the Kusto emulator running with every dataset loaded.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath

from azure.kusto.data.exceptions import KustoError

from sentinel_detections.kusto import connect, load_config
from sentinel_detections.manifest import load_manifest
from sentinel_detections.report import build_rows, render_results
from sentinel_detections.rules import case_errors, discover, pairing_errors, rule_errors

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    """Validate every rule, evaluate it on the emulator and write the report."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "docs" / "results.md")
    args = parser.parse_args()

    datasets = load_manifest(REPO_ROOT / "data" / "manifest.yaml")
    rules_dir, cases_dir = REPO_ROOT / "rules", REPO_ROOT / "tests" / "cases"
    pairs = discover(rules_dir, cases_dir)
    problems = pairing_errors(rules_dir, cases_dir)
    for pair in pairs:
        problems += [f"{pair.rule.path}: {e}" for e in rule_errors(pair.rule.data)]
        problems += [
            f"{pair.case.path}: {e}" for e in case_errors(pair.case.data, pair.rule, datasets)
        ]
    if problems:
        print("Fix these before generating the report:", *problems, sep="\n  ", file=sys.stderr)
        return 1

    config = load_config()
    try:
        with connect(config) as client:
            rows = build_rows(client, config.database, pairs, datasets, REPO_ROOT)
    except (KustoError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    output = args.output.resolve()
    output_dir = PurePosixPath(output.parent.relative_to(REPO_ROOT).as_posix())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_results(rows, output_dir), encoding="utf-8", newline="\n")
    noun = "rule" if len(rows) == 1 else "rules"
    print(f"Wrote {len(rows)} {noun} to {output.relative_to(REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
