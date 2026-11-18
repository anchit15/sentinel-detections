"""Run a KQL query against the Kusto emulator and print the result as a table.

The query comes from a file, or from stdin when no file (or ``-``) is given:

    python scripts/kql.py query.kql --limit 20
    "Event | take 5" | python scripts/kql.py

Exploration queries run as written: they may filter on the emulator-only Dataset
column, and none of the rule checks apply.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from azure.kusto.data.exceptions import KustoError

from sentinel_detections.kusto import connect, load_config


def positive_int(value: str) -> int:
    """argparse type for an integer of at least 1."""
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {number}")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run a KQL query against the Kusto emulator and print the result."
    )
    parser.add_argument(
        "query_file",
        nargs="?",
        default="-",
        help="file containing the query; omit or use - to read stdin",
    )
    parser.add_argument(
        "--limit", type=positive_int, default=50, help="maximum rows to print (default 50)"
    )
    parser.add_argument(
        "--width",
        type=positive_int,
        default=60,
        help="maximum characters shown per cell (default 60)",
    )
    return parser.parse_args(argv)


def read_query(query_file: str, stdin: TextIO) -> str:
    """Return the query text from ``query_file``, or from ``stdin`` for ``-``."""
    text = stdin.read() if query_file == "-" else Path(query_file).read_text(encoding="utf-8")
    query = text.strip().rstrip(";").rstrip()
    if not query:
        raise ValueError("the query is empty")
    return query


def cell(value: object, width: int) -> str:
    """Render one value on a single line, shortened to ``width`` characters."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\t", " ")
    return text if len(text) <= width else text[: max(width - 3, 0)] + "..."


def format_table(columns: list[str], rows: list[list[str]]) -> str:
    """Lay out ``rows`` under ``columns`` with each column padded to its widest cell."""
    widths = [max([len(name)] + [len(row[i]) for row in rows]) for i, name in enumerate(columns)]

    def line(values: list[str]) -> str:
        cells = (value.ljust(width) for value, width in zip(values, widths, strict=True))
        return "  ".join(cells).rstrip()

    return "\n".join(
        [line(columns), line(["-" * width for width in widths])] + [line(row) for row in rows]
    )


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    args = parse_args(argv)
    try:
        query = read_query(args.query_file, sys.stdin)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    config = load_config()
    try:
        with connect(config) as client:
            total = client.execute_query(config.database, f"{query}\n| count")
            total_rows = int(total.primary_results[0][0]["Count"])
            result = client.execute_query(config.database, f"{query}\n| take {args.limit}")
    except (KustoError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    table = result.primary_results[0]
    columns = [column.column_name for column in table.columns]
    rows = [[cell(value, args.width) for value in row] for row in table]
    print(format_table(columns, rows))
    noun = "row" if total_rows == 1 else "rows"
    shown = f" (showing {len(rows)})" if len(rows) < total_rows else ""
    print(f"\n{total_rows} {noun}{shown}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
