"""Normalise downloaded datasets and load them into the Kusto emulator.

Run with ``python -m sentinel_detections.loader`` after ``docker compose up -d`` and
``python scripts/download_data.py``. Tables are dropped and recreated on every run.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from azure.kusto.data import KustoClient

from sentinel_detections.download import sha256_file
from sentinel_detections.kusto import Config, connect, load_config, wait_until_ready
from sentinel_detections.manifest import Dataset, load_manifest
from sentinel_detections.normalise import (
    EVENT,
    SECURITY_EVENT,
    NormalisationError,
    TableSchema,
    load_schema,
    naive_time_offset,
    normalise,
)

TABLES = (SECURITY_EVENT, EVENT)
READY_TIMEOUT_SECONDS = 180


@dataclass
class DatasetReport:
    """What happened to one dataset's records during normalisation."""

    dataset_id: str
    rows: Counter[str] = field(default_factory=Counter)
    dropped_by_channel: Counter[str] = field(default_factory=Counter)
    dropped_by_normalisation: Counter[str] = field(default_factory=Counter)


def read_records(archive: Path) -> Iterator[dict | None]:
    """Yield each JSON-lines record in the archive; None for a line that is not valid JSON."""
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.namelist():
            with bundle.open(member) as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        yield None
                        continue
                    yield record if isinstance(record, dict) else None


def csv_cell(value: object) -> object:
    """Render a row value for Kusto CSV; an empty cell is ingested as null."""
    return "" if value is None else value


def normalise_dataset(archive: Path, dataset_id: str, out_dir: Path) -> DatasetReport:
    """Normalise one archive into a gzipped CSV file per table, with no header row."""
    out_dir.mkdir(parents=True, exist_ok=True)
    report = DatasetReport(dataset_id)
    schemas = {table: load_schema(table) for table in TABLES}
    naive_offset = naive_time_offset(record for record in read_records(archive) if record)
    files = {
        table: gzip.open(
            normalised_path(out_dir, dataset_id, table), "wt", encoding="utf-8", newline=""
        )
        for table in TABLES
    }
    try:
        writers = {
            table: csv.writer(handle, lineterminator="\n") for table, handle in files.items()
        }
        for record in read_records(archive):
            if record is None:
                report.dropped_by_normalisation["invalid JSON"] += 1
                continue
            try:
                row = normalise(record, dataset_id, naive_offset)
            except NormalisationError as error:
                report.dropped_by_normalisation[error.reason] += 1
                continue
            if row is None:
                report.dropped_by_channel[str(record.get("Channel", "<none>"))] += 1
                continue
            columns = schemas[row.table].output_columns
            writers[row.table].writerow([csv_cell(row.values.get(name)) for name, _ in columns])
            report.rows[row.table] += 1
    finally:
        for handle in files.values():
            handle.close()
    return report


def normalised_path(out_dir: Path, dataset_id: str, table: str) -> Path:
    """Host path of the normalised CSV for one dataset and table."""
    return out_dir / f"{dataset_id}.{table}.csv.gz"


def create_table_command(schema: TableSchema) -> str:
    """Build the ``.create table`` command, including the Dataset tag column."""
    columns = ", ".join(f"['{name}']:{kusto_type}" for name, kusto_type in schema.output_columns)
    return f".create table {schema.table} ({columns})"


def ingest_command(table: str, container_path: PurePosixPath) -> str:
    """Build the command that ingests a CSV file the emulator can read from its mount."""
    return f".ingest into table {table} (@'{container_path}') with (format='csv')"


def counts_by_dataset(client: KustoClient, database: str, table: str) -> dict[str, int]:
    """Return the number of rows per Dataset tag in ``table``."""
    response = client.execute_query(database, f"{table} | summarize Rows = count() by Dataset")
    return {row["Dataset"]: row["Rows"] for row in response.primary_results[0]}


def _report_line(
    label: str,
    security_rows: object,
    event_rows: object,
    by_channel: object,
    by_normalisation: object,
) -> str:
    return f"{label:32} {security_rows:>13} {event_rows:>8} {by_channel:>18} {by_normalisation:>24}"


def format_report(reports: list[DatasetReport], loaded: dict[str, dict[str, int]]) -> str:
    """Render row counts per dataset and table, plus dropped records and their reasons."""
    header = _report_line(
        "dataset", SECURITY_EVENT, EVENT, "dropped (channel)", "dropped (normalisation)"
    )
    lines = [header, "-" * len(header)]
    for report in reports:
        lines.append(
            _report_line(
                report.dataset_id,
                loaded[SECURITY_EVENT].get(report.dataset_id, 0),
                loaded[EVENT].get(report.dataset_id, 0),
                sum(report.dropped_by_channel.values()),
                sum(report.dropped_by_normalisation.values()),
            )
        )
    channel_totals = sum((report.dropped_by_channel for report in reports), Counter())
    reason_totals = sum((report.dropped_by_normalisation for report in reports), Counter())
    lines.append("-" * len(header))
    lines.append(
        _report_line(
            "total",
            sum(loaded[SECURITY_EVENT].values()),
            sum(loaded[EVENT].values()),
            sum(channel_totals.values()),
            sum(reason_totals.values()),
        )
    )
    lines.append("")
    lines.append("Dropped by channel (not loaded into either table):")
    lines.extend(f"  {count:>7}  {channel}" for channel, count in channel_totals.most_common())
    lines.append("Dropped by normalisation:")
    if reason_totals:
        lines.extend(f"  {count:>7}  {reason}" for reason, count in reason_totals.most_common())
    else:
        lines.append("        0")
    return "\n".join(lines)


def load(datasets: list[Dataset], data_dir: Path, config: Config) -> int:
    """Normalise and ingest every dataset, print the report, and return an exit code."""
    raw_dir = data_dir / "raw"
    out_dir = data_dir / "normalised"
    for dataset in datasets:
        archive = raw_dir / dataset.filename
        if not archive.exists() or sha256_file(archive) != dataset.sha256:
            print(f"{archive} missing or changed; run scripts/download_data.py", file=sys.stderr)
            return 1

    with connect(config) as client:
        wait_until_ready(client, config.database, READY_TIMEOUT_SECONDS)
        for table in TABLES:
            client.execute_mgmt(config.database, f".drop table {table} ifexists")
            client.execute_mgmt(config.database, create_table_command(load_schema(table)))

        reports = []
        for dataset in datasets:
            report = normalise_dataset(raw_dir / dataset.filename, dataset.id, out_dir)
            reports.append(report)
            for table in TABLES:
                if report.rows[table]:
                    host_path = normalised_path(out_dir, dataset.id, table)
                    relative = host_path.relative_to(data_dir).as_posix()
                    container_path = PurePosixPath(config.container_data_dir) / relative
                    client.execute_mgmt(config.database, ingest_command(table, container_path))

        loaded = {table: counts_by_dataset(client, config.database, table) for table in TABLES}

    print(format_report(reports, loaded))
    mismatches = []
    for report in reports:
        for table in TABLES:
            written = report.rows[table]
            ingested = loaded[table].get(report.dataset_id, 0)
            if written != ingested:
                mismatches.append(
                    f"{report.dataset_id}/{table}: wrote {written}, loaded {ingested}"
                )
    if mismatches:
        print("\nRow count mismatch between normalised files and tables:", file=sys.stderr)
        print("\n".join(f"  {line}" for line in mismatches), file=sys.stderr)
        return 1
    return 0


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()
    datasets = load_manifest(args.data_dir / "manifest.yaml")
    return load(datasets, args.data_dir, load_config())


if __name__ == "__main__":
    sys.exit(main())
