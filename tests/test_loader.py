import csv
import gzip
import json
import zipfile
from pathlib import PurePosixPath

from sentinel_detections.loader import (
    Config,
    create_table_command,
    ingest_command,
    normalise_dataset,
    normalised_path,
)
from sentinel_detections.normalise import EVENT, SECURITY_EVENT, load_schema

SECURITY = {
    "@timestamp": "2020-09-21T22:58:30.648Z",
    "Channel": "Security",
    "Hostname": "WORKSTATION5",
    "EventID": 4720,
    "TargetUserName": "backdoor",
}
SYSMON = {
    "@timestamp": "2020-09-21T22:58:31.000Z",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Hostname": "WORKSTATION5",
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\rundll32.exe",
}


def write_archive(path, lines):
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("events.json", "\n".join(lines) + "\n")


def read_csv(path):
    with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
        return list(csv.reader(handle))


def test_normalise_dataset_writes_rows_and_counts_every_dropped_record(tmp_path):
    archive = tmp_path / "sample.zip"
    write_archive(
        archive,
        [
            json.dumps(SECURITY),
            json.dumps(SYSMON),
            json.dumps({**SYSMON, "Channel": "Windows PowerShell"}),
            "{not json",
            json.dumps({**SECURITY, "EventID": None}),
            "",
        ],
    )
    report = normalise_dataset(archive, "sample", tmp_path / "out")

    assert report.rows == {SECURITY_EVENT: 1, EVENT: 1}
    assert report.dropped_by_channel == {"Windows PowerShell": 1}
    assert report.dropped_by_normalisation == {"invalid JSON": 1, "missing EventID": 1}

    for table in (SECURITY_EVENT, EVENT):
        (row,) = read_csv(normalised_path(tmp_path / "out", "sample", table))
        assert len(row) == len(load_schema(table).output_columns)
        assert row[-1] == "sample"


def test_create_table_command_includes_every_column_and_the_dataset_tag():
    schema = load_schema(EVENT)
    command = create_table_command(schema)
    assert command.startswith(".create table Event (")
    assert command.count(":") == len(schema.columns) + 1
    assert command.endswith("['Dataset']:string)")


def test_ingest_command_reads_from_the_container_path():
    command = ingest_command(SECURITY_EVENT, PurePosixPath("/kustodata/normalised/a.csv.gz"))
    assert command == (
        ".ingest into table SecurityEvent (@'/kustodata/normalised/a.csv.gz') with (format='csv')"
    )


def test_config_defaults_and_environment_overrides(monkeypatch):
    for name in ("KUSTO_CLUSTER_URL", "KUSTO_DATABASE", "KUSTO_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    assert Config.from_env() == Config("http://localhost:8080", "NetDefaultDB", "/kustodata")

    monkeypatch.setenv("KUSTO_CLUSTER_URL", "http://localhost:8081")
    monkeypatch.setenv("KUSTO_DATA_DIR", "/data")
    config = Config.from_env()
    assert config.cluster_url == "http://localhost:8081"
    assert config.container_data_dir == "/data"
