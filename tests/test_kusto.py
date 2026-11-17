"""Unit tests for emulator configuration and query scoping; no emulator needed."""

import pytest

from sentinel_detections.kusto import Config, load_config, scoped_query, trigger_fires

ENV_VARS = ("KUSTO_CLUSTER_URL", "KUSTO_DATABASE", "KUSTO_DATA_DIR")


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """No Kusto variables in the environment, working in an empty directory."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_config_defaults(clean_env):
    assert Config.from_env() == Config("http://localhost:8080", "NetDefaultDB", "/kustodata")


def test_load_config_reads_dotenv_from_the_working_directory(clean_env):
    (clean_env / ".env").write_text(
        "KUSTO_CLUSTER_URL=http://localhost:8081\nKUSTO_DATA_DIR=/data\n", encoding="utf-8"
    )
    config = load_config()
    assert config.cluster_url == "http://localhost:8081"
    assert config.container_data_dir == "/data"
    assert config.database == "NetDefaultDB"


def test_environment_variables_take_precedence_over_dotenv(clean_env, monkeypatch):
    (clean_env / ".env").write_text("KUSTO_CLUSTER_URL=http://localhost:8081\n", encoding="utf-8")
    monkeypatch.setenv("KUSTO_CLUSTER_URL", "http://localhost:9000")
    assert load_config().cluster_url == "http://localhost:9000"


def test_scoped_query_filters_both_tables_and_hides_the_dataset_column():
    query = "Event\n| where EventID == 10\n\n"
    assert scoped_query(query, "empire_dcsync") == (
        'let SecurityEvent = SecurityEvent | where Dataset == "empire_dcsync" '
        "| project-away Dataset;\n"
        'let Event = Event | where Dataset == "empire_dcsync" | project-away Dataset;\n'
        "Event\n| where EventID == 10\n"
    )


@pytest.mark.parametrize(
    ("hits", "operator", "threshold", "fires"),
    [
        (1, "gt", 0, True),
        (0, "gt", 0, False),
        (2, "lt", 3, True),
        (3, "eq", 3, True),
        (3, "ne", 3, False),
    ],
)
def test_trigger_fires(hits, operator, threshold, fires):
    assert trigger_fires(hits, operator, threshold) is fires
