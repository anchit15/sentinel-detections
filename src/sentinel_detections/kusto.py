"""Connect to the Kusto emulator and run rule queries scoped to one dataset."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoError
from dotenv import find_dotenv, load_dotenv

from sentinel_detections.normalise import DATASET_COLUMN, EVENT, SECURITY_EVENT

READY_POLL_SECONDS = 3
SAMPLE_VALUE_LENGTH = 200


@dataclass(frozen=True)
class Config:
    """Emulator connection settings, read from environment variables."""

    cluster_url: str
    database: str
    container_data_dir: str

    @classmethod
    def from_env(cls) -> Config:
        """Build the config; defaults match docker-compose.yml and .env.example."""
        return cls(
            cluster_url=os.environ.get("KUSTO_CLUSTER_URL", "http://localhost:8080"),
            database=os.environ.get("KUSTO_DATABASE", "NetDefaultDB"),
            container_data_dir=os.environ.get("KUSTO_DATA_DIR", "/kustodata"),
        )


def load_config() -> Config:
    """Read ``.env`` from the working directory upwards, then build the config.

    Variables already set in the environment take precedence over ``.env``.
    """
    load_dotenv(find_dotenv(usecwd=True))
    return Config.from_env()


def connect(config: Config) -> KustoClient:
    """Return a client for the emulator, which has no authentication."""
    return KustoClient(KustoConnectionStringBuilder.with_no_authentication(config.cluster_url))


def wait_until_ready(client: KustoClient, database: str, timeout: float) -> None:
    """Poll the emulator until it answers management commands or the timeout passes."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            client.execute_mgmt(database, ".show version")
            return
        except (KustoError, OSError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Kusto emulator not reachable: {error}") from error
            time.sleep(READY_POLL_SECONDS)


def scoped_query(query: str, dataset_id: str) -> str:
    """Prefix ``query`` so it only sees one dataset, without changing the query text.

    The prefix shadows both tables with a filtered copy and removes the Dataset column,
    so a query that refers to Dataset fails to compile instead of filtering on it.
    """
    filters = "".join(
        f'let {table} = {table} | where {DATASET_COLUMN} == "{dataset_id}" '
        f"| project-away {DATASET_COLUMN};\n"
        for table in (SECURITY_EVENT, EVENT)
    )
    return f"{filters}{query.rstrip()}\n"


def count_hits(client: KustoClient, database: str, query: str, dataset_id: str) -> int:
    """Return the number of rows ``query`` produces on one dataset."""
    response = client.execute_query(database, scoped_query(query, dataset_id) + "| count")
    return int(response.primary_results[0][0]["Count"])


def sample_rows(
    client: KustoClient, database: str, query: str, dataset_id: str, limit: int
) -> list[dict[str, str]]:
    """Return up to ``limit`` result rows, with long values shortened for display."""
    response = client.execute_query(database, scoped_query(query, dataset_id) + f"| take {limit}")
    return [
        {name: _shorten(value) for name, value in row.to_dict().items()}
        for row in response.primary_results[0]
    ]


def trigger_fires(hits: int, operator: str, threshold: int) -> bool:
    """Whether Sentinel would raise an alert for ``hits`` result rows."""
    comparisons = {
        "gt": hits > threshold,
        "lt": hits < threshold,
        "eq": hits == threshold,
        "ne": hits != threshold,
    }
    return comparisons[operator]


def _shorten(value: object) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= SAMPLE_VALUE_LENGTH else text[:SAMPLE_VALUE_LENGTH] + "..."
