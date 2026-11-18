"""Shared fixtures: the dataset manifest and the Kusto emulator."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from typing import NoReturn

import pytest
from azure.kusto.data import KustoClient
from azure.kusto.data.exceptions import KustoError

from paths import MANIFEST
from sentinel_detections.kusto import connect, load_config
from sentinel_detections.manifest import Dataset, load_manifest


@dataclass(frozen=True)
class KustoSession:
    """A connected client and the database that holds the loaded tables."""

    client: KustoClient
    database: str


@pytest.fixture(scope="session")
def datasets() -> list[Dataset]:
    """Every dataset in the manifest."""
    return load_manifest(MANIFEST)


@pytest.fixture(scope="session")
def kusto(datasets: list[Dataset]) -> Iterator[KustoSession]:
    """A session against the emulator, with every manifest dataset loaded.

    Skips dependent tests when the emulator or data is missing, or fails them when
    KUSTO_REQUIRED=1 so CI cannot pass by skipping.
    """
    config = load_config()
    client = connect(config)
    try:
        response = client.execute_query(
            config.database, "union SecurityEvent, Event | distinct Dataset"
        )
        loaded = {row["Dataset"] for row in response.primary_results[0]}
    except (KustoError, OSError) as error:
        client.close()
        _unavailable(f"Kusto emulator or tables not available at {config.cluster_url}: {error}")
    missing = sorted({dataset.id for dataset in datasets} - loaded)
    if missing:
        client.close()
        _unavailable(f"datasets not loaded: {missing}; run python -m sentinel_detections.loader")
    yield KustoSession(client, config.database)
    client.close()


def _unavailable(message: str) -> NoReturn:
    if os.environ.get("KUSTO_REQUIRED") == "1":
        pytest.fail(message)
    pytest.skip(message)
