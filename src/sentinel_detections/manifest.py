"""Load and validate the dataset manifest (data/manifest.yaml)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[a-z0-9_]+$")
# A 40-character commit SHA in the URL path keeps the download immutable.
PINNED_URL_PATTERN = re.compile(r"^https://\S+/[0-9a-f]{40}/\S+$")

REQUIRED_FIELDS = ("id", "source", "url", "sha256", "licence", "primary_technique", "techniques")
OPTIONAL_FIELDS = ("notes",)


class ManifestError(ValueError):
    """Raised when the manifest is missing fields or contains invalid values."""


@dataclass(frozen=True)
class Dataset:
    """One downloadable dataset and the ATT&CK techniques its logs contain."""

    id: str
    source: str
    url: str
    sha256: str
    licence: str
    primary_technique: str
    techniques: tuple[str, ...]
    notes: str = ""

    @property
    def filename(self) -> str:
        """Local file name for the downloaded archive."""
        return f"{self.id}.zip"


def parse_dataset(entry: dict) -> Dataset:
    """Validate one manifest entry and build a Dataset from it."""
    if not isinstance(entry, dict):
        raise ManifestError(f"Dataset entry must be a mapping, got {type(entry).__name__}")
    label = entry.get("id", "<missing id>")
    missing = [field for field in REQUIRED_FIELDS if field not in entry]
    if missing:
        raise ManifestError(f"{label}: missing fields {missing}")
    unknown = sorted(set(entry) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if unknown:
        raise ManifestError(f"{label}: unknown fields {unknown}")

    if not ID_PATTERN.match(str(entry["id"])):
        raise ManifestError(f"{label}: id must be lowercase letters, digits and underscores")
    if not PINNED_URL_PATTERN.match(str(entry["url"])):
        raise ManifestError(f"{label}: url must be https and pinned to a 40-character commit SHA")
    if not SHA256_PATTERN.match(str(entry["sha256"])):
        raise ManifestError(f"{label}: sha256 must be 64 lowercase hex characters")

    techniques = entry["techniques"]
    if not isinstance(techniques, list) or not techniques:
        raise ManifestError(f"{label}: techniques must be a non-empty list")
    for technique in [entry["primary_technique"], *techniques]:
        if not TECHNIQUE_PATTERN.match(str(technique)):
            raise ManifestError(f"{label}: invalid ATT&CK technique id {technique!r}")
    if len(set(techniques)) != len(techniques):
        raise ManifestError(f"{label}: techniques contains duplicates")
    if entry["primary_technique"] not in techniques:
        raise ManifestError(f"{label}: primary_technique must also appear in techniques")

    return Dataset(
        id=entry["id"],
        source=entry["source"],
        url=entry["url"],
        sha256=entry["sha256"],
        licence=entry["licence"],
        primary_technique=entry["primary_technique"],
        techniques=tuple(techniques),
        notes=entry.get("notes", ""),
    )


def parse_manifest(document: dict) -> list[Dataset]:
    """Validate a parsed manifest document and return its datasets."""
    if not isinstance(document, dict) or not isinstance(document.get("datasets"), list):
        raise ManifestError("Manifest must contain a 'datasets' list")
    datasets = [parse_dataset(entry) for entry in document["datasets"]]
    ids = [dataset.id for dataset in datasets]
    duplicates = sorted({dataset_id for dataset_id in ids if ids.count(dataset_id) > 1})
    if duplicates:
        raise ManifestError(f"Duplicate dataset ids: {duplicates}")
    return datasets


def load_manifest(path: Path) -> list[Dataset]:
    """Read and validate the manifest file at ``path``."""
    with path.open(encoding="utf-8") as handle:
        return parse_manifest(yaml.safe_load(handle))
