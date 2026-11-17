"""Download manifest datasets and verify their SHA-256 hashes."""

from __future__ import annotations

import hashlib
import shutil
import urllib.request
from pathlib import Path

from sentinel_detections.manifest import Dataset

CHUNK_SIZE = 1024 * 1024
TIMEOUT_SECONDS = 60


class ChecksumError(RuntimeError):
    """Raised when a downloaded file does not match its pinned SHA-256."""


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of the file at ``path``."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_dataset(dataset: Dataset, raw_dir: Path) -> bool:
    """Ensure ``dataset`` is in ``raw_dir`` with the pinned hash.

    Returns True if the file was downloaded, False if a verified copy already existed.
    Raises ChecksumError, leaving no file behind, if the download does not match.
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    target = raw_dir / dataset.filename
    if target.exists() and sha256_file(target) == dataset.sha256:
        return False

    # Write to a temporary name first so an interrupted or bad download never
    # looks like a valid dataset.
    partial = target.with_suffix(target.suffix + ".part")
    try:
        with urllib.request.urlopen(dataset.url, timeout=TIMEOUT_SECONDS) as response:
            with partial.open("wb") as handle:
                shutil.copyfileobj(response, handle, CHUNK_SIZE)
        actual = sha256_file(partial)
        if actual != dataset.sha256:
            raise ChecksumError(f"{dataset.id}: expected sha256 {dataset.sha256}, got {actual}")
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)
    return True
