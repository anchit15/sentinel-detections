import hashlib

import pytest

from sentinel_detections.download import ChecksumError, download_dataset
from sentinel_detections.manifest import Dataset

CONTENT = b"zip bytes"


def make_dataset(tmp_path, sha256):
    """A dataset served from a local file, so the test needs no network."""
    source = tmp_path / "source.zip"
    source.write_bytes(CONTENT)
    return Dataset(
        id="sample",
        source="test",
        url=source.as_uri(),
        sha256=sha256,
        licence="MIT",
        primary_technique="T1003.001",
        techniques=("T1003.001",),
    )


def test_download_verifies_and_then_reuses_the_cached_file(tmp_path):
    dataset = make_dataset(tmp_path, hashlib.sha256(CONTENT).hexdigest())
    raw_dir = tmp_path / "raw"
    assert download_dataset(dataset, raw_dir) is True
    assert (raw_dir / "sample.zip").read_bytes() == CONTENT
    assert download_dataset(dataset, raw_dir) is False


def test_hash_mismatch_raises_and_leaves_no_file(tmp_path):
    dataset = make_dataset(tmp_path, "0" * 64)
    raw_dir = tmp_path / "raw"
    with pytest.raises(ChecksumError, match="expected sha256"):
        download_dataset(dataset, raw_dir)
    assert list(raw_dir.iterdir()) == []


def test_corrupted_local_copy_is_downloaded_again(tmp_path):
    dataset = make_dataset(tmp_path, hashlib.sha256(CONTENT).hexdigest())
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "sample.zip").write_bytes(b"tampered")
    assert download_dataset(dataset, raw_dir) is True
    assert (raw_dir / "sample.zip").read_bytes() == CONTENT
