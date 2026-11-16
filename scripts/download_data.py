"""Download every dataset in the manifest into data/raw/, verifying SHA-256 hashes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel_detections.download import ChecksumError, download_dataset
from sentinel_detections.manifest import load_manifest


def main() -> int:
    """Download all datasets; return a non-zero exit code if any fail."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()

    datasets = load_manifest(args.data_dir / "manifest.yaml")
    raw_dir = args.data_dir / "raw"
    failures = 0
    for dataset in datasets:
        try:
            downloaded = download_dataset(dataset, raw_dir)
        except (ChecksumError, OSError) as error:
            failures += 1
            print(f"FAILED  {dataset.id}: {error}", file=sys.stderr)
            continue
        print(f"{'fetched' if downloaded else 'cached '} {dataset.id}")

    print(f"{len(datasets) - failures}/{len(datasets)} datasets ready in {raw_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
