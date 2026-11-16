from pathlib import Path

import pytest

from sentinel_detections.manifest import ManifestError, load_manifest, parse_manifest

MANIFEST = Path(__file__).parents[1] / "data" / "manifest.yaml"

VALID_ENTRY = {
    "id": "empire_dcsync",
    "source": "OTRF Security-Datasets",
    "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
    "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/x.zip",
    "sha256": "a" * 64,
    "licence": "MIT",
    "primary_technique": "T1003.006",
    "techniques": ["T1003.006"],
}


def entry(**changes):
    result = {**VALID_ENTRY, **changes}
    return {key: value for key, value in result.items() if value is not None}


def test_repository_manifest_has_one_attack_dataset_per_planned_technique():
    datasets = load_manifest(MANIFEST)
    primaries = [dataset.primary_technique for dataset in datasets]
    assert len(datasets) == 12
    assert len(set(primaries)) == 12


def test_valid_entry_parses():
    (dataset,) = parse_manifest({"datasets": [entry(notes="extra context")]})
    assert dataset.techniques == ("T1003.006",)
    assert dataset.filename == "empire_dcsync.zip"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"sha256": None}, "missing fields"),
        ({"maintainer": "someone"}, "unknown fields"),
        ({"id": "Empire-DCSync"}, "id must be"),
        (
            {"url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/x.zip"},
            "pinned",
        ),
        ({"url": "http://example.com/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/x.zip"}, "https"),
        ({"sha256": "abc"}, "sha256"),
        ({"techniques": []}, "non-empty"),
        ({"techniques": ["T1003.006", "T1003.006"]}, "duplicates"),
        ({"techniques": ["T1003.6"]}, "invalid ATT&CK"),
        ({"primary_technique": "T1059.001"}, "primary_technique"),
    ],
)
def test_invalid_entries_are_rejected(changes, message):
    with pytest.raises(ManifestError, match=message):
        parse_manifest({"datasets": [entry(**changes)]})


def test_duplicate_ids_are_rejected():
    with pytest.raises(ManifestError, match="Duplicate"):
        parse_manifest({"datasets": [entry(), entry()]})


@pytest.mark.parametrize("document", [None, {}, {"datasets": "x"}])
def test_document_must_contain_a_datasets_list(document):
    with pytest.raises(ManifestError, match="datasets"):
        parse_manifest(document)
