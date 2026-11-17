"""Tests for dataset classification, pass/fail checks and the deliberately broken rules."""

import pytest
from azure.kusto.data.exceptions import KustoServiceError

from paths import FIXTURES_DIR
from sentinel_detections.harness import (
    DatasetHits,
    Evaluation,
    evaluate,
    format_false_positives,
    rule_failures,
)
from sentinel_detections.kusto import count_hits
from sentinel_detections.rules import classify_datasets, load_rule, load_test_case

BROKEN_RULE = load_rule(FIXTURES_DIR / "rules" / "broken.yaml")
BROKEN_CASE = load_test_case(FIXTURES_DIR / "cases" / "broken.yaml")


def evaluation(attack_hits=3, false_positives=()):
    return Evaluation(
        attack=DatasetHits("empire_mimikatz_logonpasswords", attack_hits),
        cross_hits=(DatasetHits("empire_over_pth", 2),),
        false_positives=tuple(false_positives),
    )


def test_datasets_sharing_a_technique_are_cross_hits_not_benign(datasets):
    cross, benign = classify_datasets(BROKEN_RULE, "empire_mimikatz_logonpasswords", datasets)
    assert sorted(cross) == ["empire_over_pth", "psh_lsass_dump_comsvcs"]
    assert len(benign) == len(datasets) - 3
    assert "empire_mimikatz_logonpasswords" not in cross + benign


def test_passing_evaluation_has_no_failures():
    assert rule_failures(evaluation(), BROKEN_RULE, BROKEN_CASE) == []


def test_too_few_attack_hits_fail():
    failures = rule_failures(evaluation(attack_hits=0), BROKEN_RULE, BROKEN_CASE)
    assert failures[0] == (
        "attack dataset empire_mimikatz_logonpasswords: 0 hits, expected at least 1"
    )
    assert "would not trigger an alert" in failures[1]


def test_attack_hits_below_the_trigger_threshold_fail():
    rule = load_rule(FIXTURES_DIR / "rules" / "broken.yaml")
    rule.data["triggerThreshold"] = 5
    failures = rule_failures(evaluation(attack_hits=3), rule, BROKEN_CASE)
    assert failures == [
        "attack dataset empire_mimikatz_logonpasswords: 3 hits would not trigger an alert "
        "(triggerOperator gt, triggerThreshold 5)"
    ]


def test_false_positive_failure_names_dataset_count_and_samples():
    samples = tuple({"Computer": f"host{n}", "Image": "svchost.exe"} for n in range(5))
    noisy = DatasetHits("empire_dcsync", 12, samples)
    quiet = DatasetHits("schtask_create", 0)
    failures = rule_failures(evaluation(false_positives=[noisy, quiet]), BROKEN_RULE, BROKEN_CASE)
    assert failures == [format_false_positives(noisy)]
    lines = failures[0].splitlines()
    assert lines[0] == "false positives in empire_dcsync: 12 hits (showing 5 sample rows)"
    assert lines[1] == "  1. Computer=host0, Image=svchost.exe"
    assert len(lines) == 6


@pytest.mark.emulator
def test_broken_rule_fails_the_harness(kusto, datasets):
    result = evaluate(
        kusto.client,
        kusto.database,
        BROKEN_RULE.query,
        BROKEN_RULE,
        BROKEN_CASE.attack_dataset,
        datasets,
    )
    failures = rule_failures(result, BROKEN_RULE, BROKEN_CASE)
    assert "0 hits, expected at least 1" in failures[0]


@pytest.mark.emulator
def test_query_reading_dataset_cannot_compile_against_scoped_tables(kusto):
    rule = load_rule(FIXTURES_DIR / "rules" / "uses_dataset.yaml")
    with pytest.raises(KustoServiceError, match="Dataset"):
        count_hits(kusto.client, kusto.database, rule.query, "empire_mimikatz_logonpasswords")
