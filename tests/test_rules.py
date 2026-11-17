"""Checks run against every rule under rules/ and its test case under tests/cases/."""

import pytest

from paths import CASES_DIR, RULES_DIR
from sentinel_detections.harness import attack_failures, evaluate, rule_failures
from sentinel_detections.rules import case_errors, discover, pairing_errors, rule_errors

PAIRS = discover(RULES_DIR, CASES_DIR)


def pair_id(pair):
    return pair.rule.stem


def test_every_rule_has_exactly_one_test_case():
    errors = pairing_errors(RULES_DIR, CASES_DIR)
    assert not errors, "\n".join(errors)


@pytest.mark.parametrize("pair", PAIRS, ids=pair_id)
def test_rule_matches_sentinel_schema(pair):
    errors = rule_errors(pair.rule.data)
    assert not errors, f"{pair.rule.path}:\n" + "\n".join(errors)


@pytest.mark.parametrize("pair", PAIRS, ids=pair_id)
def test_test_case_is_valid(pair, datasets):
    errors = case_errors(pair.case.data, pair.rule, datasets)
    assert not errors, f"{pair.case.path}:\n" + "\n".join(errors)


@pytest.mark.emulator
@pytest.mark.parametrize("pair", PAIRS, ids=pair_id)
def test_rule_fires_on_attack_and_never_on_benign_datasets(pair, kusto, datasets):
    if rule_errors(pair.rule.data) or case_errors(pair.case.data, pair.rule, datasets):
        pytest.fail("rule or test case is invalid; see the schema tests")
    evaluation = evaluate(
        kusto.client, kusto.database, pair.rule.query, pair.rule, pair.case.attack_dataset, datasets
    )
    failures = rule_failures(evaluation, pair.rule, pair.case)
    assert not failures, f"{pair.rule.stem}:\n" + "\n".join(failures)


@pytest.mark.emulator
@pytest.mark.parametrize("pair", PAIRS, ids=pair_id)
def test_baseline_fires_on_attack(pair, kusto, datasets):
    evaluation = evaluate(
        kusto.client,
        kusto.database,
        pair.case.baseline_query,
        pair.rule,
        pair.case.attack_dataset,
        datasets,
    )
    failures = attack_failures(evaluation, pair.case)
    assert not failures, f"{pair.rule.stem} baseline:\n" + "\n".join(failures)
