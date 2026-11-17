"""Unit tests for rule and test-case validation; no emulator needed."""

import copy
from datetime import timedelta

import pytest

from paths import FIXTURES_DIR
from sentinel_detections.rules import (
    RuleFileError,
    case_errors,
    load_rule,
    load_yaml,
    pairing_errors,
    parse_time_span,
    rule_errors,
)

VALID_RULE = load_rule(FIXTURES_DIR / "rules" / "broken.yaml")
VALID_CASE = {
    "attack_dataset": "empire_mimikatz_logonpasswords",
    "min_hits": 1,
    "baseline_query": "Event | take 1",
}


def mutated(**changes):
    data = copy.deepcopy(VALID_RULE.data)
    for key, value in changes.items():
        if value is None:
            del data[key]
        else:
            data[key] = value
    return data


def host_mapping(identifier):
    return [
        {"entityType": "Host", "fieldMappings": [{"identifier": identifier, "columnName": "C"}]}
    ]


def test_fixture_rule_is_valid():
    assert rule_errors(VALID_RULE.data) == []


def test_unknown_field_is_rejected():
    rule = load_rule(FIXTURES_DIR / "rules" / "schema_invalid.yaml")
    errors = rule_errors(rule.data)
    assert any("'status' was unexpected" in error for error in errors), errors


def test_query_reading_the_dataset_column_is_rejected():
    rule = load_rule(FIXTURES_DIR / "rules" / "uses_dataset.yaml")
    assert rule_errors(rule.data) == [
        "$.query: must not reference the emulator-only Dataset column"
    ]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"entityMappings": None}, "'entityMappings' is a required property"),
        ({"id": "not-a-guid"}, "is not a 'uuid'"),
        ({"severity": "Critical"}, "is not one of"),
        ({"queryFrequency": "1w"}, "does not match"),
        ({"triggerOperator": ">"}, "is not one of"),
        ({"triggerThreshold": 10001}, "is greater than the maximum"),
        ({"tactics": ["Credential Access"]}, "is not one of"),
        ({"relevantTechniques": ["T1003.1"]}, "does not match"),
        ({"version": "1.0"}, "does not match"),
        ({"kind": "NRT"}, "was expected"),
        ({"query": ""}, "should be non-empty"),
        ({"entityMappings": host_mapping("Name")}, "is not one of"),
        ({"entityMappings": host_mapping("HostName") * 11}, "is too long"),
        (
            {"requiredDataConnectors": [{"connectorId": "X", "dataTypes": ["SigninLogs"]}]},
            "is not one of",
        ),
        ({"queryFrequency": "1h", "queryPeriod": "30m"}, "greater than or equal"),
        ({"queryFrequency": "15d", "queryPeriod": "15d"}, "between 5m and 14d"),
        ({"queryFrequency": "1m", "queryPeriod": "1h"}, "between 5m and 14d"),
        ({"queryFrequency": "30m", "queryPeriod": "2d"}, "at least 1h"),
        ({"query": "Event | where TimeGenerated > ago(1h)"}, "ago() or now()"),
        ({"query": "Event | where TimeGenerated < now ()"}, "ago() or now()"),
    ],
)
def test_invalid_rules_are_rejected(changes, message):
    errors = rule_errors(mutated(**changes))
    assert any(message in error for error in errors), errors


def test_account_identifiers_differ_from_host_identifiers():
    account = [
        {"entityType": "Account", "fieldMappings": [{"identifier": "Name", "columnName": "A"}]}
    ]
    assert rule_errors(mutated(entityMappings=account)) == []


def test_long_trigger_operator_names_are_accepted():
    assert rule_errors(mutated(triggerOperator="GreaterThan")) == []


def test_duplicate_yaml_keys_are_rejected(tmp_path):
    path = tmp_path / "rule.yaml"
    path.write_text("query: a\nquery: b\n", encoding="utf-8")
    with pytest.raises(RuleFileError, match="duplicate key 'query'"):
        load_yaml(path)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("5m", timedelta(minutes=5)), ("1h", timedelta(hours=1)), ("14d", timedelta(days=14))],
)
def test_parse_time_span(value, expected):
    assert parse_time_span(value) == expected


def test_valid_test_case(datasets):
    assert case_errors(VALID_CASE, VALID_RULE, datasets) == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"attack_dataset": "unknown_dataset"}, "is not in the manifest"),
        ({"attack_dataset": "empire_dcsync"}, "is not in the rule's relevantTechniques"),
        ({"min_hits": 0}, "is less than the minimum"),
        ({"expected_cross_hits": ["empire_over_pth"]}, "was unexpected"),
        ({"baseline_query": 'Event | where Dataset == "x"'}, "Dataset column"),
    ],
)
def test_invalid_test_cases_are_rejected(changes, message, datasets):
    errors = case_errors({**VALID_CASE, **changes}, VALID_RULE, datasets)
    assert any(message in error for error in errors), errors


def test_pairing_reports_missing_orphaned_and_duplicate_files(tmp_path):
    rules, cases = tmp_path / "rules", tmp_path / "cases"
    for path in (
        rules / "credential_access" / "a.yaml",
        rules / "persistence" / "a.yaml",
        rules / "persistence" / "b.yaml",
        cases / "a.yaml",
        cases / "c.yaml",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    errors = "\n".join(pairing_errors(rules, cases))
    assert "'a' is used more than once" in errors
    assert "b.yaml: no test case" in errors
    assert "c.yaml: no rule named c.yaml" in errors
