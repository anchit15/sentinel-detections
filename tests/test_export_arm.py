"""ARM template export of the rule files; no emulator needed."""

import json
from dataclasses import replace

import pytest

from paths import RULES_DIR
from sentinel_detections.arm import (
    API_VERSION,
    MAX_RULES_PER_TEMPLATE,
    RESOURCE_TYPE,
    build_template,
    iso_duration,
    split_techniques,
)
from sentinel_detections.rules import load_rules

RULES = load_rules(RULES_DIR)
TEMPLATE = build_template(RULES)
RESOURCES = {
    rule.data["id"]: resource for rule, resource in zip(RULES, TEMPLATE["resources"], strict=True)
}


def test_template_takes_the_workspace_as_its_only_parameter():
    assert TEMPLATE["parameters"] == {"workspace": {"type": "String"}}
    assert TEMPLATE["contentVersion"] == "1.0.0.0"


def test_one_scheduled_resource_per_rule_named_by_rule_id():
    assert len(TEMPLATE["resources"]) == len(RULES)
    for rule_id, resource in RESOURCES.items():
        assert resource["type"] == RESOURCE_TYPE
        assert resource["apiVersion"] == API_VERSION
        assert resource["kind"] == "Scheduled"
        assert resource["name"].endswith(f"/Microsoft.SecurityInsights/{rule_id}')]")
        assert resource["id"].endswith(f"'/alertRules/{rule_id}')]")


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.stem)
def test_query_and_attack_fields_are_carried_over_unchanged(rule):
    properties = RESOURCES[rule.data["id"]]["properties"]
    for yaml_field, arm_field in (
        ("name", "displayName"),
        ("description", "description"),
        ("severity", "severity"),
        ("query", "query"),
        ("tactics", "tactics"),
        ("entityMappings", "entityMappings"),
        ("triggerThreshold", "triggerThreshold"),
    ):
        assert properties[arm_field] == rule.data[yaml_field]
    tags = set(rule.relevant_techniques)
    assert set(properties["subTechniques"]) == {t for t in tags if "." in t}
    assert set(properties["techniques"]) == {t.split(".")[0] for t in tags}


def test_schedule_and_trigger_use_arm_formats():
    properties = RESOURCES["4965eff1-cbfe-43b8-ace1-19382bc93e41"]["properties"]
    assert properties["queryFrequency"] == "PT1H"
    assert properties["queryPeriod"] == "PT2H"
    assert properties["triggerOperator"] == "GreaterThan"


@pytest.mark.parametrize(
    ("span", "expected"), [("5m", "PT5M"), ("1h", "PT1H"), ("24h", "PT24H"), ("14d", "P14D")]
)
def test_iso_duration(span, expected):
    assert iso_duration(span) == expected


def test_split_techniques_lists_each_parent_once():
    assert split_techniques(["T1218.011", "T1003.001", "T1003.006", "T1059"]) == (
        ["T1003", "T1059", "T1218"],
        ["T1003.001", "T1003.006", "T1218.011"],
    )


def test_template_is_deterministic_json():
    assert json.dumps(build_template(reversed(RULES))) == json.dumps(TEMPLATE)


def test_too_many_rules_for_one_import_file_is_refused():
    rule = RULES[0]
    clones = [
        replace(rule, path=rule.path.with_name(f"{i}.yaml"))
        for i in range(MAX_RULES_PER_TEMPLATE + 1)
    ]
    with pytest.raises(ValueError, match="import limit"):
        build_template(clones)
