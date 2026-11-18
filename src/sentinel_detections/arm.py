"""Build an ARM template that Microsoft Sentinel's Analytics import accepts.

The template mirrors the structure of Sentinel's own analytics-rule export: one
``workspace`` parameter and one ``alertRules`` resource per rule, named by rule id so that
importing again updates the same rules instead of duplicating them.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sentinel_detections.rules import TIME_UNITS, Rule

TEMPLATE_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
RESOURCE_TYPE = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
# The version Sentinel's export writes. GA versions (latest 2025-09-01) have no
# subTechniques property, which would drop 11 of the 12 technique tags.
API_VERSION = "2023-12-01-preview"
# Sentinel's Analytics import reads at most 50 rules from one file.
MAX_RULES_PER_TEMPLATE = 50

ARM_TRIGGER_OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
ISO_DURATION_UNITS = {"minutes": "PT{}M", "hours": "PT{}H", "days": "P{}D"}

# Settings the rule YAML cannot express. Grouping alerts that share all entities over
# 5 hours merges duplicates from rules whose queryPeriod overlaps the previous run.
SUPPRESSION = {"suppressionDuration": "PT5H", "suppressionEnabled": False}
INCIDENT_CONFIGURATION = {
    "createIncident": True,
    "groupingConfiguration": {
        "enabled": True,
        "reopenClosedIncident": False,
        "lookbackDuration": "PT5H",
        "matchingMethod": "AllEntities",
        "groupByEntities": [],
        "groupByAlertDetails": [],
        "groupByCustomDetails": [],
    },
}
EVENT_GROUPING = {"aggregationKind": "AlertPerResult"}


def iso_duration(span: str) -> str:
    """Convert a Sentinel YAML time span (``5m``, ``1h``, ``1d``) to ISO 8601 (``PT1H``)."""
    return ISO_DURATION_UNITS[TIME_UNITS[span[-1]]].format(int(span[:-1]))


def split_techniques(technique_ids: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split ATT&CK ids into (parent techniques, sub-techniques) as the Sentinel API expects.

    Every sub-technique's parent is included in the techniques list.
    """
    ids = list(technique_ids)
    parents = sorted({technique.split(".")[0] for technique in ids})
    subtechniques = sorted({technique for technique in ids if "." in technique})
    return parents, subtechniques


def alert_rule_resource(rule: Rule) -> dict[str, Any]:
    """Build the ARM resource for one scheduled rule."""
    data = rule.data
    techniques, subtechniques = split_techniques(rule.relevant_techniques)
    rule_id = data["id"]
    return {
        "id": (
            "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', "
            f"parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/{rule_id}')]"
        ),
        "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/{rule_id}')]",
        "type": RESOURCE_TYPE,
        "kind": data["kind"],
        "apiVersion": API_VERSION,
        "properties": {
            "displayName": data["name"],
            "description": data["description"],
            "severity": data["severity"],
            "enabled": True,
            "query": data["query"],
            "queryFrequency": iso_duration(data["queryFrequency"]),
            "queryPeriod": iso_duration(data["queryPeriod"]),
            "triggerOperator": ARM_TRIGGER_OPERATORS[rule.trigger_operator],
            "triggerThreshold": rule.trigger_threshold,
            **SUPPRESSION,
            "tactics": data["tactics"],
            "techniques": techniques,
            "subTechniques": subtechniques,
            "incidentConfiguration": INCIDENT_CONFIGURATION,
            "eventGroupingSettings": EVENT_GROUPING,
            "entityMappings": data["entityMappings"],
        },
    }


def build_template(rules: Iterable[Rule]) -> dict[str, Any]:
    """Build one ARM template containing every rule, ordered by rule file path."""
    ordered = sorted(rules, key=lambda rule: rule.path)
    if len(ordered) > MAX_RULES_PER_TEMPLATE:
        raise ValueError(
            f"{len(ordered)} rules exceed Sentinel's import limit of "
            f"{MAX_RULES_PER_TEMPLATE} per file"
        )
    return {
        "$schema": TEMPLATE_SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": {"type": "String"}},
        "resources": [alert_rule_resource(rule) for rule in ordered],
    }
