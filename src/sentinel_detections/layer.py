"""Build an ATT&CK Navigator layer showing which techniques the rules cover."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sentinel_detections.rules import Rule

# Microsoft Sentinel is aligned to ATT&CK v18 and the rule tags are validated by Sentinel,
# so the layer pins the same version. Later versions revoke T1562.002 and split the
# Defense Evasion tactic, which would drop or misplace techniques.
ATTACK_VERSION = "18"
NAVIGATOR_VERSION = "5.3.2"
LAYER_FORMAT_VERSION = "4.5"

LAYER_NAME = "sentinel-detections coverage"
LAYER_DESCRIPTION = (
    "ATT&CK techniques covered by the scheduled analytics rules in this repository. "
    "Score = number of rules tagged with the technique."
)
LOW_COLOUR = "#ffffff"
HIGH_COLOUR = "#31a354"


def _interpolate(low: str, high: str, fraction: float) -> str:
    """Blend two #rrggbb colours; fraction 0 gives low, 1 gives high."""
    start = [int(low[i : i + 2], 16) for i in (1, 3, 5)]
    end = [int(high[i : i + 2], 16) for i in (1, 3, 5)]
    channels = [round(a + (b - a) * fraction) for a, b in zip(start, end, strict=True)]
    return "#" + "".join(f"{channel:02x}" for channel in channels)


def build_layer(rules: Iterable[Rule], repo_root: Path) -> dict[str, Any]:
    """Build a Navigator layer (format 4.5) scoring each technique by its number of rules.

    Techniques carry no ``tactic`` field, so the Navigator shows each one under every
    tactic it belongs to in the pinned ATT&CK version.
    """
    covering: dict[str, list[Rule]] = {}
    for rule in sorted(rules, key=lambda rule: rule.path):
        for technique in rule.relevant_techniques:
            covering.setdefault(technique, []).append(rule)

    techniques = [
        {
            "techniqueID": technique,
            "score": len(technique_rules),
            "comment": "; ".join(rule.data["name"] for rule in technique_rules),
            "metadata": [
                {"name": "Rule", "value": rule.path.relative_to(repo_root).as_posix()}
                for rule in technique_rules
            ],
        }
        for technique, technique_rules in sorted(covering.items())
    ]
    max_score = max((len(technique_rules) for technique_rules in covering.values()), default=1)
    legend = [
        {
            "label": f"{score} rule" if score == 1 else f"{score} rules",
            "color": _interpolate(LOW_COLOUR, HIGH_COLOUR, score / max_score),
        }
        for score in range(1, max_score + 1)
    ]
    return {
        "name": LAYER_NAME,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT_VERSION,
        },
        "domain": "enterprise-attack",
        "description": LAYER_DESCRIPTION,
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": [LOW_COLOUR, HIGH_COLOUR], "minValue": 0, "maxValue": max_score},
        "legendItems": legend,
    }
