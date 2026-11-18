"""ATT&CK Navigator layer built from the rule files; no emulator needed."""

from collections import Counter

from paths import REPO_ROOT, RULES_DIR
from sentinel_detections.layer import build_layer
from sentinel_detections.rules import load_rules

RULES = load_rules(RULES_DIR)
LAYER = build_layer(RULES, REPO_ROOT)


def test_layer_declares_the_pinned_versions():
    assert LAYER["versions"] == {"attack": "18", "navigator": "5.3.2", "layer": "4.5"}
    assert LAYER["domain"] == "enterprise-attack"


def test_every_tagged_technique_appears_once_scored_by_rule_count():
    expected = Counter(t for rule in RULES for t in rule.relevant_techniques)
    scores = {entry["techniqueID"]: entry["score"] for entry in LAYER["techniques"]}
    assert len(scores) == len(LAYER["techniques"])
    assert scores == dict(expected)


def test_technique_lists_its_rules_by_name_and_path():
    lsass = next(entry for entry in LAYER["techniques"] if entry["techniqueID"] == "T1003.001")
    assert lsass["comment"] == ("LSASS memory read access; LSASS dump via comsvcs.dll MiniDump")
    assert [item["value"] for item in lsass["metadata"]] == [
        "rules/credential_access/lsass_memory_access.yaml",
        "rules/defense_evasion/rundll32_comsvcs_minidump.yaml",
    ]


def test_techniques_carry_no_tactic_so_they_show_under_every_tactic():
    assert all("tactic" not in entry for entry in LAYER["techniques"])


def test_gradient_and_legend_cover_the_score_range():
    max_score = max(entry["score"] for entry in LAYER["techniques"])
    assert LAYER["gradient"]["maxValue"] == max_score
    assert [item["label"] for item in LAYER["legendItems"]] == ["1 rule", "2 rules"][:max_score]
    assert LAYER["legendItems"][-1]["color"] == LAYER["gradient"]["colors"][-1]


def test_layer_does_not_depend_on_rule_order():
    assert build_layer(reversed(RULES), REPO_ROOT) == LAYER
