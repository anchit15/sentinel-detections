"""Load, validate and pair detection rules with their test cases."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from sentinel_detections.manifest import Dataset

MIN_TIME_SPAN = timedelta(minutes=5)
MAX_TIME_SPAN = timedelta(days=14)
TIME_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

# The Dataset column only exists in the emulator, so a rule that reads it would not
# run in Sentinel. KQL identifiers are case-sensitive.
DATASET_REFERENCE = re.compile(r"\bDataset\b")
# Sentinel applies queryPeriod itself; the datasets date from 2020, so a relative
# time filter would silently match nothing here.
TIME_FUNCTION = re.compile(r"\b(ago|now)\s*\(")

TRIGGER_OPERATORS = {
    "gt": "gt",
    "GreaterThan": "gt",
    "lt": "lt",
    "LessThan": "lt",
    "eq": "eq",
    "Equal": "eq",
    "ne": "ne",
    "NotEqual": "ne",
}


class RuleFileError(ValueError):
    """Raised when a rule or test-case file cannot be parsed."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_yaml(path: Path) -> Any:
    """Parse a YAML file, rejecting duplicate keys."""
    try:
        with path.open(encoding="utf-8") as handle:
            # _UniqueKeyLoader is a SafeLoader, so this never constructs arbitrary objects.
            return yaml.load(handle, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise RuleFileError(f"{path}: {error}") from error


@dataclass(frozen=True)
class Rule:
    """A Sentinel scheduled analytics rule loaded from YAML."""

    path: Path
    data: dict[str, Any]

    @property
    def stem(self) -> str:
        """File name without extension; also names the rule's test case."""
        return self.path.stem

    @property
    def query(self) -> str:
        return self.data["query"]

    @property
    def relevant_techniques(self) -> tuple[str, ...]:
        return tuple(self.data["relevantTechniques"])

    @property
    def trigger_operator(self) -> str:
        """The trigger operator in its short form (gt, lt, eq, ne)."""
        return TRIGGER_OPERATORS[self.data["triggerOperator"]]

    @property
    def trigger_threshold(self) -> int:
        return self.data["triggerThreshold"]


@dataclass(frozen=True)
class TestCase:
    """Expectations for one rule: its attack dataset, minimum hits and baseline query."""

    __test__ = False  # Not a pytest test class despite the name.

    path: Path
    data: dict[str, Any]

    @property
    def attack_dataset(self) -> str:
        return self.data["attack_dataset"]

    @property
    def min_hits(self) -> int:
        return self.data["min_hits"]

    @property
    def baseline_query(self) -> str:
        return self.data["baseline_query"]


@dataclass(frozen=True)
class RulePair:
    """A rule and its test case, matched by file stem."""

    rule: Rule
    case: TestCase


@cache
def _validator(schema_file: str) -> Draft202012Validator:
    path = resources.files("sentinel_detections") / "schemas" / schema_file
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _schema_errors(data: Any, schema_file: str) -> list[str]:
    errors = sorted(_validator(schema_file).iter_errors(data), key=lambda e: list(e.path))
    return [f"{error.json_path}: {error.message}" for error in errors]


def parse_time_span(value: str) -> timedelta:
    """Convert a Sentinel time span such as ``5m``, ``1h`` or ``14d`` to a timedelta."""
    return timedelta(**{TIME_UNITS[value[-1]]: int(value[:-1])})


def query_errors(query: str, field: str) -> list[str]:
    """Return problems that would make a query behave differently here than in Sentinel."""
    errors = []
    if DATASET_REFERENCE.search(query):
        errors.append(f"$.{field}: must not reference the emulator-only Dataset column")
    if TIME_FUNCTION.search(query):
        errors.append(
            f"$.{field}: must not use ago() or now(); Sentinel applies queryPeriod itself"
        )
    return errors


def rule_errors(data: Any) -> list[str]:
    """Validate a parsed rule; return a list of problems, empty when valid."""
    errors = _schema_errors(data, "scheduled_rule.schema.json")
    if errors:
        return errors

    frequency = parse_time_span(data["queryFrequency"])
    period = parse_time_span(data["queryPeriod"])
    for name, span in (("queryFrequency", frequency), ("queryPeriod", period)):
        if not MIN_TIME_SPAN <= span <= MAX_TIME_SPAN:
            errors.append(f"$.{name}: must be between 5m and 14d")
    if period < frequency:
        errors.append("$.queryPeriod: must be greater than or equal to queryFrequency")
    if period >= timedelta(days=2) and frequency < timedelta(hours=1):
        errors.append("$.queryFrequency: must be at least 1h when queryPeriod is 2d or more")
    errors.extend(query_errors(data["query"], "query"))
    return errors


def case_errors(data: Any, rule: Rule, datasets: Iterable[Dataset]) -> list[str]:
    """Validate a parsed test case against its rule and the dataset manifest."""
    errors = _schema_errors(data, "test_case.schema.json")
    if errors:
        return errors

    by_id = {dataset.id: dataset for dataset in datasets}
    attack = by_id.get(data["attack_dataset"])
    if attack is None:
        errors.append(f"$.attack_dataset: {data['attack_dataset']!r} is not in the manifest")
    elif attack.primary_technique not in rule.relevant_techniques:
        errors.append(
            f"$.attack_dataset: its primary technique {attack.primary_technique} "
            f"is not in the rule's relevantTechniques {list(rule.relevant_techniques)}"
        )
    errors.extend(query_errors(data["baseline_query"], "baseline_query"))
    return errors


def load_rule(path: Path) -> Rule:
    """Load a rule file without validating it."""
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise RuleFileError(f"{path}: expected a mapping at the top level")
    return Rule(path=path, data=data)


def load_test_case(path: Path) -> TestCase:
    """Load a test-case file without validating it."""
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise RuleFileError(f"{path}: expected a mapping at the top level")
    return TestCase(path=path, data=data)


def _yaml_files(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.yaml")) if directory.is_dir() else []


def load_rules(rules_dir: Path) -> list[Rule]:
    """Load every rule file under ``rules_dir``, sorted by path, without validating them."""
    return [load_rule(path) for path in _yaml_files(rules_dir)]


def rule_set_errors(rules: Iterable[Rule]) -> list[str]:
    """Validate every rule and check that rule ids are unique across the set.

    Exported Sentinel resources are named by rule id, so a repeated id would make one
    rule silently overwrite another on import.
    """
    errors = []
    paths_by_id: dict[str, list[Path]] = {}
    for rule in rules:
        errors.extend(f"{rule.path}: {error}" for error in rule_errors(rule.data))
        if isinstance(rule.data.get("id"), str):
            paths_by_id.setdefault(rule.data["id"], []).append(rule.path)
    for rule_id, paths in sorted(paths_by_id.items()):
        if len(paths) > 1:
            errors.append(f"rule id {rule_id} is used by {', '.join(map(str, paths))}")
    return errors


def pairing_errors(rules_dir: Path, cases_dir: Path) -> list[str]:
    """Report rules without a test case, test cases without a rule, and repeated stems."""
    rule_paths = _yaml_files(rules_dir)
    case_paths = _yaml_files(cases_dir)
    errors = []
    stems = [path.stem for path in rule_paths]
    for stem in sorted({stem for stem in stems if stems.count(stem) > 1}):
        errors.append(f"rule file name {stem!r} is used more than once under {rules_dir}")
    case_stems = {path.stem for path in case_paths}
    for path in rule_paths:
        if path.stem not in case_stems:
            errors.append(f"{path}: no test case at {cases_dir / (path.stem + '.yaml')}")
    for path in case_paths:
        if path.stem not in set(stems):
            errors.append(f"{path}: no rule named {path.stem}.yaml under {rules_dir}")
    return errors


def discover(rules_dir: Path, cases_dir: Path) -> list[RulePair]:
    """Load every rule under ``rules_dir`` that has a test case in ``cases_dir``."""
    cases = {path.stem: path for path in _yaml_files(cases_dir)}
    return [
        RulePair(rule=load_rule(path), case=load_test_case(cases[path.stem]))
        for path in _yaml_files(rules_dir)
        if path.stem in cases
    ]


def classify_datasets(
    rule: Rule, attack_dataset: str, datasets: Iterable[Dataset]
) -> tuple[list[str], list[str]]:
    """Split every non-attack dataset into (cross-hit datasets, benign datasets).

    A dataset is a cross-hit dataset when its manifest techniques overlap the rule's
    relevantTechniques: hits there are expected and reported, not false positives.
    """
    techniques = set(rule.relevant_techniques)
    cross, benign = [], []
    for dataset in datasets:
        if dataset.id == attack_dataset:
            continue
        (cross if techniques & set(dataset.techniques) else benign).append(dataset.id)
    return cross, benign
