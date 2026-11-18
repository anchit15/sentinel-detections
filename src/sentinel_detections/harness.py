"""Evaluate rule queries across datasets and turn the results into pass/fail checks.

For each rule, every loaded dataset falls into one of three groups:

* the attack dataset named in the rule's test case, where the rule must fire;
* cross-hit datasets, whose manifest techniques overlap the rule's relevantTechniques,
  where hits are expected and reported but not required;
* benign datasets (all others), where every hit is a false positive.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from azure.kusto.data import KustoClient

from sentinel_detections.kusto import count_hits, sample_rows, trigger_fires
from sentinel_detections.manifest import Dataset
from sentinel_detections.rules import Rule, TestCase, classify_datasets

SAMPLE_LIMIT = 5


@dataclass(frozen=True)
class DatasetHits:
    """Rows a query returned on one dataset, with sample rows for false positives."""

    dataset_id: str
    hits: int
    samples: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class Evaluation:
    """Results of one query (tuned or baseline) on every dataset."""

    attack: DatasetHits
    cross_hits: tuple[DatasetHits, ...]
    false_positives: tuple[DatasetHits, ...]

    @property
    def cross_hit_total(self) -> int:
        return sum(result.hits for result in self.cross_hits)

    @property
    def false_positive_total(self) -> int:
        return sum(result.hits for result in self.false_positives)


def evaluate(
    client: KustoClient,
    database: str,
    query: str,
    rule: Rule,
    attack_dataset: str,
    datasets: Iterable[Dataset],
) -> Evaluation:
    """Run ``query`` on each dataset separately and group the hits."""
    cross, benign = classify_datasets(rule, attack_dataset, datasets)

    def hits_on(dataset_id: str, with_samples: bool = False) -> DatasetHits:
        hits = count_hits(client, database, query, dataset_id)
        samples = ()
        if with_samples and hits:
            samples = tuple(sample_rows(client, database, query, dataset_id, SAMPLE_LIMIT))
        return DatasetHits(dataset_id, hits, samples)

    return Evaluation(
        attack=hits_on(attack_dataset),
        cross_hits=tuple(hits_on(dataset_id) for dataset_id in cross),
        false_positives=tuple(hits_on(dataset_id, with_samples=True) for dataset_id in benign),
    )


def attack_failures(evaluation: Evaluation, case: TestCase) -> list[str]:
    """Problems with detection on the attack dataset (used for tuned and baseline queries)."""
    attack = evaluation.attack
    if attack.hits < case.min_hits:
        return [
            f"attack dataset {attack.dataset_id}: {attack.hits} hits, "
            f"expected at least {case.min_hits}"
        ]
    return []


def rule_failures(evaluation: Evaluation, rule: Rule, case: TestCase) -> list[str]:
    """Every reason the tuned rule fails its test case; empty when it passes."""
    failures = attack_failures(evaluation, case)
    attack = evaluation.attack
    if not trigger_fires(attack.hits, rule.trigger_operator, rule.trigger_threshold):
        failures.append(
            f"attack dataset {attack.dataset_id}: {attack.hits} hits would not trigger an alert "
            f"(triggerOperator {rule.trigger_operator}, triggerThreshold {rule.trigger_threshold})"
        )
    failures.extend(
        format_false_positives(result) for result in evaluation.false_positives if result.hits
    )
    return failures


def format_false_positives(result: DatasetHits) -> str:
    """Describe false positives on one dataset with sample rows to tune from."""
    lines = [
        f"false positives in {result.dataset_id}: {result.hits} hits "
        f"(showing {len(result.samples)} sample rows)"
    ]
    for number, row in enumerate(result.samples, start=1):
        cells = ", ".join(f"{name}={value}" for name, value in row.items())
        lines.append(f"  {number}. {cells}")
    return "\n".join(lines)
