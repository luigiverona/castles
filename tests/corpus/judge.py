from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from castles.app.export import csv_export, json_export
from castles.app.results import ResultSet
from castles.core.finding import Finding
from castles.detect.assess import identity
from castles.detect.build import discover
from castles.detect.extract import extract
from castles.detect.infra import Infrastructure
from castles.detect.resolve import Decision, resolve
from castles.detect.suffix import Suffixes

from .load import load
from .schema import CORPUS_VERSION, Case

GENERATED = datetime(2026, 7, 14, 18, tzinfo=UTC)
SEEDS = (7, 19, 43)


@dataclass(frozen=True, slots=True)
class Report:
    corpus_version: int
    total_cases: int
    passed_cases: int
    failed_cases: int
    expected_findings: int
    produced_findings: int
    false_positives: int
    false_negatives: int
    relationship_mismatches: int
    score_bound_mismatches: int
    resolution_mismatches: int
    observation_mismatches: int
    privacy_mismatches: int
    nondeterministic_cases: int
    failures: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.failed_cases == 0

    def summary(self) -> str:
        values = asdict(self)
        values.pop("failures")
        return json.dumps(values, sort_keys=True, separators=(",", ":"))

    def detail(self) -> str:
        if not self.failures:
            return self.summary()
        return self.summary() + "\n" + "\n".join(self.failures)


def _privacy(case: Case, findings: tuple[Finding, ...]) -> tuple[str, ...]:
    result = ResultSet("synthetic", "synthetic-owner@corpus.example", None, findings)
    rendered = "\n".join(
        (
            repr(findings),
            json_export((result,), GENERATED),
            csv_export((result,)),
        )
    ).casefold()
    failures = [value for value in case.private if value.casefold() in rendered]
    structural = ("corpus/", "http://", "https://", "oauth", "authorization:")
    failures.extend(value for value in structural if value in rendered)
    return tuple(sorted(set(failures)))


def _decisions(case: Case, actual: tuple[Decision, ...]) -> tuple[int, int, tuple[str, ...]]:
    expected = {item.entity: item for item in case.decisions}
    produced = {item.entity: item for item in actual}
    mismatches = 0
    scores = 0
    failures: list[str] = []
    if set(expected) != set(produced):
        mismatches += len(set(expected) ^ set(produced))
        failures.append(f"decisions expected={sorted(expected)} produced={sorted(produced)}")
    for entity in sorted(set(expected) & set(produced)):
        wanted = expected[entity]
        current = produced[entity]
        if wanted.state is not current.status:
            mismatches += 1
            failures.append(
                f"decision {entity} expected={wanted.state.value} produced={current.status.value}"
            )
        if set(wanted.explanations) != set(current.reasons):
            mismatches += 1
            failures.append(f"decision {entity} explanations differ")
        if wanted.identity is not None:
            if current.candidate is None:
                scores += 1
                failures.append(f"decision {entity} has no candidate for identity scoring")
            else:
                value = identity(current.candidate).score
                if not wanted.identity.contains(value):
                    scores += 1
                    failures.append(
                        f"decision {entity} identity expected={wanted.identity} produced={value}"
                    )
    return mismatches, scores, tuple(failures)


def evaluate(cases: tuple[Case, ...] | None = None) -> Report:
    cases = load() if cases is None else cases
    suffixes = Suffixes()
    infrastructure = Infrastructure()
    failed: set[str] = set()
    failures: list[str] = []
    expected_findings = produced_findings = 0
    false_positives = false_negatives = 0
    relationship_mismatches = score_mismatches = 0
    resolution_mismatches = observation_mismatches = 0
    privacy_mismatches = nondeterministic = 0

    for case in cases:
        messages = tuple(extract(message.normalize()) for message in case.messages)
        decisions = resolve(messages, suffixes, infrastructure)
        findings = discover(messages, suffixes, infrastructure)
        expected = {item.entity: item for item in case.findings}
        produced = {item.entity: item for item in findings}
        expected_findings += len(expected)
        produced_findings += len(produced)
        additions = set(produced) - set(expected)
        omissions = set(expected) - set(produced)
        false_positives += len(additions)
        false_negatives += len(omissions)
        if additions:
            failures.append(f"{case.identifier}: false positives {sorted(additions)}")
        if omissions:
            failures.append(f"{case.identifier}: false negatives {sorted(omissions)}")
        if additions or omissions:
            failed.add(case.identifier)
        expected_order = tuple(item.entity for item in case.findings)
        produced_order = tuple(item.entity for item in findings)
        if expected_order != produced_order:
            observation_mismatches += 1
            failures.append(
                f"{case.identifier}: finding order expected={expected_order} produced={produced_order}"
            )
            failed.add(case.identifier)
        unexpected_suppressed = set(case.suppressed) & set(produced)
        if unexpected_suppressed:
            false_positives += len(unexpected_suppressed - additions)
            failures.append(
                f"{case.identifier}: expected suppression {sorted(unexpected_suppressed)}"
            )
            failed.add(case.identifier)

        for entity in sorted(set(expected) & set(produced)):
            wanted = expected[entity]
            current = produced[entity]
            if not wanted.identity.contains(current.identity.score):
                score_mismatches += 1
                failures.append(
                    f"{case.identifier}: {entity} identity expected={wanted.identity} produced={current.identity.score}"
                )
                failed.add(case.identifier)
            if current.identity.band is not wanted.band:
                score_mismatches += 1
                failures.append(
                    f"{case.identifier}: {entity} identity band expected={wanted.band.value} produced={current.identity.band.value}"
                )
                failed.add(case.identifier)
            if set(wanted.identity_explanations) != set(current.identity.explanations):
                score_mismatches += 1
                failures.append(f"{case.identifier}: {entity} identity explanations differ")
                failed.add(case.identifier)
            expected_relations = {item.kind: item for item in wanted.relationships}
            produced_relations = {item.kind: item for item in current.relationships}
            if set(expected_relations) != set(produced_relations):
                relationship_mismatches += 1
                failures.append(
                    f"{case.identifier}: {entity} relationships expected={sorted(item.value for item in expected_relations)} produced={sorted(item.value for item in produced_relations)}"
                )
                failed.add(case.identifier)
            for kind in set(expected_relations) & set(produced_relations):
                relation = expected_relations[kind]
                actual = produced_relations[kind]
                if not relation.score.contains(actual.confidence.score):
                    score_mismatches += 1
                    failures.append(
                        f"{case.identifier}: {entity}/{kind.value} score expected={relation.score} produced={actual.confidence.score}"
                    )
                    failed.add(case.identifier)
                if actual.confidence.band is not relation.band:
                    score_mismatches += 1
                    failures.append(
                        f"{case.identifier}: {entity}/{kind.value} band expected={relation.band.value} produced={actual.confidence.band.value}"
                    )
                    failed.add(case.identifier)
                if set(relation.explanations) != set(actual.confidence.explanations):
                    relationship_mismatches += 1
                    failures.append(f"{case.identifier}: {entity}/{kind.value} explanations differ")
                    failed.add(case.identifier)
            if set(wanted.explanations) != set(current.explanations):
                observation_mismatches += 1
                failures.append(f"{case.identifier}: {entity} finding explanations differ")
                failed.add(case.identifier)
            observation = (current.first_seen, current.last_seen, current.message_count)
            expected_observation = (wanted.first_seen, wanted.last_seen, wanted.message_count)
            if observation != expected_observation:
                observation_mismatches += 1
                failures.append(
                    f"{case.identifier}: {entity} observations expected={expected_observation} produced={observation}"
                )
                failed.add(case.identifier)

        decision_count, decision_scores, decision_failures = _decisions(case, decisions)
        resolution_mismatches += decision_count
        score_mismatches += decision_scores
        if decision_failures:
            failures.extend(f"{case.identifier}: {value}" for value in decision_failures)
            failed.add(case.identifier)

        if case.deterministic:
            unstable = False
            for seed in SEEDS:
                shuffled = list(messages)
                random.Random(seed).shuffle(shuffled)  # noqa: S311 - deterministic test order
                if discover(tuple(shuffled), suffixes, infrastructure) != findings:
                    unstable = True
                    break
            if unstable:
                nondeterministic += 1
                failures.append(f"{case.identifier}: output changed under fixed-seed permutation")
                failed.add(case.identifier)

        leaked = _privacy(case, findings)
        if leaked:
            privacy_mismatches += len(leaked)
            failures.append(f"{case.identifier}: private output tokens {list(leaked)}")
            failed.add(case.identifier)

    return Report(
        CORPUS_VERSION,
        len(cases),
        len(cases) - len(failed),
        len(failed),
        expected_findings,
        produced_findings,
        false_positives,
        false_negatives,
        relationship_mismatches,
        score_mismatches,
        resolution_mismatches,
        observation_mismatches,
        privacy_mismatches,
        nondeterministic,
        tuple(failures),
    )


def main() -> None:
    report = evaluate()
    print(report.detail() if not report.ok else report.summary())
    if not report.ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
