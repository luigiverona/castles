from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import permutations

import pytest

from castles.core.entity import Relationship, Resolution
from castles.core.error import InputError
from castles.core.message import NormalizedMessage
from castles.core.signal import MessageSignals, Signal, SignalKind, SignalSource, Strength
from castles.detect.assess import _diminishing, identity
from castles.detect.build import discover
from castles.detect.extract import extract
from castles.detect.infra import InfraStatus, Infrastructure
from castles.detect.resolve import Candidate, Decision, resolve
from castles.detect.suffix import Rule, Section, Suffixes, hostname

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def message(
    key: str,
    *,
    sender: str | None = "unknown-saas.example",
    authenticated: tuple[str, ...] = (),
    subject: str = "",
    text: str = "",
    links: tuple[str, ...] = (),
    unsubscribe: tuple[str, ...] = (),
    offset: int = 0,
) -> MessageSignals:
    return extract(
        NormalizedMessage(
            key,
            NOW + timedelta(minutes=offset),
            sender,
            None,
            None,
            authenticated,
            subject,
            text,
            links,
            unsubscribe,
        )
    )


def test_unknown_entity_and_relationship_discovery() -> None:
    findings = discover((message("one", subject="Invoice is available"),))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.entity == "unknown-saas.example"
    assert finding.identity.score == 30
    assert finding.relationships[0].kind is Relationship.BILLING
    assert finding.relationships[0].confidence.score == 26
    assert finding.message_count == 1


def test_known_entity_requires_no_catalog() -> None:
    finding = discover((message("one", sender="github.com", authenticated=("github.com",)),))[0]
    assert finding.entity == "github.com"
    assert finding.identity.score == 80
    assert "identity.agreement.sender_auth" in finding.identity.explanations


def test_marketing_does_not_imply_lifecycle() -> None:
    finding = discover((message("one", subject="Special offer ends today"),))[0]
    assert [item.kind for item in finding.relationships] == [Relationship.MARKETING]


def test_identity_and_relationship_scores_are_independent() -> None:
    weak_relation = discover((message("one", sender="github.com", subject="Invoice available"),))[0]
    strong_identity = discover(
        (message("one", sender="github.com", authenticated=("github.com",)),)
    )[0]
    assert weak_relation.identity.score == 30
    assert strong_identity.identity.score == 80
    assert weak_relation.relationships[0].confidence.score == 26
    assert strong_identity.relationships == ()


def test_duplicate_non_amplification() -> None:
    signal = Signal(
        SignalKind.SENDER, SignalSource.HEADER, "github.com", Strength.STRONG, "identity.sender"
    )
    current = MessageSignals("one", NOW, (signal, signal, signal))
    assert discover((current,))[0].identity.score == 30


def test_diminishing_evidence_is_monotonic_and_capped() -> None:
    scores = [
        discover(tuple(message(str(index), sender="github.com") for index in range(count)))[
            0
        ].identity.score
        for count in (1, 2, 3, 20)
    ]
    assert scores == [30, 45, 52, 71]
    assert scores == sorted(scores)


def test_diminishing_evidence_is_bounded_for_large_counts() -> None:
    assert _diminishing(30, 1_000_000) == 1_000_051


def test_competing_entities_prevent_relationship_attribution() -> None:
    current = message(
        "one",
        sender="alpha.example.com",
        authenticated=("beta.example.net",),
        subject="Invoice available",
    )
    findings = discover((current,))
    assert {item.entity for item in findings} == {"example.com", "example.net"}
    assert all(not item.relationships for item in findings)


def test_known_infrastructure_is_suppressed() -> None:
    current = message(
        "one",
        sender="company.example",
        links=("u1.ct.sendgrid.net", "static.cloudfront.net"),
    )
    assert [item.entity for item in discover((current,))] == ["company.example"]


def test_ambiguous_infrastructure_is_not_reported() -> None:
    current = message("one", sender="mandrillapp.com", subject="Invoice available")
    assert discover((current,)) == ()
    decision = resolve((current,), Suffixes(), Infrastructure())[0]
    assert decision.status is Resolution.AMBIGUOUS


def test_link_only_identity_is_unresolved() -> None:
    current = message("one", sender=None, links=("account.github.com",))
    assert discover((current,)) == ()
    assert resolve((current,), Suffixes(), Infrastructure())[0].status is Resolution.UNRESOLVED


def test_nonresolved_decisions_are_not_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    current = message("one", sender="github.com")
    boundary = Suffixes().boundary("github.com")
    signal = current.signals[0]
    candidate = Candidate("github.com", (current,), (("one", signal, boundary),))
    for status in (Resolution.UNRESOLVED, Resolution.AMBIGUOUS, Resolution.CONFLICTED):
        monkeypatch.setattr(
            "castles.detect.build.resolve",
            lambda *_args, status=status: (Decision("github.com", status, candidate, ("reason",)),),
        )
        assert discover((current,)) == ()


def test_private_suffix_keeps_tenants_separate() -> None:
    findings = discover(
        (
            message("one", sender="one.github.io"),
            message("two", sender="two.github.io"),
        )
    )
    assert {item.entity for item in findings} == {"one.github.io", "two.github.io"}


@pytest.mark.parametrize(
    ("value", "entity", "section", "rule"),
    [
        ("mail.example.co.uk", "example.co.uk", Section.ICANN, Rule.EXACT),
        ("tenant.github.io", "tenant.github.io", Section.PRIVATE, Rule.EXACT),
        ("foo.bar.ck", "foo.bar.ck", Section.ICANN, Rule.WILDCARD),
        ("www.ck", "www.ck", Section.ICANN, Rule.EXCEPTION),
        ("mail.unknown", "mail.unknown", Section.NONE, Rule.PREVAILING),
    ],
)
def test_suffix_boundaries(value: str, entity: str, section: Section, rule: Rule) -> None:
    result = Suffixes().boundary(value)
    assert result.entity == entity
    assert result.section is section
    assert result.rule is rule


def test_idna_and_malformed_hostnames() -> None:
    assert hostname("MÜNICH.example.") == "xn--mnich-kva.example"
    for value in ("127.0.0.1", "localhost", "printer.local", "bad..example", "-bad.example"):
        with pytest.raises(InputError):
            hostname(value)


def test_infrastructure_matching_is_label_aware() -> None:
    classifier = Infrastructure()
    assert classifier.classify("click.sendgrid.net").status is InfraStatus.KNOWN
    assert classifier.classify("sendgrid.net.evil.example").status is InfraStatus.NOT_LISTED
    assert classifier.classify("pm.mtasv.net").status is InfraStatus.KNOWN
    assert classifier.classify("x.pm.mtasv.net").status is InfraStatus.NOT_LISTED
    assert classifier.classify("mailchi.mp").status is InfraStatus.AMBIGUOUS


def test_prevailing_suffix_caps_confidence() -> None:
    current = message("one", sender="unknown-saas.example", authenticated=("unknown-saas.example",))
    decision = resolve((current,), Suffixes(), Infrastructure())[0]
    assert decision.candidate is not None
    score = identity(decision.candidate)
    assert score.score == 49
    assert "identity.cap.prevailing_suffix" in score.explanations


def test_permutations_are_deterministic() -> None:
    values = (
        message("one", sender="github.com", subject="Invoice available"),
        message("two", sender="github.com", text="Payment failed", offset=1),
        message("three", sender="spotify.com", subject="Subscription renewed", offset=2),
    )
    expected = discover(values)
    assert all(discover(tuple(order)) == expected for order in permutations(values))


def test_extraction_covers_supported_inputs() -> None:
    current = extract(
        NormalizedMessage(
            "one",
            NOW,
            "sender.example",
            "reply.example",
            "return.example",
            ("auth.example",),
            "Verification code and invoice available",
            "Support ticket updated and activity summary",
            ("link.example",),
            ("leave.example",),
        )
    )
    assert {signal.kind for signal in current.signals} == {
        SignalKind.SENDER,
        SignalKind.REPLY,
        SignalKind.RETURN_PATH,
        SignalKind.AUTHENTICATED,
        SignalKind.LINK,
        SignalKind.UNSUBSCRIBE,
        SignalKind.AUTHENTICATION,
        SignalKind.BILLING,
        SignalKind.SUPPORT,
        SignalKind.ACTIVITY,
    }
