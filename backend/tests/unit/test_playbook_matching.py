"""Playbook scope matching. PLAN D27 / CONTRACT Playbook.severity_threshold.

The threshold is a total order — `low < medium < high < critical` — and
`unknown` sits OUTSIDE it and fails closed. That is not a detail: `unknown`
means classification failed, so treating it as "at least high" would fire real
response actions on the pipeline's own bugs, at exactly the moment the pipeline
is least trustworthy.
"""

from __future__ import annotations

import pytest

from app.ingestion.labels import SEVERITY_ORDER, meets_threshold
from app.playbooks.engine import matches_alert, validate_steps
from app.store.models import Playbook


def playbook(**overrides: object) -> Playbook:
    base: dict[str, object] = {
        "id": 1,
        "owner_id": 1,
        "name": "contain",
        "alert_type": None,
        "severity_threshold": None,
        "steps": [],
        "is_enabled": True,
    }
    base.update(overrides)
    return Playbook(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# D27 — the order, and the thing outside it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("threshold", SEVERITY_ORDER)
def test_unknown_satisfies_no_threshold_ever(threshold: str) -> None:
    """The single most important line in this file.

    An alert whose classification failed must never auto-trigger a playbook.
    """
    assert meets_threshold("unknown", threshold) is False
    assert (
        matches_alert(
            playbook(severity_threshold=threshold),
            attack_type="dos",
            severity="unknown",
        )
        is False
    )


def test_unknown_does_not_even_satisfy_an_empty_threshold_implicitly() -> None:
    """An empty threshold means "any severity", and `unknown` IS any severity.

    This is the one case where `unknown` passes, and it passes because the
    operator asked for everything — not because a comparison silently ranked a
    failure state above `low`.
    """
    assert (
        matches_alert(
            playbook(severity_threshold=None), attack_type="dos", severity="unknown"
        )
        is True
    )


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        ("low", "low", True),
        ("low", "medium", False),
        ("medium", "low", True),
        ("high", "high", True),
        ("high", "critical", False),
        ("critical", "high", True),
        ("critical", "critical", True),
    ],
)
def test_the_total_order(severity: str, threshold: str, expected: bool) -> None:
    assert (
        matches_alert(
            playbook(severity_threshold=threshold),
            attack_type="dos",
            severity=severity,
        )
        is expected
    )


# ---------------------------------------------------------------------------
# alert_type is free text and "" means any
# ---------------------------------------------------------------------------


def test_an_empty_alert_type_matches_every_type() -> None:
    assert (
        matches_alert(playbook(alert_type=""), attack_type="botnet", severity="high")
        is True
    )


def test_a_named_alert_type_matches_case_insensitively() -> None:
    assert (
        matches_alert(playbook(alert_type="DDoS"), attack_type="ddos", severity="high")
        is True
    )
    assert (
        matches_alert(playbook(alert_type="ddos"), attack_type="dos", severity="high")
        is False
    )


def test_a_disabled_playbook_never_matches() -> None:
    assert (
        matches_alert(playbook(is_enabled=False), attack_type="dos", severity="high")
        is False
    )


# ---------------------------------------------------------------------------
# step validation
# ---------------------------------------------------------------------------


def test_an_empty_step_list_is_legal() -> None:
    """Steps with an empty title are stripped client-side before submit."""
    assert validate_steps([]) == []


def test_an_unknown_step_type_is_rejected_by_name() -> None:
    with pytest.raises(ValueError, match="is not a step type"):
        validate_steps([{"type": "escalate", "title": "x"}])


def test_the_legacy_label_alias_is_accepted_and_normalised_to_title() -> None:
    """`title` is canonical; the render path falls back to `label`."""
    assert validate_steps([{"type": "manual", "label": "Isolate host"}]) == [
        {"type": "manual", "title": "Isolate host", "description": None}
    ]
