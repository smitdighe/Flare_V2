"""Canonical label and severity maps.

PLAN §6.3: raw label spellings map to canonical classes through an EXPLICIT
map, with zero unmapped enforced by a test. An unmapped spelling is a loud
failure, never a silent fallthrough to "other" — that is how a class quietly
disappears from an eval.

PLAN D27: severity order is low < medium < high < critical. `unknown` sits
outside the order and satisfies no threshold — it is a failure state, never a
ground-truth label.
"""

from __future__ import annotations

from typing import Final

# Raw spellings exactly as they appear in CICIDS2017's MachineLearningCSV.
#
# The Web Attack labels contain byte 0x96 — a CP-1252 en dash. Depending on how
# a given copy was written and re-encoded that surfaces as U+2013 (en dash),
# U+FFFD (replacement char) or the raw byte, so every observed form is listed.
# A spelling that reaches here unmatched raises; it is never guessed at.
RAW_TO_CANONICAL: Final[dict[str, str]] = {
    "BENIGN": "benign",
    # DoS variants collapse to one class: they are the same tactic and the
    # per-variant counts are too thin to score separately after a 3-way split.
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "DDoS": "ddos",
    "PortScan": "port_scan",
    "Bot": "botnet",
    # Keys are the NORMALIZED form (see normalize_label): whatever the
    # separator survived as, it is collapsed to a plain hyphen before lookup.
    "Web Attack - Brute Force": "web_attack",
    "Web Attack - XSS": "web_attack",
    "Web Attack - Sql Injection": "web_attack",
    # Present in the capture but deliberately excluded from the partitions —
    # CICIDS2017 contains only 11 Heartbleed flows in total, which cannot yield
    # a meaningful share in three disjoint partitions. Mapped so it is
    # recognised rather than crashing the zero-unmapped check, then dropped
    # explicitly and reported by build_partitions.py.
    "Heartbleed": "heartbleed",
}

# The classes the classifier is trained and scored on.
CANONICAL_CLASSES: Final[tuple[str, ...]] = (
    "benign",
    "dos",
    "ddos",
    "port_scan",
    "botnet",
    "web_attack",
)

EXCLUDED_CLASSES: Final[dict[str, str]] = {
    "heartbleed": "only 11 flows exist in the entire capture; cannot survive a 3-way split",
}

# PLAN §6.3 requires this map to exist and be documented — the prior codebase
# evaluated attack type only and had no severity mapping at all.
CLASS_TO_SEVERITY: Final[dict[str, str]] = {
    "benign": "low",
    "port_scan": "medium",  # reconnaissance, no compromise yet
    "web_attack": "high",  # direct attempt against an application edge
    "botnet": "high",  # implies an already-compromised host
    "dos": "high",  # service degradation in progress
    "ddos": "critical",  # distributed, service-affecting
}

# PLAN D27. `unknown` is intentionally absent: it is outside the order.
SEVERITY_ORDER: Final[tuple[str, ...]] = ("low", "medium", "high", "critical")


class UnmappedLabelError(ValueError):
    """A raw label spelling that RAW_TO_CANONICAL does not cover."""


# Every separator seen where CICIDS2017's byte 0x96 ends up, collapsed to a
# plain hyphen before lookup. Covers the true CP-1252 en dash, the U+FFFD a
# UTF-8 conversion leaves behind, and the "ï¿½" mojibake a double-decode
# produces.
_SEPARATOR_VARIANTS: Final[tuple[str, ...]] = ("–", "�", "ï¿½", "")


def normalize_label(raw_label: str) -> str:
    """Collapse encoding damage in the separator so lookup is encoding-agnostic."""
    text = raw_label.strip()
    for variant in _SEPARATOR_VARIANTS:
        text = text.replace(variant, "-")
    while "--" in text:
        text = text.replace("--", "-")
    return " ".join(text.split())


def canonical_class(raw_label: str) -> str:
    key = normalize_label(raw_label)
    try:
        return RAW_TO_CANONICAL[key]
    except KeyError as exc:
        raise UnmappedLabelError(
            f"Unmapped label spelling {key!r}. Add it to RAW_TO_CANONICAL "
            f"explicitly — never fall through to a default."
        ) from exc


def severity_for(canonical: str) -> str:
    try:
        return CLASS_TO_SEVERITY[canonical]
    except KeyError as exc:
        raise UnmappedLabelError(f"No severity mapped for class {canonical!r}") from exc


def severity_rank(severity: str) -> int:
    """Position in the total order. `unknown` returns -1 and fails every threshold.

    PLAN D27: an alert whose classification failed must never satisfy a
    playbook or notification threshold — that would fire real actions on the
    pipeline's own failures.
    """
    if severity not in SEVERITY_ORDER:
        return -1
    return SEVERITY_ORDER.index(severity)


def meets_threshold(severity: str, threshold: str | None) -> bool:
    if not threshold:
        return True
    rank = severity_rank(severity)
    if rank < 0:
        return False  # fails closed
    return rank >= severity_rank(threshold)
