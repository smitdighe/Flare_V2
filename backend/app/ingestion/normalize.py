"""NormalizedAlert and the CICIDS2017 flow parser.

PLAN §6.3: parsers return a TYPED NormalizedAlert, never a loose dict.
PLAN D16: field names are dest_ip / dest_port, never dst_*.
PLAN D24: every record carries its `source`.

ENDPOINTS ARE REAL. An earlier build read `MachineLearningCSV`, which carries
no Flow ID, no addresses and no timestamp, so endpoints had to be derived from
CICIDS2017's published topology and stamped as derived. The pipeline now reads
`GeneratedLabelledFlows`, the same CICFlowMeter run with those columns present,
so `src_ip`, `dest_ip`, `Protocol` and the capture time are read straight out of
the row. There is no synthesis path and no flag that turns one back on.

PLAN I4 — THE LABEL NEVER REACHES THE SIGNATURE. The prior codebase built its
signature as f"CICIDS {raw_label} flow ..." and then put the signature in the
prompt, so 450/450 eval prompts contained the answer in plain text. Here the
signature is synthesized from FLOW FEATURES ONLY by `synthesize_signature`,
which never receives the label — it is not a parameter, so it cannot leak by
accident. The label travels in `ground_truth_class`, a field the prompt builder
must never read, and `tests/unit/test_no_label_leak.py` asserts no class name
appears in any generated signature.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

AlertSource = Literal["cicids_replay", "suricata_sample", "live_demo"]

# IANA protocol numbers, as they appear in GeneratedLabelledFlows' `Protocol`
# column. Only these three occur across the five attack days; an unrecognised
# number is rendered as "IP/<n>" rather than guessed at, so an unexpected
# protocol is visible in the UI instead of silently becoming TCP.
_PROTOCOL_BY_NUMBER: dict[int, str] = {
    0: "HOPOPT",
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


@dataclass
class NormalizedAlert:
    id: str
    timestamp: datetime
    source: AlertSource

    severity: str
    attack_type: str

    src_ip: str
    dest_ip: str
    dest_port: int
    protocol: str

    signature: str

    mitre_technique: str | None = None
    ioc_checked: bool = False
    ioc_reputation: int | None = None
    vt_ip: str | None = None
    vt_hash: str | None = None
    explanation: str | None = None
    remediation: str | None = None

    classify_latency_ms: float | None = None
    enrich_latency_ms: float | None = None
    reasoning_latency_ms: float | None = None

    trace: list[dict[str, Any]] = field(default_factory=list)
    confidence: float | None = None
    degraded: bool = False

    # PLAN §4.1 Phase 4 — rule actions that actually mutate the alert.
    tags: list[str] = field(default_factory=list)
    rule_trace: list[dict[str, Any]] = field(default_factory=list)

    # Never serialized to the API, never read by a prompt builder. Present so
    # the eval harness can score a replayed row without the label having gone
    # anywhere near the model. PLAN I4.
    ground_truth_class: str | None = None
    row_id: str | None = None

    # When the flow was actually captured, from the source file. `timestamp`
    # above is ARRIVAL time — see `parse_cicids_row`. Not serialized: the
    # frozen contract has no field for it and the drawer renders `timestamp`.
    captured_at: datetime | None = None

    src_port: int | None = None
    flow_id: str | None = None

    # The 77 flow features, kept for the classifier. Not serialized.
    features: dict[str, float] = field(default_factory=dict)


def alert_id_from(seed: str) -> str:
    """`ALT-XXXXXX` — the format the frozen frontend expects and keys on."""
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:6].upper()
    return f"ALT-{digest}"


def synthesize_signature(
    dest_port: int,
    protocol: str,
    flow_duration_us: float,
    fwd_packets: float,
    bwd_packets: float,
    fwd_bytes: float,
    bwd_bytes: float,
    syn_flags: float,
    psh_flags: float,
) -> str:
    """Build a human-readable signature from FLOW FEATURES ONLY.

    The label is not a parameter of this function. That is deliberate: it
    cannot leak into the signature by accident, and a future edit that wanted
    to leak it would have to change the signature of the function itself.

    The wording describes what the flow LOOKS like, never what it IS. A flow
    with many SYNs and no payload reads as "SYN-heavy, no payload" — an
    observation. Calling it "port scan" would be the label by another name.
    """
    duration_ms = flow_duration_us / 1000.0
    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes
    avg_packet = (total_bytes / total_packets) if total_packets else 0.0

    shape: list[str] = []

    if syn_flags >= 1 and total_bytes < 100:
        shape.append("SYN-heavy, minimal payload")
    if total_packets >= 1000:
        shape.append("high packet volume")
    elif total_packets <= 4:
        shape.append("very short exchange")
    if duration_ms > 0 and total_packets / max(duration_ms / 1000.0, 1e-6) > 500:
        shape.append("elevated packet rate")
    if bwd_packets == 0 and fwd_packets > 0:
        shape.append("unanswered")
    if psh_flags >= 1 and avg_packet > 400:
        shape.append("large pushed payload")
    if not shape:
        shape.append("nominal exchange")

    return (
        f"Flow to {protocol}/{dest_port} — {', '.join(shape)} "
        f"({total_packets:.0f} pkts, {total_bytes:.0f} bytes, {duration_ms:.0f} ms)"
    )


def protocol_name(number: int) -> str:
    return _PROTOCOL_BY_NUMBER.get(number, f"IP/{number}")


class MissingEndpointError(ValueError):
    """A CICIDS row arrived without the endpoint columns GLF supplies."""


def parse_cicids_row(
    row: dict[str, Any],
    *,
    timestamp: datetime,
    source: AlertSource = "cicids_replay",
) -> NormalizedAlert:
    """One cleaned GeneratedLabelledFlows row -> NormalizedAlert.

    `timestamp` is the ARRIVAL time the caller stamps — the moment the alert
    entered the feed. The row's own capture time (July 2017) is kept separately
    in `captured_at`. Both are true statements about different things: the
    frozen UI renders relative age and buckets event velocity off `timestamp`,
    and a 2017 date there would make every alert nine years old on screen.
    """
    row_id = str(row.get("row_id") or "")
    canonical = str(row.get("canonical_class") or "")

    def num(key: str) -> float:
        try:
            return float(row.get(key, 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    src_ip = str(row.get("Source IP") or "").strip()
    dest_ip = str(row.get("Destination IP") or "").strip()
    if not src_ip or not dest_ip:
        raise MissingEndpointError(
            f"row {row_id or '<unknown>'} has no Source IP / Destination IP. "
            "The partitions must be built from GeneratedLabelledFlows; "
            "MachineLearningCSV does not carry endpoints and nothing here "
            "invents them."
        )
    validate_ip(src_ip)
    validate_ip(dest_ip)

    dest_port = int(num("Destination Port"))
    protocol = protocol_name(int(num("Protocol")))

    signature = synthesize_signature(
        dest_port=dest_port,
        protocol=protocol,
        flow_duration_us=num("Flow Duration"),
        fwd_packets=num("Total Fwd Packets"),
        bwd_packets=num("Total Backward Packets"),
        fwd_bytes=num("Total Length of Fwd Packets"),
        bwd_bytes=num("Total Length of Bwd Packets"),
        syn_flags=num("SYN Flag Count"),
        psh_flags=num("PSH Flag Count"),
    )

    from app.ml.features import FEATURE_COLUMNS

    return NormalizedAlert(
        id=alert_id_from(row_id or str(row.get("Flow ID") or signature)),
        timestamp=timestamp,
        source=source,
        # PLAN I4/I5 — the PARSER DOES NOT PREDICT. Phase 2 stamped the
        # dataset's severity for the true class here as a placeholder; Phase 3
        # removed it. A parser that copies the ground-truth class onto the
        # rendered alert is a label leak with a plausible name on it, and the
        # graph would have had nothing to disagree with. Both fields stay
        # `unknown` until the classify node writes a real verdict.
        severity="unknown",
        attack_type="unknown",
        src_ip=src_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        signature=signature,
        ground_truth_class=canonical or None,
        row_id=row_id or None,
        captured_at=parse_captured_at(row.get("captured_at")),
        src_port=int(num("Source Port")) or None,
        flow_id=str(row.get("Flow ID") or "") or None,
        features={name: num(name) for name in FEATURE_COLUMNS},
    )


def parse_captured_at(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def validate_ip(value: str) -> str:
    ipaddress.ip_address(value)
    return value


def utcnow() -> datetime:
    return datetime.now(UTC)
