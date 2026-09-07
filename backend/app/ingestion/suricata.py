"""Suricata EVE JSON reader.

PLAN §6.1: the EVE sample buys DEMO REALISM, not eval credibility. Every record
read here CARRIES NO GROUND-TRUTH LABEL — Suricata reports which rule fired,
which is a static per-rule prior, not the contextual per-instance verdict the
pipeline produces. PLAN I15 (extended): a `suricata_sample` or `live_demo` row
must never enter the eval set or the training set.

PLAN D25: EVE records have a signature and a 5-tuple but none of the 77 CICIDS
flow features, so the LightGBM tier cannot score them. They route straight to
the LLM with an explicit `skipped` trace entry naming the reason — Phase 3
wires that; this module only guarantees `features` stays empty so the skip is
forced rather than optional.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.ingestion.normalize import AlertSource, NormalizedAlert, alert_id_from

# Suricata's own severity is 1 (most severe) to 4. It is a static per-rule
# prior; the pipeline's severity is a per-instance posterior. Mapped so the
# feed renders, and overwritten by the graph in Phase 3.
_SURICATA_SEVERITY: dict[int, str] = {1: "high", 2: "medium", 3: "low", 4: "low"}


class EveParseError(ValueError):
    pass


def _parse_timestamp(raw: str) -> datetime:
    # Suricata emits ISO-8601 with a numeric offset and microseconds.
    value = datetime.fromisoformat(raw)
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def parse_eve_record(
    record: dict[str, Any], *, source: AlertSource = "suricata_sample"
) -> NormalizedAlert | None:
    """One EVE record -> NormalizedAlert, or None if it is not an alert.

    Non-alert event types (flow, dns, http, stats) are the majority of an
    eve.json and are skipped by the caller, which counts them rather than
    discarding them silently (PLAN T13).
    """
    if record.get("event_type") != "alert":
        return None

    alert = record.get("alert") or {}
    signature = str(alert.get("signature") or "").strip()
    if not signature:
        raise EveParseError("alert record has no alert.signature")

    src_ip = str(record.get("src_ip") or "").strip()
    dest_ip = str(record.get("dest_ip") or "").strip()
    if not src_ip or not dest_ip:
        raise EveParseError("alert record missing src_ip/dest_ip")

    timestamp = _parse_timestamp(str(record["timestamp"]))
    dest_port = int(record.get("dest_port") or 0)
    signature_id = alert.get("signature_id")

    seed = f"{signature_id}:{src_ip}:{dest_ip}:{dest_port}:{record['timestamp']}"

    return NormalizedAlert(
        id=alert_id_from(seed),
        timestamp=timestamp,
        source=source,
        severity=_SURICATA_SEVERITY.get(int(alert.get("severity") or 3), "unknown"),
        # The rule category is Suricata's own classification, not a canonical
        # class of ours and not a ground truth. Phase 3's graph produces the
        # real attack_type; until then it is carried through as-is.
        attack_type=str(alert.get("category") or "unknown").lower().replace(" ", "_"),
        src_ip=src_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=str(record.get("proto") or "TCP").upper(),
        # Real ET signature text. Unlike the CICIDS path this is NOT synthesized
        # and NOT derived from a label, because there is no label.
        signature=signature,
        ground_truth_class=None,  # PLAN §6.1 — no labels, ever
        features={},  # PLAN D25 — forces the ML-tier skip
    )


def read_eve_file(
    path: Path, *, source: AlertSource = "suricata_sample"
) -> Iterator[NormalizedAlert]:
    """Stream alerts from an eve.json. Malformed lines are counted by the caller."""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EveParseError(f"{path.name}: malformed JSON line") from exc
            parsed = parse_eve_record(record, source=source)
            if parsed is not None:
                yield parsed
