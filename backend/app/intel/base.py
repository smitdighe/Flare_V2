"""Threat-intel contract. PLAN Part D / T11 / I7.

T11 IS THE RULE THAT SHAPES THIS MODULE. The prior codebase built a VirusTotal
query by taking `md5(signature)` and calling the file-hash endpoint. That hash
corresponds to no file that has ever existed, so the lookup was a guaranteed
404, and the 404 was rendered to the analyst as a verdict. Here:

  * NOTHING IS EVER SYNTHESIZED INTO A LOOKUP KEY. Only observed values are
    queried, and the only observed value an alert reliably carries is the
    source IP.
  * `vt_hash` therefore stays NULL. It is a real field with no real producer on
    this data path, and a null is the honest value for it (I12 is about fields
    the pipeline claims to fill; this one it does not claim).

A source that fails is `IntelResult(status="error")`, which is a first-class
DEGRADED outcome: it is visible in the trace, it makes `degraded=True` on the
aggregate, and it is NOT cached.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

IntelStatus = Literal["ok", "error", "rate_limited", "skipped"]


@dataclass(frozen=True)
class IntelResult:
    """One source's verdict on one IP."""

    source: str
    status: IntelStatus
    # 0-100, normalized across sources so `max()` is meaningful. None whenever
    # status is not "ok" — a failed lookup has no score, and defaulting it to 0
    # would render "we could not check" as "clean".
    score: int | None = None
    malicious: bool = False
    detail: str | None = None
    duration_ms: float = 0.0

    @property
    def usable(self) -> bool:
        return self.status == "ok" and self.score is not None


def external_endpoint(src_ip: str, dest_ip: str) -> tuple[str, str] | None:
    """Which end of this flow is worth a reputation lookup, and which end it is.

    Returns `(ip, role)` where role is `"source"` or `"destination"`, or None
    when both ends are internal.

    **SOURCE FIRST, THEN DESTINATION.** Checking only the source looked right
    and was wrong on the most interesting traffic in the dataset: a botnet
    beacon runs from an INTERNAL compromised host OUTBOUND to the C2, so the
    source is RFC1918 and the address actually worth asking about is the
    destination. CICIDS2017's C2 is 205.174.165.73 and a source-only lookup
    never asks about it once.

    Source keeps priority because an inbound attack is the more common shape and
    the attacker is the source there. The role travels with the answer so the
    trace can say WHICH end was checked — "reputation 92" means very different
    things about an inbound source and an outbound destination.
    """
    if is_public_ip(src_ip):
        return src_ip, "source"
    if is_public_ip(dest_ip):
        return dest_ip, "destination"
    return None


def is_public_ip(value: str) -> bool:
    """Private, loopback, link-local and reserved space is not worth a quota unit.

    CICIDS2017 is a lab capture, so most source addresses are RFC1918. Querying
    them would spend the daily allowance on addresses no intel source has ever
    seen, and get back a uniform "no data" that says nothing.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )
