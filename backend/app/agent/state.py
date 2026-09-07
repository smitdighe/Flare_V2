"""Typed graph state. PLAN §4.2 / I1 / CONTRACT §8.3.

TWO RULES SHAPE THIS FILE.

**No untyped dicts.** Every field a node writes is declared here with a type. A
`dict[str, Any]` state is how a field named in the API contract quietly stops
having a producer (I12) — nothing fails, the key is just never set, and the
screen renders its empty state forever.

**No `{**state, **result}` clobber merges.** Each node returns ONLY the fields it
owns, and LangGraph applies them per channel. A node that returned the whole
state would overwrite a sibling's write with a stale copy, and the bug would be
invisible because the shape stays correct. `trace` and `errors` carry
`operator.add` reducers so appends compose instead of replacing.

The config values the routers read are SNAPSHOTTED into state at run start
(`severity_floor`, `confidence_threshold`, `intel_escalation_score`). That is
what makes the routers pure `state -> str` functions with no external read at
all — they can be unit-tested by constructing a state and calling them, which is
what Part A asks for.
"""

from __future__ import annotations

import operator
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class NodeName(StrEnum):
    """CONTRACT §8.3 — these seven, in this order, and no others."""

    CLASSIFY = "classify"
    ENRICH = "enrich"
    RETRIEVE = "retrieve"
    REASON = "reason"
    RECOMMEND = "recommend"
    RULES = "rules"
    FINALIZE = "finalize"


PIPELINE_ORDER: tuple[str, ...] = tuple(node.value for node in NodeName)


class TraceStatus(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"


class TokenUsage(BaseModel):
    prompt: int = 0
    completion: int = 0


class TraceNode(BaseModel):
    """One node, one invocation. CONTRACT §8.3.

    `provider` / `model` / `model_version` are I16: every verdict is attributable
    to the artifact that produced it. `key_id` is a LABEL — `"groq-reserved"` —
    and raw key material never reaches this object (I16).
    """

    model_config = ConfigDict(extra="forbid")

    node: str
    status: TraceStatus
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    duration_ms: float | None = None
    tokens: TokenUsage | None = None
    note: str | None = None
    key_id: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "node": self.node,
            "status": self.status.value,
            "provider": self.provider,
            "model": self.model,
            "model_version": self.model_version,
            "duration_ms": self.duration_ms,
            "tokens": (
                {"prompt": self.tokens.prompt, "completion": self.tokens.completion}
                if self.tokens
                else None
            ),
            "note": self.note,
            "key_id": self.key_id,
        }


class RetrievedTechnique(BaseModel):
    technique_id: str
    name: str
    section: str
    score: float


class RuleOutcome(BaseModel):
    rule_id: str
    rule_name: str
    fired: bool
    action: str | None = None
    from_severity: str | None = None
    to_severity: str | None = None


class PipelineState(BaseModel):
    """Everything the graph reads or writes for one alert."""

    model_config = ConfigDict(extra="forbid", validate_assignment=False)

    # -- inputs, written once before the graph runs ------------------------
    alert_id: str
    source: str
    signature: str
    src_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    features: dict[str, float] = Field(default_factory=dict)

    # -- config snapshot, so routers stay pure -----------------------------
    severity_floor: str = "high"
    confidence_threshold: float = 0.99
    intel_escalation_score: int = 50
    retrieval_low_confidence_score: float = 0.45
    offline_mode: bool = False

    # -- classify ----------------------------------------------------------
    attack_type: str = "unknown"
    severity: str = "unknown"
    confidence: float | None = None
    model_version: str | None = None
    ml_attack_type: str | None = None
    ml_severity: str | None = None
    ml_confidence: float | None = None
    classification_escalated: bool = False
    classification_escalation_reason: str | None = None

    # -- enrich ------------------------------------------------------------
    ioc_checked: bool = False
    ioc_reputation: int | None = None
    vt_ip: str | None = None
    # PLAN T11 — stays None on every alert. Nothing here synthesizes a file
    # hash to query VirusTotal with; the field has no honest producer on flow
    # data and a null is the truthful value.
    vt_hash: str | None = None
    intel_malicious: bool = False
    intel_escalated: bool = False
    intel_escalation_note: str | None = None
    reclassify_requested: bool = False

    # -- reasoning admission, decided in enrich, READ by route_after_enrich --
    reason_budget_available: bool = True
    reason_skip_reason: str | None = None

    # -- retrieve ----------------------------------------------------------
    retrieved: list[RetrievedTechnique] = Field(default_factory=list)
    mitre_technique: str | None = None
    retrieval_low_confidence: bool = False

    # -- reason / recommend ------------------------------------------------
    explanation: str | None = None
    remediation: str | None = None

    # -- rules -------------------------------------------------------------
    rule_outcomes: list[RuleOutcome] = Field(default_factory=list)
    rules_overrode: bool = False
    # PLAN §4.1 Phase 4 — the `add_tag` action needs somewhere real to land, and
    # the drawer needs the per-condition fire trace as it was AT TRIAGE TIME.
    tags: list[str] = Field(default_factory=list)
    rule_trace: list[dict[str, Any]] = Field(default_factory=list)

    # -- timings and status ------------------------------------------------
    classify_latency_ms: float | None = None
    enrich_latency_ms: float | None = None
    reasoning_latency_ms: float | None = None
    degraded: bool = False
    budget_exhausted: bool = False

    # -- reducers ----------------------------------------------------------
    # operator.add so a node's append composes with what is already there.
    # Assignment semantics here would silently discard every earlier entry and
    # I1 would fail in a way no test that only checks the LAST node would see.
    trace: Annotated[list[TraceNode], operator.add] = Field(default_factory=list)
    errors: Annotated[list[str], operator.add] = Field(default_factory=list)
    visited: Annotated[list[str], operator.add] = Field(default_factory=list)

    # -- helpers -----------------------------------------------------------

    def ran(self, node: str) -> bool:
        return node in self.visited

    def trace_for(self, node: str) -> TraceNode | None:
        for entry in self.trace:
            if entry.node == node:
                return entry
        return None


RouteAfterClassify = Literal["enrich", "retrieve"]
RouteAfterEnrich = Literal["retrieve", "recommend"]
RouteAfterReason = Literal["recommend", "rules"]
