"""Shared graph-test scaffolding.

The graph is exercised END TO END with stubbed PROVIDERS, not stubbed nodes. The
routers, the trace decorator, the finalize backfill, the grounding and the rules
precedence are all the real ones — only the two things that would otherwise hit
the network are replaced. A test that stubbed the nodes would assert that the
stubs were called, which proves nothing about the pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.agent.state import PipelineState
from app.config import Settings
from app.providers.base import LLMResult, ProviderError
from app.providers.keypool import KeyPool
from app.providers.registry import ProviderRegistry
from app.rag.retriever import Retrieved


@dataclass
class StubLLM:
    """Stands in for GroqClient / GeminiClient with the same `complete` shape."""

    provider: str
    model: str
    payload: dict[str, Any] | None = None
    raw: str | None = None
    error: Exception | None = None
    prompt_tokens: int = 120
    completion_tokens: int = 40
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def complete(self, system: str, user: str, **_: Any) -> LLMResult:
        self.calls.append((system, user))
        if self.error is not None:
            raise self.error
        content = self.raw if self.raw is not None else json.dumps(self.payload or {})
        return LLMResult(
            provider=self.provider,
            model=self.model,
            key_id=f"{self.provider}-dev",
            content=content,
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
            duration_ms=12.5,
        )


@dataclass
class StubIntelVerdict:
    ip: str
    checked: bool = True
    score: int | None = None
    malicious: bool = False
    degraded: bool = False
    cached: bool = False
    results: list[Any] = field(default_factory=list)
    duration_ms: float = 5.0

    @property
    def sources_ok(self) -> list[str]:
        return ["abuseipdb", "virustotal"] if self.checked else []

    @property
    def sources_failed(self) -> list[str]:
        return ["virustotal"] if self.degraded else []

    def note(self) -> str:
        return "stubbed intel"


@dataclass
class StubAggregator:
    verdict: StubIntelVerdict | None = None
    lookups: list[str] = field(default_factory=list)

    async def lookup(self, ip: str) -> StubIntelVerdict:
        self.lookups.append(ip)
        return self.verdict or StubIntelVerdict(ip=ip, checked=True, score=0)

    @property
    def cache_stats(self) -> dict[str, int | float]:
        return {"entries": 0}


@dataclass
class StubRetriever:
    hits: list[Retrieved] = field(default_factory=list)
    chunk_count: int = 30
    dimensions: int = 384

    def search(self, _text: str, _top_k: int = 5) -> list[Retrieved]:
        return list(self.hits)


class StubClassifier:
    """Mimics FastTierClassifier.predict without loading a booster."""

    def __init__(
        self,
        attack_type: str = "dos",
        severity: str = "high",
        probability: float | None = 1.0,
        status: str = "ok",
        note: str | None = None,
    ) -> None:
        self.attack_type = attack_type
        self.severity = severity
        self.probability = probability
        self.status = status
        self.note = note
        self.model_version = "1.0.0"

    def predict(self, alert: Any) -> Any:
        from app.ml.classifier import Prediction

        skipped = alert.source != "cicids_replay"
        if skipped:
            return Prediction(
                attack_type="unknown",
                severity="unknown",
                probability=None,
                model_version=self.model_version,
                trace={
                    "stage": "classify",
                    "status": "skipped",
                    "provider": "lightgbm",
                    "model": self.model_version,
                    "reason": (
                        "source carries no CICIDS flow features; a zero-filled "
                        "vector would be a fabricated input (PLAN D25)"
                    ),
                },
            )
        return Prediction(
            attack_type=self.attack_type,
            severity=self.severity,
            probability=self.probability,
            model_version=self.model_version,
            trace={
                "stage": "classify",
                "status": self.status,
                "provider": "lightgbm",
                "model": self.model_version,
                **({"detail": self.note} if self.note else {}),
            },
        )


def stub_registry(
    settings: Settings, groq: StubLLM | None = None, gemini: StubLLM | None = None
) -> ProviderRegistry:
    pool_args = {"dev": "k-dev", "reserved": "k-reserved", "spare": "k-spare"}
    return ProviderRegistry(
        settings=settings,
        groq_pool=KeyPool("groq", pool_args, default_cooldown_seconds=60.0),
        gemini_pool=KeyPool("gemini", pool_args, default_cooldown_seconds=60.0),
        groq=groq or StubLLM("groq", "openai/gpt-oss-120b"),  # type: ignore[arg-type]
        gemini=gemini or StubLLM("gemini", "gemini-3.6-flash"),  # type: ignore[arg-type]
        offline=__import__(
            "app.providers.offline", fromlist=["OfflineProvider"]
        ).OfflineProvider(),
    )


def alert_stub(**overrides: Any) -> Any:
    """The attributes `initial_state` reads off a NormalizedAlert."""

    @dataclass
    class _Alert:
        id: str = "ALT-ABC123"
        source: str = "cicids_replay"
        signature: str = "Flow to TCP/80 — SYN-heavy, minimal payload (2 pkts, 0 bytes, 3 ms)"
        src_ip: str = "118.25.6.39"
        dest_ip: str = "192.168.10.50"
        dest_port: int = 80
        protocol: str = "TCP"
        features: dict[str, float] = field(default_factory=lambda: {"Destination Port": 80.0})
        severity: str = "unknown"
        attack_type: str = "unknown"
        confidence: float | None = None
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
        degraded: bool = False
        trace: list[dict[str, Any]] = field(default_factory=list)

    return _Alert(**overrides)


def trace_map(state: PipelineState) -> dict[str, Any]:
    return {entry.node: entry for entry in state.trace}


__all__ = [
    "ProviderError",
    "StubAggregator",
    "StubClassifier",
    "StubIntelVerdict",
    "StubLLM",
    "StubRetriever",
    "alert_stub",
    "stub_registry",
    "trace_map",
]
