"""retrieve — MiniLM embeddings, numpy cosine, committed index. PLAN §4.4 / D3.

Local CPU inference through ONNX. No API call, no vector database, no network:
retrieval costs nothing in quota, which is why it sits in front of the only
stage that does.

**A KNOWN LIMITATION IS SURFACED, NOT PAPERED OVER.** `web_attack` retrieves
T1505.003 (Web Shell) above T1110 (Brute Force) because a credential-stuffing
flow and a web-shell flow have the same shape in CICFlowMeter columns — the
distinguishing evidence is in the HTTP payload, which this dataset does not
carry. Rather than hand-mapping the class to the "right" technique, the trace
records the score and flags a weak match. A confident-looking answer with no
evidence behind it is worse than a flagged uncertain one.

`asyncio.to_thread` because ONNX inference is a synchronous C call that holds
the thread for its duration (I6, T5). Milliseconds each, but at the configured
replay rate that is milliseconds stolen from every other coroutine on the loop.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.agent.state import NodeName, PipelineState, RetrievedTechnique, TraceStatus
from app.agent.trace import TraceBuilder, traced
from app.rag.retriever import build_query, get_retriever


@traced(NodeName.RETRIEVE)
async def retrieve_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    retriever = get_retriever()

    # PLAN I4 — the CLASSIFIER's verdict builds the query, never the label.
    # `build_query` is shared with scripts/eval_retrieval.py so the measured
    # recall@k describes this exact path.
    query = build_query(state.attack_type, state.signature, state.dest_port)

    hits = await asyncio.to_thread(retriever.search, query, state_top_k(state))
    retrieved = [
        RetrievedTechnique(
            technique_id=hit.technique_id,
            name=hit.name,
            section=hit.section,
            score=hit.score,
        )
        for hit in hits
    ]

    top = retrieved[0] if retrieved else None
    low_confidence = bool(top and top.score < state.retrieval_low_confidence_score)

    if top is None:
        trace.record(
            TraceStatus.SKIPPED,
            provider="minilm-onnx",
            model=f"all-MiniLM-L6-v2 ({retriever.dimensions}d)",
            note="the index returned no chunk for this query",
        )
        return {"retrieved": [], "mitre_technique": None}

    note = (
        f"top {len(retrieved)} of {retriever.chunk_count} chunks; best "
        f"{top.technique_id} at cosine {top.score:.3f}"
    )
    if low_confidence:
        note += (
            f" — BELOW the {state.retrieval_low_confidence_score} confidence "
            "line, so this is a weak match and is reported as one rather than "
            "presented as a confident mapping"
        )
    if state.attack_type == "web_attack":
        note += (
            " | known limitation: web-attack flows retrieve T1505.003 over "
            "T1110 because credential stuffing and a web shell have identical "
            "CICFlowMeter shapes; the distinguishing evidence is in the HTTP "
            "payload, which this dataset does not carry"
        )

    trace.record(
        TraceStatus.OK,
        provider="minilm-onnx",
        model=f"all-MiniLM-L6-v2 ({retriever.dimensions}d)",
        note=note,
    )
    return {
        "retrieved": retrieved,
        "mitre_technique": top.technique_id,
        "retrieval_low_confidence": low_confidence,
    }


def state_top_k(state: PipelineState) -> int:
    from app.config import get_settings

    return get_settings().retrieval_top_k
