"""Verify the pinned provider model IDs against the live APIs. PLAN D31 / T3.

D28 and D30 pinned DISPLAY NAMES. A display name is not an API ID, and a
retired ID does not fail loudly — it 404s and the caller degrades to template
text that is indistinguishable from real model output. That is T3, and it is a
demo-day failure, not a build-time one.

Two things this script does that reading the docs cannot:

  1. It lists what THIS ACCOUNT'S KEY can see, which is not the same as what
     the docs advertise.
  2. It ISSUES A REAL CALL to every pinned ID. `gemini-2.5-flash` is listed by
     the models endpoint and 404s on generateContent with "no longer available
     to new users" — so a listing is not evidence a model is callable. Only a
     call is.

Run it before a rehearsal and before demo day. It spends a handful of tokens on
the `dev` key by design; that is what the dev key is for (D26).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]

GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models"
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"

PROBE = 'Reply with JSON only: {"ok": true}'


def load_env() -> None:
    """Read backend/.env without pulling pydantic-settings into a script."""
    path = REPO_ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _non_200(
    model_id: str, listed: bool, status: int, text: str, elapsed_ms: int
) -> dict[str, Any]:
    """A failed probe, with the ONE distinction this script exists to draw.

    A 429 means the KEY is spent, and says nothing about whether the model ID
    is real — that is a quota fact, not a T3 fact. A 404 means the ID does not
    resolve for this account, which IS T3 and is a ship blocker. Collapsing
    them would make an exhausted dev key look like a retired model and send
    someone chasing a config change that fixes nothing.
    """
    return {
        "model": model_id,
        "listed": listed,
        "callable": False,
        # `blocking` is what the exit code reads. A spent key is not a blocker.
        "blocking": status != 429,
        "status": status,
        "latency_ms": elapsed_ms,
        "detail": text[:240],
    }


def check_groq(model_id: str, key: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    listing = httpx.get(GROQ_MODELS_URL, headers=headers, timeout=30)
    listed = False
    if listing.status_code == 200:
        listed = any(m["id"] == model_id for m in listing.json().get("data", []))

    started = time.perf_counter()
    response = httpx.post(
        GROQ_CHAT_URL,
        headers=headers,
        json={
            "model": model_id,
            "messages": [{"role": "user", "content": PROBE}],
            "temperature": 0,
            "max_completion_tokens": 64,
            "response_format": {"type": "json_object"},
            # PLAN D29 — route the final answer into `content` explicitly
            # rather than trusting the default. A reasoning model that puts its
            # answer in a sibling channel returns 200 with empty content, and a
            # 200 is not a success (I18).
            "reasoning_format": "hidden",
            "reasoning_effort": "low",
        },
        timeout=60,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000)

    if response.status_code != 200:
        return _non_200(model_id, listed, response.status_code, response.text, elapsed_ms)

    body = response.json()
    message = body["choices"][0]["message"]
    content = (message.get("content") or "").strip()
    usage = body.get("usage") or {}
    return {
        "model": model_id,
        "listed": listed,
        "callable": bool(content),
        "status": 200,
        "latency_ms": elapsed_ms,
        "content_populated": bool(content),
        "separate_reasoning_channel": "reasoning" in message,
        "usage_fields": {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
        },
    }


def check_gemini(model_id: str, key: str, thinking_level: str) -> dict[str, Any]:
    headers = {"x-goog-api-key": key, "Content-Type": "application/json"}

    listing = httpx.get(
        f"{GEMINI_BASE}/models", headers=headers, params={"pageSize": 200}, timeout=30
    )
    listed = False
    if listing.status_code == 200:
        listed = any(
            m["name"] == f"models/{model_id}" for m in listing.json().get("models", [])
        )

    started = time.perf_counter()
    response = httpx.post(
        f"{GEMINI_BASE}/models/{model_id}:generateContent",
        headers=headers,
        json={
            "contents": [{"role": "user", "parts": [{"text": PROBE}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "maxOutputTokens": 64,
                # PLAN D30 — thinking level and timeout are set as a pair.
                "thinkingConfig": {"thinkingLevel": thinking_level},
            },
        },
        timeout=90,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000)

    if response.status_code != 200:
        return _non_200(model_id, listed, response.status_code, response.text, elapsed_ms)

    body = response.json()
    parts = body.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    content = "".join(p.get("text", "") for p in parts).strip()
    usage = body.get("usageMetadata") or {}
    return {
        "model": model_id,
        "listed": listed,
        "callable": bool(content),
        "status": 200,
        "latency_ms": elapsed_ms,
        "thinking_level": thinking_level,
        "content_populated": bool(content),
        "usage_fields": {
            "prompt_tokens": usage.get("promptTokenCount"),
            "completion_tokens": usage.get("candidatesTokenCount"),
            "thoughts_tokens": usage.get("thoughtsTokenCount", 0),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    load_env()
    from app.config import get_settings

    settings = get_settings()

    groq_key = settings.groq_api_key_dev
    gemini_key = settings.gemini_api_key_dev
    if not groq_key or not gemini_key:
        print("GROQ_API_KEY_DEV and GEMINI_API_KEY_DEV must be set to verify.")
        return 2

    results = [
        check_groq(settings.groq_model_primary, groq_key),
        check_groq(settings.groq_model_fallback, groq_key),
        check_gemini(
            settings.gemini_model, gemini_key, settings.gemini_thinking_level
        ),
    ]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            if row["callable"]:
                mark = "OK"
            elif row.get("blocking"):
                mark = "FAIL"
            else:
                mark = "QUOTA"
            print(
                f"{mark:<5} {row['model']:<24} listed={row['listed']!s:<5} "
                f"status={row['status']} {row['latency_ms']:>6}ms"
            )
            if not row["callable"]:
                print(f"       {row.get('detail', 'empty content — a 200 is not a success')}")

    spent = [r for r in results if not r["callable"] and not r.get("blocking")]
    if spent:
        print(
            f"\n{len(spent)} model(s) could not be probed because the DEV KEY is rate "
            "limited. That is a quota fact, not a model-ID fact — the dev key is "
            "expected to burn (D26). Re-run later, or probe with a reserved key."
        )

    blocking = [r for r in results if not r["callable"] and r.get("blocking")]
    if blocking:
        print(
            f"\n{len(blocking)} pinned model ID(s) are NOT CALLABLE. Do not ship this "
            "configuration — a retired ID degrades silently to template text (T3).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
