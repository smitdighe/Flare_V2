"""Probe EVERY key in every pool, one real call each. PLAN D26 / D39 / I16.

`scripts/verify_models.py` answers "is this model ID callable?" and spends the
DEV key to do it. This answers a different question that no other check can:

    IS EACH INDIVIDUAL KEY ALIVE?

Nothing else in the system can tell you. Selection is sticky by design (D26), so
a healthy `dev` key means `reserved` and `spare` are never touched, and
`/health/deep` — which spends real quota on every call — deliberately probes only
ONE key per provider. A key that has never been called has never been rejected,
so it reports `dead=false` for exactly as long as nobody asks it anything. The
observed failure (D39) was a Gemini key answering 403 "project has been denied
access" on every call while the health screen showed three live keys.

THE COST IS THE POINT. One request per key, and `reserved` is supposed to be
untouched before demo day — so this is not a thing to run in a loop. Run it
after rotating credentials, before a rehearsal, and once on demo morning.

    python -m scripts.verify_keys
    python -m scripts.verify_keys --json
    python -m scripts.verify_keys --provider gemini

Exit codes: 0 all keys live · 1 at least one key is DEAD (a credential problem,
which only a human can fix) · 2 nothing to probe. A key that is merely RATE
LIMITED is not a failure — that is a quota fact about today, not a statement
about the credential, and conflating them would send someone to the console to
replace a working key.

I16 — key material is never printed, logged or returned. Labels only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]

GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"

PROBE_SYSTEM = "Reply with JSON only."
PROBE_USER = 'Return exactly {"ok": true}'

#: Big enough that a reasoning model can finish a JSON object. 16 is NOT: the
#: model runs, produces a fragment, and Groq answers 400 "Failed to validate
#: JSON" — which is a fact about the token budget being read as a fact about
#: the key.
PROBE_MAX_TOKENS = 128

LIVE, COOLING, DEAD, ERROR = "live", "cooling", "DEAD", "error"


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


def _classify(status: int, body: str, headers: Any) -> tuple[str, str] | None:
    """Map a non-200 onto the same three states the pool uses at runtime.

    Imported from `app.providers.base` rather than reimplemented so this script
    cannot drift from what the running system would decide about the same
    response — a preflight that disagrees with production is worse than none.
    """
    from app.providers.base import key_revocation_reason, retry_after_seconds

    if status == 429:
        after = retry_after_seconds(headers)
        # Google puts the real delay in the BODY, not the header, and a daily
        # quota arrives wearing the same 429 as a per-minute one. Surface the
        # quotaId when it is there — "20 per DAY per project" and "30 per
        # minute" call for completely different decisions.
        quota = ""
        try:
            for violation in json.loads(body)["error"]["details"]:
                if violation.get("@type", "").endswith("QuotaFailure"):
                    first = violation["violations"][0]
                    quota = (
                        f" quotaId={first.get('quotaId')} "
                        f"limit={first.get('quotaValue')}"
                    )
                    break
        except Exception:
            pass
        return COOLING, f"429 rate limited (retry_after={after}){quota}"

    revoked = key_revocation_reason(status, body)
    if revoked is not None:
        return DEAD, revoked
    if status != 200:
        return ERROR, f"HTTP {status}: {body[:160]}"
    return None


async def probe_groq(client: httpx.AsyncClient, label: str, secret: str, settings: Any) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = await client.post(
            GROQ_CHAT_URL,
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.groq_model_primary,
                "messages": [
                    {"role": "system", "content": PROBE_SYSTEM},
                    {"role": "user", "content": PROBE_USER},
                ],
                "temperature": 0,
                "max_completion_tokens": PROBE_MAX_TOKENS,
                "response_format": {"type": "json_object"},
                "reasoning_format": settings.groq_reasoning_format,
                "reasoning_effort": settings.groq_reasoning_effort,
            },
            timeout=settings.llm_timeout_seconds_groq,
        )
    except Exception as exc:
        return {"key_id": label, "state": ERROR, "detail": f"{type(exc).__name__}: {exc}"}

    elapsed = round((time.perf_counter() - started) * 1000)
    verdict = _classify(response.status_code, response.text, response.headers)
    if verdict is not None:
        state, detail = verdict
        return {"key_id": label, "state": state, "detail": detail, "latency_ms": elapsed}

    message = (response.json()["choices"][0].get("message")) or {}
    content = (message.get("content") or "").strip()
    if not content:
        # PLAN I18/D29 — a 200 carrying nothing is a failed call, not a live key.
        return {
            "key_id": label,
            "state": ERROR,
            "detail": "HTTP 200 with empty message.content (PLAN I18/D29)",
            "latency_ms": elapsed,
        }
    return {"key_id": label, "state": LIVE, "detail": content[:40], "latency_ms": elapsed}


async def probe_gemini(client: httpx.AsyncClient, label: str, secret: str, settings: Any) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = await client.post(
            f"{GEMINI_BASE}/models/{settings.gemini_model}:generateContent",
            headers={"x-goog-api-key": secret, "Content-Type": "application/json"},
            json={
                "systemInstruction": {"parts": [{"text": PROBE_SYSTEM}]},
                "contents": [{"role": "user", "parts": [{"text": PROBE_USER}]}],
                "generationConfig": {
                    "temperature": 0,
                    "responseMimeType": "application/json",
                    "maxOutputTokens": PROBE_MAX_TOKENS,
                    # PLAN D30 — probe at the level the app actually runs at.
                    "thinkingConfig": {"thinkingLevel": settings.gemini_thinking_level},
                },
            },
            timeout=settings.llm_timeout_seconds_gemini,
        )
    except Exception as exc:
        return {"key_id": label, "state": ERROR, "detail": f"{type(exc).__name__}: {exc}"}

    elapsed = round((time.perf_counter() - started) * 1000)
    verdict = _classify(response.status_code, response.text, response.headers)
    if verdict is not None:
        state, detail = verdict
        return {"key_id": label, "state": state, "detail": detail, "latency_ms": elapsed}

    body = response.json()
    candidates = body.get("candidates") or []
    parts = ((candidates[0].get("content") or {}).get("parts") or []) if candidates else []
    content = "".join(part.get("text", "") for part in parts).strip()
    if not content:
        return {
            "key_id": label,
            "state": ERROR,
            "detail": "HTTP 200 with no text parts (PLAN I18)",
            "latency_ms": elapsed,
        }
    return {"key_id": label, "state": LIVE, "detail": content[:40], "latency_ms": elapsed}


async def run(providers: tuple[str, ...]) -> list[dict[str, Any]]:
    from app.config import get_settings
    from app.providers.registry import build_registry

    settings = get_settings()
    registry = build_registry(settings)

    pools = {"groq": (registry.groq_pool, probe_groq),
             "gemini": (registry.gemini_pool, probe_gemini)}

    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient() as client:
        for name in providers:
            pool, probe = pools[name]
            # Sequential per provider on purpose: firing three keys at once
            # against one free tier can 429 keys that would each have answered
            # on their own, and report a healthy pool as cooling.
            for label, secret in pool.keys_for_probe():
                row = await probe(client, label, secret, settings)
                row["provider"] = name
                results.append(row)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--provider",
        choices=("groq", "gemini"),
        help="probe only this provider (default: both)",
    )
    args = parser.parse_args()

    load_env()
    providers = (args.provider,) if args.provider else ("groq", "gemini")

    from app.providers.keypool import EmptyPoolError

    try:
        results = asyncio.run(run(providers))
    except EmptyPoolError as exc:
        print(f"nothing to probe: {exc}", file=sys.stderr)
        return 2

    if not results:
        print("nothing to probe: no keys are configured.", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            print(
                f"{row['state']:<8} {row['key_id']:<18} "
                f"{str(row.get('latency_ms', '-')):>6}ms  {row['detail'][:180]}"
            )

    dead = [r for r in results if r["state"] == DEAD]
    cooling = [r for r in results if r["state"] == COOLING]
    errored = [r for r in results if r["state"] == ERROR]

    print(
        f"\n{sum(1 for r in results if r['state'] == LIVE)} live · "
        f"{len(cooling)} cooling · {len(dead)} dead · {len(errored)} error",
        file=sys.stderr,
    )
    if cooling:
        print(
            "Cooling is a QUOTA fact about today, not a broken credential. Check "
            "the quotaId above: a per-minute limit clears in a minute, a "
            "per-DAY-per-PROJECT limit does not, and keys sharing one project "
            "share one window no matter how many labels they have.",
            file=sys.stderr,
        )
    if dead:
        print(
            f"\n{len(dead)} key(s) are DEAD: "
            + ", ".join(r["key_id"] for r in dead)
            + ". This does not clear on its own — provision a replacement "
            "credential before the demo.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
