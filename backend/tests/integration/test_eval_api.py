"""GET /eval. CONTRACT §2.4 / PLAN E6 / E10.

The screen reads eleven required fields and recomputes the misclassified list
client-side from a twelfth. A missing key renders as an empty state forever
(PLAN I12), so the contract shape is asserted key by key rather than by spot
check.
"""

from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient

from app.eval import cache
from tests.conftest import auth_header, login, make_user

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"
HAVE_SPLITS = (SPLITS / "eval.csv").exists()

REQUIRED_FIELDS = (
    "sample_size",
    "severity_accuracy",
    "attack_type_accuracy",
    "avg_latency_ms",
    "high_severity_precision",
    "high_severity_recall",
    "high_severity_f1",
    "confusion_matrix",
    "attack_type_breakdown",
    "rows",
    "misclassified_count",
)


def _small_run(monkeypatch):
    """Shrink the run for a test without touching the shipped defaults.

    The route reads `get_settings()`, so the override goes there rather than on
    the settings object — a pydantic field is not a class attribute and cannot
    be patched in place.
    """
    from app.config import get_settings
    from app.ml.classifier import load_classifier

    load_classifier()
    small = get_settings().model_copy(
        update={"eval_sample_size": 12, "eval_score_full_partition": False}
    )
    monkeypatch.setattr("app.api.routes.eval.get_settings", lambda: small)
    return small


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Never read or write the committed run from a test."""
    monkeypatch.setattr(cache, "CACHE_PATH", tmp_path / "latest.json")
    yield


def payload() -> dict[str, Any]:
    return {
        "sample_size": 80,
        "severity_accuracy": 0.99,
        "attack_type_accuracy": 0.99,
        "avg_latency_ms": 12.5,
        "high_severity_precision": 1.0,
        "high_severity_recall": 0.98,
        "high_severity_f1": 0.99,
        "confusion_matrix": {
            "labels": ["critical", "high", "medium", "low"],
            "matrix": [[13, 0, 0, 0], [0, 40, 0, 0], [0, 0, 13, 0], [0, 0, 0, 14]],
        },
        "attack_type_breakdown": {
            "benign": {"correct": 13, "true_count": 14, "accuracy": 0.928571}
        },
        "rows": [],
        "misclassified_count": 0,
        "unscored_count": 0,
        "guards": [],
        "guards_tripped": [],
        # `cache.write` refuses a payload without these — they are what
        # distinguishes a real run from a hand-built dict.
        "tiers": {},
        "partition": {"seed": 20260904, "exact_feature_overlap_with_train": 0},
        "usage": {"calls_attempted": 0, "success_rate": None},
        "run_notice": "fixture",
        "generated_at": "2026-09-05T00:00:00+00:00",
    }


async def test_eval_requires_authentication(client: AsyncClient):
    assert (await client.get("/api/v1/eval")).status_code == 401


async def test_a_cached_run_is_served_and_says_it_is_cached(client: AsyncClient):
    """PLAN §19 step 8 — the panel must not wait on a provider under pressure."""
    cache.write(payload())
    await make_user("eval@example.com")
    token = await login(client, "eval@example.com")

    response = await client.get("/api/v1/eval", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    data = body["data"]
    assert data["cached"] is True
    assert data["generated_at"] == "2026-09-05T00:00:00+00:00"


async def test_the_cached_payload_carries_every_field_the_screen_reads(
    client: AsyncClient,
):
    cache.write(payload())
    await make_user("fields@example.com")
    token = await login(client, "fields@example.com")

    data = (
        await client.get("/api/v1/eval", headers=auth_header(token))
    ).json()["data"]

    for field in REQUIRED_FIELDS:
        assert field in data, field
    assert data["confusion_matrix"]["labels"] == ["critical", "high", "medium", "low"]
    assert len(data["confusion_matrix"]["matrix"]) == 4
    assert all(len(row) == 4 for row in data["confusion_matrix"]["matrix"])


async def test_a_corrupt_cache_does_not_serve_garbage(client: AsyncClient):
    cache.CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cache.CACHE_PATH.write_text("{not json", encoding="utf-8")

    assert cache.read() is None


@pytest.mark.skipif(not HAVE_SPLITS, reason="partitions not built in this checkout")
async def test_a_forced_run_scores_live_and_replaces_the_cache(
    client: AsyncClient, monkeypatch
):
    """`?force=true` is the Refresh button, and the only thing that re-runs.

    Offline in the test environment, so no provider is called: the LLM tier
    scores nothing and says so, which is exactly PLAN E9's requirement that a
    deterministic run announce itself rather than pass as a measurement.
    """
    settings = _small_run(monkeypatch)

    await make_user("forced@example.com")
    token = await login(client, "forced@example.com")

    response = await client.get(
        "/api/v1/eval?force=true", headers=auth_header(token)
    )

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["cached"] is False
    assert data["sample_size"] == 12
    assert data["offline"] is True

    # PLAN E9 — the warning is on the payload AND in the notice.
    assert "OFFLINE MODE" in data["run_notice"]

    # PLAN E14/E15 — three blocks, scored on the same rows.
    assert set(data["tiers"]) >= {"lightgbm", "llm", "system"}
    for tier in ("lightgbm", "llm", "system"):
        assert data["tiers"][tier]["sample_size"] == 12

    # PLAN E12 — all three baselines, on the payload.
    baselines = data["baselines"]
    assert baselines["random"] == pytest.approx(1 / 6, abs=1e-4)
    assert 0.0 <= baselines["majority_class"] <= 1.0
    assert baselines["nearest_neighbour_1nn"] is not None

    # PLAN E17 — the escalation rate travels with the headline.
    assert 0.0 <= data["escalation"]["rate"] <= 1.0
    assert data["escalation"]["threshold"] == settings.escalation_confidence_threshold

    # PLAN §7.3b — disjointness verified at the feature vector, on these rows.
    assert data["partition"]["exact_feature_overlap_with_train"] == 0

    # The forced run replaced the cache, and the next unforced call serves it.
    again = (await client.get("/api/v1/eval", headers=auth_header(token))).json()[
        "data"
    ]
    assert again["cached"] is True
    assert again["sample_size"] == 12


@pytest.mark.skipif(not HAVE_SPLITS, reason="partitions not built in this checkout")
async def test_the_misclassified_list_and_its_count_use_one_definition(
    client: AsyncClient, monkeypatch
):
    """CONTRACT §2.4 — the header count and the list must not disagree.

    The frontend recomputes the list from `rows` with its own expression and
    reads the count from `misclassified_count`. If the backend's definition
    differs, the screen shows a count that does not match what it lists.
    """
    _small_run(monkeypatch)

    await make_user("counts@example.com")
    token = await login(client, "counts@example.com")
    data = (
        await client.get("/api/v1/eval?force=true", headers=auth_header(token))
    ).json()["data"]

    client_side = [
        row
        for row in data["rows"]
        if row["pred_severity"] != row["true_severity"]
        or row["pred_attack_type"] != row["true_attack_type"]
    ]
    assert len(client_side) == data["misclassified_count"] == len(data["rows"])
    # PLAN I13 — a failed row is counted separately, never listed as a
    # misclassification with `unknown` in it.
    assert all(row["pred_severity"] != "unknown" for row in data["rows"])


def test_the_cache_refuses_a_payload_no_run_produced():
    """A test fixture once reached the shipped cache. Never again.

    `read`/`write` bound the module constant as a DEFAULT ARGUMENT, so patching
    the attribute did not redirect them and a synthetic payload was written over
    the real run. The binding is fixed; this asserts the second lock.
    """
    with pytest.raises(cache.NotAMeasurementError, match="tiers"):
        cache.write({"sample_size": 80, "attack_type_accuracy": 1.0})
