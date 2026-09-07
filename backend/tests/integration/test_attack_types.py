"""GET /alerts/attack-types — the FE-11 filter-options endpoint."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import AsyncClient

from app.ingestion.labels import CANONICAL_CLASSES
from tests.conftest import auth_header, login, make_user

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"

needs_data = pytest.mark.skipif(
    not (SPLITS / "MANIFEST.json").exists(), reason="partitions not built"
)


@needs_data
async def test_returns_the_classes_present_in_the_data(client: AsyncClient) -> None:
    await make_user(email="viewer-types@flare.dev", password="pw-viewer-types-1")
    token = await login(client, "viewer-types@flare.dev", "pw-viewer-types-1")

    response = await client.get("/api/v1/alerts/attack-types", headers=auth_header(token))
    assert response.status_code == 200

    body = response.json()
    assert body["ok"] is True

    manifest = json.loads((SPLITS / "MANIFEST.json").read_text(encoding="utf-8"))
    values = [t["value"] for t in body["data"]["attack_types"]]

    assert values == manifest["canonical_classes"], (
        "the endpoint must mirror the built partitions, not a second hardcoded list"
    )
    for name in values:
        for partition in manifest["partition_class_counts"].values():
            assert partition.get(name, 0) > 0, f"{name} is offered but absent from a partition"


@needs_data
async def test_offers_no_class_that_matches_nothing(client: AsyncClient) -> None:
    """The defect FE-11 exists to fix.

    FilterStrip.jsx hardcoded sql_injection, brute_force, malware and other —
    none of which any alert can carry — while omitting benign, dos, botnet and
    web_attack, which every alert can.
    """
    await make_user(email="viewer-dead@flare.dev", password="pw-viewer-dead-1")
    token = await login(client, "viewer-dead@flare.dev", "pw-viewer-dead-1")

    response = await client.get("/api/v1/alerts/attack-types", headers=auth_header(token))
    values = {t["value"] for t in response.json()["data"]["attack_types"]}

    assert values <= set(CANONICAL_CLASSES)
    assert not (values & {"sql_injection", "brute_force", "malware", "other"})
    assert {"benign", "dos", "botnet", "web_attack"} <= values


@needs_data
async def test_every_option_carries_a_label_and_a_severity(client: AsyncClient) -> None:
    await make_user(email="viewer-lbl@flare.dev", password="pw-viewer-lbl-1")
    token = await login(client, "viewer-lbl@flare.dev", "pw-viewer-lbl-1")

    response = await client.get("/api/v1/alerts/attack-types", headers=auth_header(token))
    options = response.json()["data"]["attack_types"]

    assert options
    for option in options:
        assert option["label"] == option["value"].replace("_", " ").upper()
        assert option["severity"] in {"low", "medium", "high", "critical"}


@needs_data
async def test_excluded_classes_are_reported_not_hidden(client: AsyncClient) -> None:
    """Heartbleed has 11 flows in the whole capture. Saying so is the honest move."""
    await make_user(email="viewer-exc@flare.dev", password="pw-viewer-exc-1")
    token = await login(client, "viewer-exc@flare.dev", "pw-viewer-exc-1")

    response = await client.get("/api/v1/alerts/attack-types", headers=auth_header(token))
    excluded = response.json()["data"]["excluded"]

    assert "heartbleed" in excluded
    assert excluded["heartbleed"]["rows_available"] == 11
    assert excluded["heartbleed"]["reason"]


async def test_requires_authentication(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/alerts/attack-types")).status_code == 401
