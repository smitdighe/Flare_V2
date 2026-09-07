"""One named test per hard invariant. PLAN §5 / §12.

**THE MAPPING IS THE POINT.** PLAN §5 says every invariant gets a test that
fails loudly if violated, and until now that was true in substance and
unauditable in form: the tests existed, scattered across a dozen files under
names that described a behaviour rather than an invariant, and nobody could
answer "which test is I13?" without reading all of them.

Every test here is named `test_I<n>_...`. `INVARIANT_COVERAGE` below maps each
invariant to the test that owns it, and `test_every_invariant_has_a_named_test`
parses PLAN §5 and fails the build if an invariant is added there without one.
That last test is what makes this file a contract instead of a snapshot.

I1, I4, I15 and I18 are the four that matter most (§12), and each of them gets
two tests here rather than one.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import re
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.invariant

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent

#: The names the ground truth travels under. `canonical_class` is the column in
#: the partition CSVs; the other two are the fields `EvalRow` holds it in. None
#: of them may appear on `PipelineState` or inside the classifier (I3/I4).
TRUTH_KEYS: tuple[str, ...] = (
    "canonical_class",
    "ground_truth_class",
    "true_attack_type",
    "true_severity",
)


# ---------------------------------------------------------------------------
# the map — every invariant, and where its named test lives
# ---------------------------------------------------------------------------

_HERE = "tests/invariants/test_invariants.py::"

#: I -> (one-line statement, the test that owns it).
INVARIANT_COVERAGE: dict[str, tuple[str, str]] = {
    "I1": (
        "No stage is silently skipped — exactly one trace entry per node, always.",
        _HERE + "test_I1_one_trace_entry_per_node_always",
    ),
    "I2": (
        "No hardcoded metric. Every rendered number is computed from real data.",
        _HERE + "test_I2_no_hardcoded_metric_literals",
    ),
    "I3": (
        "No self-scoring. The answer key and the classifier share no code path.",
        _HERE + "test_I3_the_answer_key_is_not_the_classifier",
    ),
    "I4": (
        "No label leak. The ground-truth label never reaches any prompt.",
        _HERE + "test_I4_the_label_cannot_reach_a_prompt",
    ),
    "I5": (
        "No deterministic fast path posing as inference; a skip is labelled.",
        _HERE + "test_I5_a_skipped_tier_is_labelled_in_the_trace",
    ),
    "I6": (
        "No blocking call on the event loop.",
        _HERE + "test_I6_no_blocking_call_on_the_event_loop",
    ),
    "I7": (
        "No LLM or HTTP call without a timeout.",
        _HERE + "test_I7_every_outbound_client_carries_a_timeout",
    ),
    "I8": (
        "No route claims a role it does not enforce.",
        _HERE + "test_I8_every_role_gated_route_enforces_its_role",
    ),
    "I9": (
        "No mock or seeded fake data in any environment.",
        _HERE + "test_I9_no_seeded_fake_data_anywhere",
    ),
    "I10": (
        "pytest cannot touch the runtime database.",
        _HERE + "test_I10_pytest_cannot_touch_the_runtime_database",
    ),
    "I11": (
        "Every README claim is backed by a passing test.",
        _HERE + "test_I11_readme_claims_point_at_real_artifacts",
    ),
    "I12": (
        "Every rendered field has a producer.",
        _HERE + "test_I12_every_rendered_field_has_a_producer",
    ),
    "I13": (
        "Failures stay in the denominator as `unknown`.",
        _HERE + "test_I13_failures_stay_in_the_denominator",
    ),
    "I14": (
        "The trained model is a tier, not an oracle.",
        _HERE + "test_I14_the_model_is_clamped_traced_and_overridable",
    ),
    "I15": (
        "Three-way disjoint partitions, enforced on the FEATURE VECTOR.",
        _HERE + "test_I15_partitions_are_disjoint_by_feature_vector",
    ),
    "I16": (
        "Every inference records its artifact; key LABELS only, never material.",
        _HERE + "test_I16_artifacts_are_stamped_and_keys_are_labels",
    ),
    "I17": (
        "A trained artifact is reproducible from committed inputs.",
        _HERE + "test_I17_the_artifact_is_reproducible_from_committed_inputs",
    ),
    "I18": (
        "A 200 is not a success.",
        _HERE + "test_I18_a_200_with_no_usable_content_is_a_failure",
    ),
    "I19": (
        "Live-demo failure never takes replay down.",
        _HERE + "test_I19_replay_survives_the_live_path_being_absent",
    ),
}


def test_every_invariant_has_a_named_test() -> None:
    """PLAN §5 — the mapping is auditable, and stays auditable.

    Parses the invariant table out of PLAN.md rather than trusting a list
    maintained here. An invariant added to the plan without a test named for it
    fails this test, which is the only way the mapping stays true after the
    person who wrote it has moved on.
    """
    plan = (REPO_ROOT / "PLAN.md").read_text(encoding="utf-8")
    section = plan.split("## 5. Hard invariants", 1)[1].split("\n---", 1)[0]

    declared = {
        line.split("|")[1].strip()
        for line in section.splitlines()
        if re.match(r"^\| I\d+ \|", line)
    }
    assert declared, "the invariant table was not found in PLAN §5"

    missing = sorted(declared - set(INVARIANT_COVERAGE), key=lambda i: int(i[1:]))
    assert not missing, (
        f"PLAN §5 declares {missing} with no named test. Add the test and the "
        "row in INVARIANT_COVERAGE — an invariant with no test is a comment."
    )

    stale = sorted(set(INVARIANT_COVERAGE) - declared, key=lambda i: int(i[1:]))
    assert not stale, f"{stale} is claimed here and no longer in PLAN §5"

    here = {
        name
        for name, obj in globals().items()
        if name.startswith("test_") and inspect.isfunction(obj)
    }
    for invariant, (_statement, owner) in INVARIANT_COVERAGE.items():
        if owner.startswith(_HERE):
            test_name = owner.rsplit("::", 1)[1]
            assert test_name in here, (
                f"{invariant} names {test_name}, which does not exist"
            )
        else:
            path = BACKEND_ROOT / owner.split("::", 1)[0]
            assert path.exists(), f"{invariant} delegates to {owner}, which is missing"


def _walk_routes(app: Any) -> list[Any]:
    """Every leaf route in the app, flattened.

    `app.routes` returns four entries — the docs routes and one
    `_IncludedRouter` standing in for the whole API — so anything that walks it
    directly silently sees no application routes at all and every assertion
    over "all routes" passes vacuously. Descending through `original_router` is
    what makes such a test able to fail.
    """
    seen: set[int] = set()
    leaves: list[Any] = []

    def descend(node: Any) -> None:
        if id(node) in seen:
            return
        seen.add(id(node))
        routes = getattr(node, "routes", None)
        if routes is None:
            inner = getattr(node, "original_router", None)
            if inner is not None:
                descend(inner)
            return
        for route in routes:
            if hasattr(route, "methods") and hasattr(route, "path"):
                leaves.append(route)
            else:
                descend(route)
            inner = getattr(route, "original_router", None)
            if inner is not None:
                descend(inner)

    descend(app)
    return leaves


# ---------------------------------------------------------------------------
# I1 — one trace entry per node, always
# ---------------------------------------------------------------------------


async def test_I1_one_trace_entry_per_node_always(wire) -> None:
    """Including on an UNHANDLED exception inside a node body.

    Not a caught provider error — an actual bug. A missing entry is a stage that
    ran invisibly, which is the reason the drawer cannot be trusted in either
    prior build.
    """
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName, TraceStatus
    from tests.unit.conftest_graph import StubRetriever, alert_stub

    class _Exploding(StubRetriever):
        def search(self, _text: str, _top_k: int = 5) -> Any:
            raise RuntimeError("deliberate unhandled failure inside a node")

    config = wire(retriever=_Exploding())
    state = await run_pipeline(alert_stub(), config)

    nodes = [entry.node for entry in state.trace]
    expected = [node.value for node in NodeName]
    assert nodes == expected, (
        f"expected exactly one entry per node in order {expected}, got {nodes}"
    )
    assert len(nodes) == len(set(nodes)), "no node reported twice"

    retrieve = next(e for e in state.trace if e.node == NodeName.RETRIEVE.value)
    assert retrieve.status is TraceStatus.FAILED, "the node that blew up says so"
    assert retrieve.note, "and it says why"


async def test_I1_the_trace_is_complete_on_the_happy_path_too(wire) -> None:
    """'Always' includes the boring case."""
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName
    from tests.unit.conftest_graph import alert_stub

    state = await run_pipeline(alert_stub(), wire())
    assert [e.node for e in state.trace] == [n.value for n in NodeName]


# ---------------------------------------------------------------------------
# I2 — no hardcoded metric
# ---------------------------------------------------------------------------


def test_I2_no_hardcoded_metric_literals() -> None:
    """Latency and accuracy fields must be produced, never written in.

    A structural scan rather than a value check: it walks the app for a metric
    key assigned a numeric literal inside a dict. That is the shape of the
    defect — `"avg_latency_ms": 0.0` — and it is invisible to any test that only
    asserts the key is present.
    """
    metric_keys = {
        "avg_latency_ms",
        "accuracy",
        "attack_type_accuracy",
        "severity_accuracy",
        "binary_detection_accuracy",
        "precision",
        "recall",
        "f1",
        "high_severity_precision",
        "high_severity_recall",
        "high_severity_f1",
        "success_rate",
        "escalation_rate",
    }
    offenders: list[str] = []

    for path in sorted((BACKEND_ROOT / "app").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values, strict=True):
                if not isinstance(key, ast.Constant) or key.value not in metric_keys:
                    continue
                if not (
                    isinstance(value, ast.Constant)
                    and isinstance(value.value, (int, float))
                ):
                    continue
                # An accumulator SEED is not a reported metric. The dict is
                # created zeroed and every field is overwritten from real counts
                # before it is returned; the distinguishing mark is that the
                # literal is an argument to `setdefault`, where the whole point
                # of the value is that it is about to be replaced.
                window = "".join(lines[max(0, value.lineno - 4) : value.lineno])
                if "setdefault" in window:
                    continue
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{value.lineno} "
                    f"{key.value} = {value.value!r}"
                )

    assert not offenders, (
        "PLAN I2 — a metric assigned a literal is a metric nobody measured:\n"
        + "\n".join(offenders)
    )


async def test_I2_latency_on_a_real_response_is_a_measurement(client) -> None:
    """The envelope's `latency_ms` is `perf_counter`, not a placeholder."""
    from tests.conftest import auth_header, login, make_user

    await make_user("i2@example.com")
    token = await login(client, "i2@example.com")

    response = await client.get("/api/v1/health", headers=auth_header(token))
    latency = response.json()["meta"]["latency_ms"]

    assert isinstance(latency, (int, float))
    assert latency > 0.0, "0.0 is what a hardcoded latency looks like"


# ---------------------------------------------------------------------------
# I3 — no self-scoring
# ---------------------------------------------------------------------------


def test_I3_the_answer_key_is_not_the_classifier() -> None:
    """PLAN §7.1 — the failure this project exists to eliminate.

    The prior build's `GROUND_TRUTH_EXPANDED` was byte-identical to its
    `SIGNATURE_RULES`. Here the answer key is a CSV column and the classifier is
    a booster; the assertion is that no module the classifier can reach sees the
    truth column, and that the truth has no slot on the state it is handed.
    """
    from app.agent.state import PipelineState
    from app.ml import classifier as classifier_mod
    from app.ml import features as features_mod

    assert not (set(PipelineState.model_fields) & set(TRUTH_KEYS)), (
        "the truth column has no slot on the state the classifier reads"
    )

    # `features.py` NAMES the truth column — in `EXCLUDED_IDENTIFIERS`, which is
    # the guard that keeps it out of the feature vector. That is the opposite of
    # a leak, so what is asserted is that the exclusion is the ONLY place it
    # appears: every reference is a bare string entry in that tuple.
    assert "canonical_class" in features_mod.EXCLUDED_IDENTIFIERS
    feature_source = Path(features_mod.__file__ or "").read_text(encoding="utf-8")
    stray = [
        line
        for line in feature_source.splitlines()
        if any(key in line for key in TRUTH_KEYS)
        and not line.strip().startswith(chr(34))
    ]
    assert not stray, (
        "app.ml.features references the truth column outside the exclusion "
        f"list: {stray}"
    )

    # The classifier must not mention it at all — it consumes the vector, and
    # the vector cannot contain the answer.
    classifier_source = Path(classifier_mod.__file__ or "").read_text(encoding="utf-8")
    for key in TRUTH_KEYS:
        assert key not in classifier_source, (
            f"app.ml.classifier mentions {key!r} — the answer key and the thing "
            "being scored must share no code path (PLAN I3)"
        )


# ---------------------------------------------------------------------------
# I4 — no label leak  (one of the four that matter most)
# ---------------------------------------------------------------------------


def test_I4_the_label_cannot_reach_a_prompt() -> None:
    """Three structural defences, asserted rather than sampled."""
    import app.agent.prompts as prompts_mod
    from app.agent.state import PipelineState
    from app.ingestion.labels import CANONICAL_CLASSES
    from app.ingestion.normalize import synthesize_signature

    # 1. The truth has no field on the state a prompt is built from.
    assert not (set(PipelineState.model_fields) & set(TRUTH_KEYS))

    # 2. `synthesize_signature` CANNOT be handed a label — it is not a
    #    parameter, so a leak would require changing the function's signature.
    parameters = set(inspect.signature(synthesize_signature).parameters)
    for forbidden in ("label", "attack_type", "raw_label", "truth", "canonical_class"):
        assert forbidden not in parameters, (
            f"synthesize_signature accepts {forbidden!r}; PLAN I4's structural "
            "guard is that it cannot be given the answer"
        )

    # 3. The prompt builder reads a fixed allowlist of feature names, and no
    #    entry in it is a class name.
    for name in prompts_mod.PROMPT_FEATURES:
        assert name not in CANONICAL_CLASSES
        assert "label" not in name.lower()


def test_I4_no_constructed_prompt_contains_a_class_name_or_a_label() -> None:
    """The direct check: the BYTES that would go to the provider.

    Not "the code looks careful" — the actual constructed prompt corpus, scanned
    for every canonical class name and every raw CICIDS spelling. This is the
    check the prior build would have failed on 450 of 450 prompts.
    """
    from app.agent.graph import initial_state
    from app.agent.prompts import build_classify_prompt
    from app.config import get_settings
    from app.eval.dataset import load_partition_rows, stratified_sample, to_eval_rows
    from app.ingestion.labels import CANONICAL_CLASSES

    rows = to_eval_rows(
        stratified_sample(load_partition_rows("eval"), cap=60, seed=20260904)
    )
    settings = get_settings()

    forbidden = {c.lower() for c in CANONICAL_CLASSES if c != "benign"}
    forbidden |= {
        "ddos",
        "dos hulk",
        "dos goldeneye",
        "dos slowloris",
        "portscan",
        "port scan",
        "web attack",
        "sql injection",
        "brute force",
        "infiltration",
        "heartbleed",
        "botnet",
    }

    hits: list[str] = []
    for row in rows:
        prompt = build_classify_prompt(initial_state(row.alert, settings)).lower()
        hits += [f"{row.alert.id}: {t!r}" for t in forbidden if t in prompt]

    assert not hits, (
        "PLAN I4 — a ground-truth class name reached a constructed prompt:\n"
        + "\n".join(hits[:20])
    )


# ---------------------------------------------------------------------------
# I5 — a fast path is labelled, not silent
# ---------------------------------------------------------------------------


async def test_I5_a_skipped_tier_is_labelled_in_the_trace(wire) -> None:
    """D25 — an EVE alert has no flow features, so the ML tier is SKIPPED, and
    the skip is visible in the trace with a reason rather than silently."""
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName, TraceStatus
    from tests.unit.conftest_graph import StubLLM, alert_stub

    # D25 routes a feature-less alert straight to the LLM, so the LLM has to be
    # able to answer for the node to reach its verdict. Without a valid payload
    # the node ends `failed` on a parse error and the SKIP — the thing under
    # test — is never reached.
    config = wire(
        groq=StubLLM(
            "groq",
            "openai/gpt-oss-120b",
            payload={"attack_type": "port_scan", "severity": "medium"},
        )
    )
    state = await run_pipeline(alert_stub(source="live_demo"), config)

    classify = next(e for e in state.trace if e.node == NodeName.CLASSIFY.value)

    # I1 forbids a second entry under `classify`, so the SKIP is recorded in
    # this one entry's note and provider rather than in an entry of its own.
    # That is the correct shape, and it is what makes the two invariants
    # compatible: one entry per node, and no tier silently absent from it.
    assert classify.provider != "lightgbm", (
        "the entry names whatever actually produced the verdict; a model that "
        "did not run must not be credited with one"
    )
    assert classify.note, "PLAN I5 — a skip with no reason is a silent skip"
    assert "flow features" in classify.note, (
        f"the note has to say WHY the tier was skipped: {classify.note!r}"
    )
    assert "Fast tier said unknown/unknown" in classify.note, (
        "and it has to say the fast tier produced NOTHING, so a reader cannot "
        f"mistake the LLM's answer for the model's: {classify.note!r}"
    )
    assert state.ml_attack_type in (None, "unknown"), (
        "no fabricated model verdict was recorded for an alert the model "
        "never saw features for (PLAN D25)"
    )
    assert classify.status is not TraceStatus.FAILED, (
        "a deliberate, reasoned skip is not a failure"
    )


# ---------------------------------------------------------------------------
# I6 — nothing blocks the loop
# ---------------------------------------------------------------------------


def test_I6_no_blocking_call_on_the_event_loop() -> None:
    """A structural scan for the calls that stop an event loop dead.

    `time.sleep`, the synchronous `requests` library and blocking `smtplib` all
    stall every other coroutine on the loop, and none of them raises — the only
    symptom is a feed that stutters under load, which is the condition a demo
    runs in.
    """
    banned_calls = {"time.sleep"}
    banned_imports = {"requests", "smtplib", "urllib.request"}
    offenders: list[str] = []

    for path in sorted((BACKEND_ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{path.relative_to(BACKEND_ROOT)}:{node.lineno} import {a.name}"
                    for a in node.names
                    if a.name.split(".")[0] in banned_imports
                ]
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in banned_imports:
                    offenders.append(
                        f"{path.relative_to(BACKEND_ROOT)}:{node.lineno} "
                        f"from {node.module} import ..."
                    )
            elif isinstance(node, ast.Call) and ast.unparse(node.func) in banned_calls:
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{node.lineno} "
                    f"{ast.unparse(node.func)}()"
                )

    assert not offenders, "PLAN I6 — blocking call on the event loop:\n" + "\n".join(
        offenders
    )


# ---------------------------------------------------------------------------
# I7 — every outbound call has a timeout
# ---------------------------------------------------------------------------


def test_I7_every_outbound_client_carries_a_timeout() -> None:
    """`httpx.AsyncClient()` with no timeout waits forever by design.

    Scanned rather than sampled, because the failure is silent until the one
    call that hangs — and a hung provider call holds a graph node, which holds
    the replay loop's alert, on the day it matters.
    """
    offenders: list[str] = []

    for path in sorted((BACKEND_ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if ast.unparse(node.func) not in ("httpx.AsyncClient", "AsyncClient"):
                continue
            if not any(kw.arg == "timeout" for kw in node.keywords):
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{node.lineno} "
                    "AsyncClient() with no timeout"
                )

    assert not offenders, "PLAN I7:\n" + "\n".join(offenders)


def test_I7_the_configured_timeouts_are_real_numbers() -> None:
    """A timeout of 0, or None, is the same as no timeout at all."""
    from app.config import get_settings

    settings = get_settings()
    for name in (
        "llm_timeout_seconds_groq",
        "llm_timeout_seconds_gemini",
        "intel_timeout_seconds",
        "smtp_timeout_seconds",
    ):
        value = getattr(settings, name)
        assert isinstance(value, (int, float)), f"{name} is not a number"
        assert value > 0, f"{name} is {value} — that is no timeout at all"


# ---------------------------------------------------------------------------
# I8 — no route claims a role it does not enforce
# ---------------------------------------------------------------------------


def _role_gated_routes() -> list[tuple[str, str, str]]:
    """Every route that DECLARES `require_role`, read off the app itself.

    Enumerated rather than hand-listed, so an admin route added without a test
    is caught by this test rather than by nobody. The invariant is "no route
    CLAIMS a role it does not enforce": the claim is the dependency, which
    `ROLE_GUARD_ATTR` makes readable, and the enforcement is what the
    assertions below exercise over HTTP.
    """
    import app.api.deps as deps_mod
    from app.api.router import api_router
    from app.main import create_app

    prefix = api_router.prefix
    found: list[tuple[str, str, str]] = []
    for route in _walk_routes(create_app()):
        for dependency in getattr(route, "dependencies", []):
            allowed = getattr(
                getattr(dependency, "dependency", None), deps_mod.ROLE_GUARD_ATTR, None
            )
            if not allowed:
                continue
            methods = sorted(set(route.methods) - {"HEAD", "OPTIONS"})
            found.append(
                (methods[0].lower(), prefix + str(route.path), "/".join(allowed))
            )
    return sorted(found)


async def test_I8_every_role_gated_route_enforces_its_role(client) -> None:
    """A viewer is refused on EVERY route that declares a role above viewer.

    The prior build's suite actively PROTECTED a privilege-escalation hole by
    asserting the permissive behaviour, so the refusal is asserted here on the
    real routes, enumerated from the app's own routing table.

    **What this does NOT assert, deliberately:** that rules and playbooks are
    admin-only. PLAN §9 gates `require_role("admin")` on user CRUD, audit and
    jobs; rules and playbooks are OWNER-SCOPED instead (D37 — authored per user,
    enforced deployment-wide), and asserting a role gate they were never
    specified to have would be inventing a requirement. Their protection is
    IDOR scoping, asserted separately below.
    """
    from tests.conftest import auth_header, login, make_user

    gated = _role_gated_routes()
    assert gated, (
        "no route declares require_role — either the guard was removed or this "
        "test can no longer see it, and both are worth failing on"
    )

    await make_user("viewer-i8@example.com", role="viewer")
    token = await login(client, "viewer-i8@example.com")
    headers = auth_header(token)

    for method, path, roles in gated:
        url = path.replace("{job}", "correlation.rebuild")
        # `json=` is only valid on the body-carrying verbs; httpx's `get` has no
        # such parameter, so the request is built per verb rather than uniformly.
        if method in ("post", "put", "patch"):
            response = await getattr(client, method)(url, headers=headers, json={})
        else:
            response = await getattr(client, method)(url, headers=headers)
        assert response.status_code == 403, (
            f"{method.upper()} {url} declares role {roles} and let a viewer "
            f"through with {response.status_code}: {response.text[:200]}"
        )


async def test_I8_a_user_cannot_set_their_own_role(client) -> None:
    """PLAN §9 — the prior build's one-HTTP-call self-promotion to admin."""
    from tests.conftest import auth_header, login, make_user

    await make_user("escalate@example.com", role="viewer")
    token = await login(client, "escalate@example.com")

    response = await client.put(
        "/api/v1/auth/profile",
        headers=auth_header(token),
        json={"name": "Escalated", "role": "admin"},
    )
    assert response.status_code in (200, 422), response.text

    me = await client.get("/api/v1/auth/me", headers=auth_header(token))
    assert me.json()["role"] == "viewer", "the role changed from a user-supplied field"


async def test_I8_owner_scoped_resources_are_scoped_on_LOOKUP(client) -> None:
    """PLAN §9 IDOR — rules and playbooks are protected by ownership, not role.

    Scoped on lookup, not only on list: a list that filters while a GET by id
    does not is the exact shape of the bug the row names.
    """
    from tests.conftest import auth_header, login, make_user

    await make_user("owner-i8@example.com", role="analyst")
    await make_user("other-i8@example.com", role="analyst")
    owner = await login(client, "owner-i8@example.com")
    other = await login(client, "other-i8@example.com")

    created = await client.post(
        "/api/v1/rules", json=_rule_body(), headers=auth_header(owner)
    )
    assert created.status_code == 201, created.text
    rule_id = created.json()["data"]["id"]

    # CONTRACT #13-16 — rules expose GET, POST and DELETE. There is no PUT, so
    # DELETE is the whole of the by-id write surface.
    response = await client.delete(
        f"/api/v1/rules/{rule_id}", headers=auth_header(other)
    )
    assert response.status_code == 404, (
        f"DELETE on another user's rule returned {response.status_code} — a 403 "
        "would confirm the row exists, and a 204 would be the IDOR itself"
    )

    listed = await client.get("/api/v1/rules", headers=auth_header(other))
    assert listed.json()["rules"] == [], "and it is not in the other user's list"

    still_there = await client.get("/api/v1/rules", headers=auth_header(owner))
    assert [r["id"] for r in still_there.json()["rules"]] == [rule_id], (
        "and the refused DELETE did not delete it"
    )


def _rule_body() -> dict[str, Any]:
    """A VALID body, deliberately.

    An invalid one 422s before the role check runs, and the test would pass
    while proving nothing at all about the role.
    """
    return {
        "name": "i8 probe",
        "description": "",
        "conditions": {
            "logic": "AND",
            "conditions": [
                {"field": "attack_type", "operator": "equals", "value": "port_scan"}
            ],
        },
        "actions": [{"type": "set_severity", "value": "critical"}],
    }


def _playbook_body() -> dict[str, Any]:
    return {
        "name": "i8 probe",
        "description": "probe",
        "alert_type": "dos",
        "severity_threshold": "high",
        "steps": [{"type": "manual", "title": "look", "description": "look at it"}],
    }


# ---------------------------------------------------------------------------
# I9 — no seeded fake data
# ---------------------------------------------------------------------------


def test_I9_no_seeded_fake_data_anywhere() -> None:
    """Not in dev either. A demo rule that fires would make the rules
    precedence look proven when it was staged (D33)."""
    banned = ("createMockAlerts", "MOCK_ALERTS", "lorem ipsum", "faker")
    offenders: list[str] = []

    for path in sorted((BACKEND_ROOT / "app").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        offenders += [
            f"{path.relative_to(BACKEND_ROOT)}: {token}"
            for token in banned
            if token in text
        ]

    assert not offenders, "PLAN I9:\n" + "\n".join(offenders)


async def test_I9_a_fresh_install_has_a_genuinely_empty_rule_set(client) -> None:
    """D33 — '0 rules configured' is the honest state, and it is the state."""
    from tests.conftest import auth_header, login, make_user

    await make_user("i9@example.com", role="analyst")
    token = await login(client, "i9@example.com")

    response = await client.get("/api/v1/rules", headers=auth_header(token))
    assert response.status_code == 200
    assert response.json()["rules"] == [], (
        "a fresh install ships zero rules — a seeded example would be fake data "
        "in every environment"
    )


# ---------------------------------------------------------------------------
# I10 — pytest cannot touch the runtime database
# ---------------------------------------------------------------------------


def test_I10_pytest_cannot_touch_the_runtime_database() -> None:
    """One run of the prior repo's suite wiped its demo database."""
    import tests.conftest as conftest_mod
    from app.config import get_settings

    url = get_settings().database_url
    assert "flare.db" not in url, "the suite is pointed at the RUNTIME database"
    assert str(conftest_mod._TMP_DIR.as_posix()) in url

    # The guard is not merely configuration — it refuses.
    with pytest.raises(RuntimeError, match="runtime database"):
        conftest_mod._assert_not_runtime_db(
            "sqlite+aiosqlite:///./flare.db"
        )

    # And no test anywhere in the suite drops or creates schema (D18 — Alembic
    # is the only authority). THIS file is skipped: it names the calls in order
    # to forbid them, and a scanner that matches its own pattern can only fail.
    for path in sorted((BACKEND_ROOT / "tests").rglob("*.py")):
        if path == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8")
        for call in ("drop" + "_all(", "create" + "_all("):
            assert call not in text, (
                f"{path.name} calls {call} — Alembic is the only schema "
                "authority (PLAN D18), and a suite that builds its own schema "
                "is not testing the migrations production runs"
            )


# ---------------------------------------------------------------------------
# I11 — README claims are backed
# ---------------------------------------------------------------------------


def test_I11_readme_claims_point_at_real_artifacts() -> None:
    """Every file and script the README names must exist.

    Phase 8 rewrites the README against this test rather than the other way
    round; what it asserts today is that nothing currently claimed is missing.
    """
    readme = (BACKEND_ROOT / "README.md").read_text(encoding="utf-8")

    referenced = set(
        re.findall(r"`((?:app|scripts|models|data|tests)/[\w./-]+)`", readme)
    )
    missing = sorted(p for p in referenced if not (BACKEND_ROOT / p).exists())
    assert not missing, (
        "PLAN I11 — the README names paths that do not exist: " + ", ".join(missing)
    )

    for command in set(re.findall(r"python -m (scripts\.[\w_]+)", readme)):
        module = BACKEND_ROOT / (command.replace(".", "/") + ".py")
        assert module.exists(), f"README documents `{command}`, which does not exist"


# ---------------------------------------------------------------------------
# I12 — every rendered field has a producer
# ---------------------------------------------------------------------------


async def test_I12_every_rendered_field_has_a_producer(client) -> None:
    """An endpoint may not return a key the pipeline never fills.

    Asserted on the eval payload because the screen that renders it has the most
    fields: every scalar the Evaluation screen reads must be present AND
    non-null.
    """
    from app.eval import cache
    from tests.conftest import auth_header, login, make_user

    if cache.read() is None:
        pytest.skip("no cached eval run on disk to check the shape of")

    await make_user("i12@example.com", role="analyst")
    token = await login(client, "i12@example.com")
    response = await client.get("/api/v1/eval", headers=auth_header(token))
    assert response.status_code == 200, response.text
    data = response.json()["data"]

    required = (
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
        "unscored_count",
    )
    for key in required:
        assert key in data, f"the Evaluation screen reads {key} and it is absent"
        assert data[key] is not None, f"{key} is present and null — no producer"


# ---------------------------------------------------------------------------
# I13 — failures stay in the denominator
# ---------------------------------------------------------------------------


def test_I13_failures_stay_in_the_denominator() -> None:
    """A metric that drops its failures measures a different population than
    the one it names."""
    from app.eval.scoring import Outcome, TierResult

    result = TierResult("llm")
    for index in range(10):
        failed = index < 3
        result.outcomes.append(
            Outcome(
                row_id=f"eval-{index}",
                signature="synthesized",
                true_attack_type="dos",
                true_severity="high",
                pred_attack_type="unknown" if failed else "dos",
                pred_severity="unknown" if failed else "high",
                latency_ms=None if failed else 12.0,
                failure="timeout" if failed else None,
            )
        )

    block = result.block()
    assert block["sample_size"] == 10, "the denominator is every row offered"
    assert block["unscored_count"] == 3
    assert block["attack_type_accuracy"] == pytest.approx(0.7), (
        "7 of 10, not 7 of 7 — the three failures drag the number down"
    )
    assert block["failures"], "and the failure categories are reported, not hidden"


# ---------------------------------------------------------------------------
# I14 — the trained model is a tier, not an oracle
# ---------------------------------------------------------------------------


async def test_I14_the_model_is_clamped_traced_and_overridable(wire) -> None:
    """It emits a trace entry, its output is enum-clamped, and a rule beats it."""
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName
    from app.ingestion.labels import CANONICAL_CLASSES
    from app.rules.engine import Condition, Rule, RuleEngine, set_rule_engine
    from tests.unit.conftest_graph import StubClassifier, alert_stub

    config = wire(classifier=StubClassifier(attack_type="dos", severity="high"))
    state = await run_pipeline(alert_stub(), config)

    classify = next(e for e in state.trace if e.node == NodeName.CLASSIFY.value)
    assert classify.provider == "lightgbm", "the model names itself in the trace"
    assert classify.model_version, "and stamps its artifact version (I16)"
    assert state.attack_type in (*CANONICAL_CLASSES, "unknown"), (
        "the model's output is enum-clamped exactly like the LLM's"
    )

    # And a rule OVERRIDES it — the model is a tier, not an oracle.
    config = wire(classifier=StubClassifier(attack_type="dos", severity="high"))
    set_rule_engine(
        RuleEngine(
            [
                Rule(
                    id="r-i14",
                    name="escalate dos",
                    conditions=(Condition("attack_type", "eq", "dos"),),
                    action="set_severity",
                    severity="critical",
                )
            ]
        )
    )
    overridden = await run_pipeline(alert_stub(), config)
    assert overridden.severity == "critical", (
        "the rule ran last and won over the model (PLAN §7.3c precedence)"
    )
    assert overridden.rules_overrode is True, "and the override is declared"


# ---------------------------------------------------------------------------
# I15 — three-way disjoint, on the FEATURE VECTOR  (one of the four)
# ---------------------------------------------------------------------------


def test_I15_partitions_are_disjoint_by_feature_vector() -> None:
    """§7.3b — id-level disjointness passed while 62 rows were shared.

    Both halves are asserted: pairwise-disjoint id sets AND zero exact
    feature-vector overlap. The second is the one that caught the real defect.
    """
    import numpy as np

    from app.eval.dataset import feature_matrix, load_partition_rows

    partitions = {
        name: load_partition_rows(name) for name in ("train", "eval", "replay")
    }

    ids = {name: {row["row_id"] for row in rows} for name, rows in partitions.items()}
    for left, right in (("train", "eval"), ("train", "replay"), ("eval", "replay")):
        shared = ids[left] & ids[right]
        assert not shared, f"{len(shared)} row ids shared between {left} and {right}"

    def vectors(name: str) -> set[bytes]:
        matrix = np.ascontiguousarray(
            feature_matrix(partitions[name]), dtype=np.float64
        )
        return {row.tobytes() for row in matrix}

    train_vectors = vectors("train")
    eval_vectors = vectors("eval")
    replay_vectors = vectors("replay")

    for name, other in (("eval", eval_vectors), ("replay", replay_vectors)):
        overlap = len(train_vectors & other)
        assert overlap == 0, (
            f"{overlap} {name} rows carry a feature vector that appears verbatim "
            "in train. Id-level disjointness passed while this was true once "
            "already (PLAN §7.3b)"
        )
    assert not (eval_vectors & replay_vectors), (
        "eval and replay share a feature vector — the demo would be replaying "
        "rows the eval scored"
    )


def test_I15_no_unlabelled_source_can_enter_a_scored_partition() -> None:
    """D24 — `live_demo` and `suricata_sample` carry no ground truth."""
    from app.eval.dataset import load_partition_rows

    for name in ("train", "eval", "replay"):
        sources = {
            row.get("source", "cicids_replay") for row in load_partition_rows(name)
        }
        assert sources <= {"cicids_replay"}, (
            f"{name} contains {sources - {'cicids_replay'}} — an alert with no "
            "ground truth cannot be scored (PLAN I15 as extended by D24)"
        )


def test_I15_a_live_demo_alert_carries_no_label_and_no_features() -> None:
    """Phase 4a — the property is enforced at CONSTRUCTION, not by convention.

    An ingested alert cannot enter a partition because it never acquires the
    two things a partition row needs: a `ground_truth_class` and a feature
    vector. `parse_eve_record` sets both to empty and takes no parameter that
    could set either, so there is no call site that could pass a label in.
    """
    import inspect

    from app.ingestion.suricata import parse_eve_record

    alert = _live_alert()
    assert alert.source == "live_demo"
    assert alert.ground_truth_class is None, "no label, ever (I15 / D24)"
    assert alert.features == {}, "no feature vector, so no partition can hold it"
    assert alert.row_id is None, "and no partition-stamped id"

    signature = inspect.signature(parse_eve_record)
    assert set(signature.parameters) == {"record", "source"}, (
        "parse_eve_record must not grow a label parameter — I4's structural "
        "argument, applied to the live path"
    )


def test_I15_the_partition_loader_refuses_a_live_demo_row() -> None:
    """The enforcement, not just the current state of the files on disk.

    A test that only reads `data/splits/*.csv` asserts that today's files are
    clean. This asserts that a live-demo row WOULD be rejected — which is the
    invariant — by feeding one through the eval's own source check.
    """
    from app.eval.dataset import SCORABLE_SOURCES

    assert SCORABLE_SOURCES == frozenset({"cicids_replay"}), (
        "only replayed CICIDS rows carry ground truth; widening this set is "
        "how an unlabelled alert gets scored (PLAN I15 / D24)"
    )
    for unlabelled in ("live_demo", "suricata_sample"):
        assert unlabelled not in SCORABLE_SOURCES


def test_I15_the_training_script_reads_only_the_train_partition() -> None:
    """The other half of D24: no live row can reach TRAINING either.

    `scripts/train_classifier.py` is the only path to a committed model, and it
    loads `train.csv` by name. A live alert has no route into that file: the
    ingest endpoint writes to the alerts table and the live queue, and neither
    is read by the partition builder or the trainer.
    """
    from pathlib import Path

    trainer = Path(__file__).resolve().parents[2] / "scripts" / "train_classifier.py"
    source = trainer.read_text(encoding="utf-8")

    assert "live_demo" not in source, (
        "the trainer must have no live-demo code path at all"
    )
    # Names of the runtime-data seams, not substrings that appear inside
    # unrelated module paths — `app.ingestion.labels` is a legitimate import
    # and matching a bare "ingest" against it would make this test noise.
    for writer in (
        "upsert_alert",
        "get_sessionmaker",
        "app.ingestion.live",
        "app.api.routes.ingest",
    ):
        assert writer not in source, (
            f"the trainer reads partition files only; {writer!r} would give it "
            "a route to runtime data, which is where unlabelled rows live"
        )


# ---------------------------------------------------------------------------
# I16 — artifact stamping, key labels only
# ---------------------------------------------------------------------------


async def test_I16_artifacts_are_stamped_and_keys_are_labels(wire) -> None:
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName
    from app.providers.keypool import KeyPool
    from tests.unit.conftest_graph import alert_stub

    state = await run_pipeline(alert_stub(severity="critical"), wire())

    classify = next(e for e in state.trace if e.node == NodeName.CLASSIFY.value)
    assert classify.model_version, (
        "PLAN I16 — the verdict names the artifact that produced it"
    )
    reason = next(e for e in state.trace if e.node == NodeName.REASON.value)
    assert reason.key_id, "and which KEY served it — by label"
    assert reason.key_id.startswith(("groq-", "gemini-"))

    # A label, never material, anywhere it could surface.
    secret = "sk-super-secret-value"
    key_pool = KeyPool(
        "groq",
        {"dev": secret, "reserved": None, "spare": None},
        default_cooldown_seconds=60.0,
    )
    lease = key_pool.acquire()
    assert secret not in repr(lease)
    assert secret not in repr(key_pool)
    assert secret not in json.dumps(key_pool.snapshot())
    assert lease.key_id == "groq-dev"


# ---------------------------------------------------------------------------
# I17 — reproducible from committed inputs
# ---------------------------------------------------------------------------


def test_I17_the_artifact_is_reproducible_from_committed_inputs() -> None:
    """Fixed seed, committed script, committed split, committed metrics."""
    metrics = json.loads(
        (BACKEND_ROOT / "models" / "classifier" / "metrics.json").read_text(
            encoding="utf-8"
        )
    )
    assert metrics.get("seed") is not None, "no seed recorded — not reproducible"
    assert metrics.get("model_version"), "no version stamped on the artifact"

    for required in (
        BACKEND_ROOT / "scripts" / "train_classifier.py",
        BACKEND_ROOT / "data" / "splits" / "train.csv",
        BACKEND_ROOT / "data" / "splits" / "MANIFEST.json",
    ):
        assert required.exists(), f"{required.name} is not committed"

    manifest = json.loads(
        (BACKEND_ROOT / "data" / "splits" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    assert manifest.get("seed") is not None, "the split is not reproducible either"


# ---------------------------------------------------------------------------
# I18 — a 200 is not a success  (one of the four)
# ---------------------------------------------------------------------------


def test_I18_a_200_with_no_usable_content_is_a_failure() -> None:
    from app.providers.base import EmptyContentError, parse_json_content

    for content in ("", "   ", "\n", "not json", "[1,2]", "null", '{"severity":"high"}'):
        with pytest.raises(EmptyContentError):
            parse_json_content(
                "groq", "model", content, required=("attack_type", "severity")
            )


async def test_I18_an_empty_content_failure_is_traced_and_never_a_default(
    wire,
) -> None:
    """It never becomes a silent default and never renders as a verdict."""
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName, TraceStatus
    from app.providers.base import EmptyContentError
    from tests.unit.conftest_graph import StubLLM, alert_stub

    config = wire(
        groq=StubLLM(
            "groq",
            "openai/gpt-oss-120b",
            error=EmptyContentError("groq", "200 with empty content"),
        ),
        gemini=StubLLM(
            "gemini",
            "gemini-3.6-flash",
            error=EmptyContentError("gemini", "200 with no text parts"),
        ),
    )
    state = await run_pipeline(alert_stub(severity="critical"), config)

    reason = next(e for e in state.trace if e.node == NodeName.REASON.value)
    assert reason.status is TraceStatus.FAILED, (
        "a 200 that carried nothing is a FAILED call, not a quiet default"
    )
    assert "EmptyContentError" in (reason.note or ""), (
        "the category is recoverable from the note, which is how the eval "
        "counts it rather than folding it into success"
    )


# ---------------------------------------------------------------------------
# I19 — the live path is additive
# ---------------------------------------------------------------------------


async def test_I19_replay_survives_the_live_path_being_absent(wire) -> None:
    """The staged-attack path is additive and isolated (D23), in four states.

    Phase 4a shipped the route, so this no longer passes because nothing is
    mounted. Each state below is a way the live path can be broken, and after
    each one replay must still produce a full verdict with a complete trace.

      1. **Disabled.** The default build. The route is not mounted at all.
      2. **Enabled but never started.** The lane exists, its worker is not
         running, and a submission just sits in the queue.
      3. **Its worker raising on every alert.** The failure counter climbs and
         nothing propagates.
      4. **Its queue full.** Submissions are refused, countably.

    The structural claim underneath all four: the live lane owns its own
    BoundedQueue and its own task. If it shared the replay loop's triage queue,
    state 4 would start dropping replayed alerts, which is precisely the
    coupling this asserts is absent.
    """
    from app.agent.graph import run_pipeline
    from app.agent.state import NodeName
    from app.ingestion.feed import get_feed
    from app.ingestion.live import LiveIngestService, get_live_ingest, reset_live_ingest
    from app.main import create_app
    from tests.unit.conftest_graph import alert_stub

    config = wire()

    async def replay_still_works(state_name: str) -> None:
        state = await run_pipeline(alert_stub(), config)
        assert state.attack_type != "unknown", f"replay produced a verdict ({state_name})"
        assert len(state.trace) == len(list(NodeName)), (
            f"with a complete trace ({state_name})"
        )
        assert state.source == "cicids_replay"

    # -- 1. disabled: the route is ABSENT, not mounted-and-refusing ---------
    live_routes = [
        route
        for route in _walk_routes(create_app())
        if "ingest" in str(getattr(route, "path", ""))
    ]
    assert live_routes == [], (
        "with live_ingest_enabled off the route must not exist at all; the test "
        "suite runs with the default settings, which is the shipped default"
    )
    await replay_still_works("live path disabled")

    # -- the live lane owns its own queue, not the replay loop's -----------
    reset_live_ingest()
    live = get_live_ingest()
    assert live.queue is not get_feed().triage_queue, (
        "a shared queue is what would make live pressure into replay drops"
    )

    # -- 2. enabled but never started --------------------------------------
    assert not live.running
    live.submit(_live_alert())
    await replay_still_works("live worker never started")

    # -- 3. the live worker raising on every alert -------------------------
    exploding = LiveIngestService(maxsize=4)

    async def always_raises(_alert: object) -> None:
        raise RuntimeError("the live path is broken")

    exploding._process = always_raises  # type: ignore[method-assign]
    await exploding.start()
    exploding.submit(_live_alert())
    exploding.submit(_live_alert())
    for _ in range(50):
        if exploding.failures >= 2:
            break
        await asyncio.sleep(0.01)
    assert exploding.failures >= 2, "the failures were counted, not propagated"
    assert exploding.running, "and the live worker survived them"
    await replay_still_works("live worker raising on every alert")
    await exploding.stop()

    # -- 4. the live queue full --------------------------------------------
    saturated = LiveIngestService(maxsize=2)
    accepted = [saturated.submit(_live_alert()) for _ in range(6)]
    assert accepted.count(False) >= 3, "a full live lane refuses, countably"
    assert saturated.queue.stats().dropped >= 3
    assert get_feed().triage_queue.stats().dropped == 0, (
        "and NOT ONE replay slot was consumed by the live lane"
    )
    await replay_still_works("live queue saturated")

    reset_live_ingest()


def _live_alert() -> Any:
    """One live-demo alert, built through the real EVE parser."""
    from app.ingestion.suricata import parse_eve_record

    alert = parse_eve_record(
        {
            "timestamp": "2026-09-06T11:04:22.116447+0000",
            "event_type": "alert",
            "src_ip": "192.168.4.31",
            "dest_ip": "192.168.4.10",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Potential SSH Scan",
                "signature_id": 2010935,
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        },
        source="live_demo",
    )
    assert alert is not None
    return alert
