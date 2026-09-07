# Flare — backend

An AI SOC triage pipeline. Real labeled network flows go in; a trained
classifier, threat intel, MITRE ATT&CK retrieval and an LLM produce a verdict,
an explanation and a recommendation, with a per-stage trace behind every one.

Spec: [`../CONTRACT.md`](../CONTRACT.md) and [`../openapi.yaml`](../openapi.yaml).
The frontend is frozen; the backend is built to fit it.

**What is real and what is replayed is stated in
[`REAL_VS_SIMULATED.md`](../REAL_VS_SIMULATED.md), up front rather than under
questioning.**

---

## The claim rule

**Every capability claim in this file maps to a passing test** (PLAN I11). Where
a claim is made, the test that backs it is named. A claim whose test was deleted
is a claim that gets deleted, not a claim that gets softened — one predecessor
repo's changelog said it had a "signature lookup table for perfect F1 scores",
which is a written confession, and judges read the README first.

Run everything behind this file:

```bash
make check
```

820 tests, ruff clean over the whole tree, mypy clean over 124 source files,
green from a cold clone.

---

## Run it

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev,ml]"
```

`[ml]` is not optional in practice — it carries LightGBM, ONNX Runtime and the
tokenizer, and without it the app imports cleanly and fails at the first
inference. The cold-clone CI job installs exactly this and fails if either
artifact cannot load
([`tests/ci/test_dependencies_are_declared.py`](tests/ci/test_dependencies_are_declared.py)).

Copy `.env.example` to `.env` and set `JWT_SECRET` — there is no fallback and
the app refuses to start without it
([`tests/unit/test_config.py`](tests/unit/test_config.py)).

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Alembic is the only schema authority (PLAN D18). There is no `create_all`
anywhere:

```bash
.venv/Scripts/python.exe -m alembic upgrade head
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
```

The frontend dev server proxies `/api` to port 8000: run it from `../frontend`
with `npm run dev` and use http://localhost:5174.

### Demo account

The frozen frontend's "Quick demo sign in" button carries hardcoded credentials
in the shipped bundle (CONTRACT §8.7). That is exactly why the account is **not**
seeded by default — on a default boot it does not exist and the button returns
401, which is intended behaviour, not a bug
([`tests/integration/test_demo_seed.py`](tests/integration/test_demo_seed.py)).
PLAN §9 forbids publishing the credentials here, so they are not repeated; the
seeder reads them from `scripts/seed_demo.py`.

```bash
.venv/Scripts/python.exe -m scripts.seed_demo --demo-seed
```

---

## What it does

| Capability | State | Test |
|---|---|---|
| Auth: register, login, refresh, `/me`, profile, change-password | working | [`test_auth.py`](tests/integration/test_auth.py) |
| RBAC — every route that declares a role enforces it | working | [`test_rbac.py`](tests/integration/test_rbac.py), I8 |
| Replay of real labeled CICIDS2017 flows, one loop per server | working | [`test_alerts.py`](tests/integration/test_alerts.py), [`test_stream.py`](tests/integration/test_stream.py) |
| LightGBM fast-tier classification (attack type + severity) | working | [`test_classifier.py`](tests/unit/test_classifier.py) |
| Threat intel enrichment (AbuseIPDB, VirusTotal), per-IP cached | working | [`test_intel.py`](tests/unit/test_intel.py) |
| MITRE ATT&CK retrieval — MiniLM ONNX embeddings, numpy cosine | working | [`test_retrieval.py`](tests/unit/test_retrieval.py) |
| LLM reasoning + recommendation, cross-provider fallback | working | [`test_graph.py`](tests/unit/test_graph.py), [`test_reason_fallback.py`](tests/unit/test_reason_fallback.py) |
| Per-stage trace: one entry per node, always, including on failure | working | I1 |
| Rules CRUD, persistence, and rules running LAST over both tiers | working | [`test_rules_api.py`](tests/integration/test_rules_api.py), [`test_rules_phase4.py`](tests/unit/test_rules_phase4.py) |
| Playbooks (state machine), audit log, CSV/PDF export | working | [`test_playbooks_api.py`](tests/integration/test_playbooks_api.py), [`test_audit_export_notifications.py`](tests/integration/test_audit_export_notifications.py) |
| Correlation and the scheduler | working | [`test_correlation_and_scheduler.py`](tests/integration/test_correlation_and_scheduler.py) |
| Presence-aware email notifications, debounce/rollup/digest | working | [`test_notifications_phase5.py`](tests/integration/test_notifications_phase5.py), [`test_presence.py`](tests/unit/test_presence.py) |
| Held-out eval scoring three tiers with baselines and guard bands | working | [`test_eval_harness.py`](tests/unit/test_eval_harness.py), [`test_eval_guards.py`](tests/unit/test_eval_guards.py) |
| **Live staged-attack injection** — `POST /ingest/eve` | working, **off by default** | [`test_ingest_live.py`](tests/integration/test_ingest_live.py), I19 |
| Offline mode — declared, labelled, never a silent template | working | [`test_graph.py`](tests/unit/test_graph.py) |
| Provider key pool, sticky rotation, dead-key removal | working | [`test_providers.py`](tests/unit/test_providers.py), [`test_dead_key_health.py`](tests/failure/test_dead_key_health.py) |

**Deliverability is the one thing above with no automated test, and it cannot
have one.** The transport, the templates, the debounce and the presence policy
are all tested against a fake transport and a monkeypatched `aiosmtplib.send`.
Whether a message lands in an inbox or a spam folder is answered only by sending
one, which is a manual step: `python -m scripts.send_test_email <address>` with
`SMTP_*` filled. It has been run and the message reached the inbox; that is a
recorded operator action, not a test result, and it is listed that way rather
than dressed up as one.

**Not built, deliberately.** Multi-tenancy, a vector database, live traffic
capture, and non-email notification channels. Each has a one-line answer in
[`REAL_VS_SIMULATED.md`](../REAL_VS_SIMULATED.md) and PLAN §17.

---

## The numbers

All three tiers, both sample sizes, every accuracy against **random, majority
and a no-training 1-NN baseline**. Nothing here is a headline in isolation.

### Attack-type accuracy, six balanced classes

| Tier | n=80 | n=300 | n=300 (post-adjudication) | random | majority | 1-NN |
|---|---|---|---|---|---|---|
| **LightGBM alone** | 1.0000 | 0.9967 | **0.9967** | 0.1667 | 0.1667 | 0.9867 |
| **LLM alone** (zero-shot) | 0.2000 | 0.2400 | **0.2333** | 0.1667 | 0.1667 | — |
| **As-shipped system** | 1.0000 | 0.9967 | **0.9967** | 0.1667 | 0.1667 | 0.9867 |
| **LightGBM, full 1,800-row partition** | 0.9944 | 0.9944 | **0.9944** | 0.1667 | 0.1667 | 0.9844 |

**The number to quote is 0.9944 on the full 1,800-row held-out partition**, one
point above a no-training 1-NN baseline of 0.9844 on a partition verified
disjoint at the feature vector. The capped-sample figure reads 0.9967 because
299/300 is the single most likely draw from a population at 0.9944 — one error
where 1.67 are expected.

### Also measured

| | n=80 | n=300 | n=300 (post-adjudication) |
|---|---|---|---|
| Binary detection (system) | 1.0000 | 0.9967 | **0.9967** |
| Severity accuracy (system) | 1.0000 | 0.9900 | **0.9900** |
| Binary detection (LLM) | 0.4875 | 0.5200 | **0.4933** |
| Severity accuracy (LLM) | 0.2375 | 0.2800 | **0.2700** |
| Escalation rate | 0/80 | 0/300 | **0/300** |
| Provider calls succeeded | 86/89 | 330/330 | **361/361** |
| Modelled list-price cost | $0.0122 | $0.0490 | **$0.0949** |
| Guard bands tripped | `llm_floor` | `lightgbm_absolute:sample` | **none** |

**All three runs are on disk and all three are published** —
`data/eval/n80.json`, `data/eval/n300.json`,
`data/eval/n300_postadjudication.json`, with `data/eval/latest.json` serving the
Evaluation screen. Nobody has to take on trust that a number moved for a good
reason: the before and the after are both dated and both readable.

**The LLM tier moved 0.2400 → 0.2333 between two runs on the identical rows.**
That is provider temperature and server-side variance, disclosed in the run
notice on every payload, not a change to anything.

### Why the LLM number is low, and why that is the finding

The LLM scores **0.2333 against a 0.1667 random baseline** on single flows —
barely above chance. Four hypotheses were tested and all four ruled out with
evidence: `unscored_count` 0, zero failures, every provider call succeeded,
every response parsed and enum-clamped, and all fifteen `PROMPT_FEATURES`
present in every prompt (PLAN §7.3d). The model is coherently wrong, not broken:
**one flow drawn from a distributed attack carries no evidence of the
distribution**, so a five-packet no-reply DDoS flow reads as benign.

That measurement is the evidence for the tiering split, and it was taken before
the split was defended, not after
([`test_eval_guards.py::test_the_measured_llm_accuracy_no_longer_trips_the_floor`](tests/unit/test_eval_guards.py)).

### Guard bands

The eval refuses to publish numbers it cannot vouch for. `run_eval` exits
non-zero when a band trips.

| Guard | Threshold | Scope |
|---|---|---|
| `lightgbm_relative` | >0.05 over 1-NN while above 0.98 | sample and full partition |
| `feature_overlap` | any non-zero eval→train feature-vector overlap | unconditional, any accuracy |
| `lightgbm_absolute` | 0.995 | **full partition only** (PLAN §7.3g) |
| `lightgbm_consistency` | exact two-sided binomial on the error count, 99% | sample |
| `degenerate` | exactly 1.000 | probability-aware |
| `llm_floor` / `llm_prompt_leak` | 0.18 / 0.90 | LLM tier |
| `router_regression` | system below LightGBM-alone | as-shipped |

**Two thresholds have been superseded, and both travel on every eval payload
with their date and their evidence** (`superseded_thresholds`): the `llm_floor`
0.35 → 0.18 (§7.3d) and `CEILING_DECISIVE_SAMPLE_SIZE` 201 → removed in favour
of the consistency test (§7.3g). A guard band that changes without leaving a
record is indistinguishable from one tuned to make a number pass.

**The guards are not decoration — one caught a real defect.** The unconditional
feature-overlap check found 62 eval rows sharing a feature vector with train
while id-level disjointness passed. The partition builder now deduplicates on
the 77-feature vector across the whole population before splitting; 193,859
duplicate vectors were dropped and exact overlap is now zero
([`test_partitions.py`](tests/unit/test_partitions.py), I15).

---

## Quota and cost budget (PLAN §10)

**Everything in this stack runs on free tiers and free/open-source tools. There
is no paid service anywhere.** Quota is therefore a design constraint, and the
sizing below is the reason the demo does not run out.

### Free-tier caps — per key

| Provider | Free-tier limit | Consumed by |
|---|---|---|
| Groq | ~30 RPM | classification escalation |
| Gemini | ~15 RPM, ~1500/day | reasoning |
| AbuseIPDB | ~1000/day | IP reputation |
| VirusTotal | ~4/min, ~500/day | IP reputation |

### The key pool: N=3, `dev` / `reserved` / `spare` (D26)

**The pressure is not demo day — it is development and rehearsal**, where the
same paths run hundreds of times a day. That asymmetry is the whole
justification for the split:

| Role | Rule |
|---|---|
| `dev` | Burned during development and rehearsal. **Expected to hit caps.** That is its job. |
| `reserved` | **Untouched until the demo.** Full daily window available on the day. |
| `spare` | Fallback if `reserved` runs out mid-demo. |

**Selection is sticky-until-exhausted, never round-robin.** Round-robin burns
all three quotas simultaneously instead of using them as sequential reserve
capacity, which defeats the point of having three. On a 429 the key is marked
cooling (honouring `Retry-After` when present), the pool advances, and a **fresh
call** is issued — never a retry of the failed call on the same key. All keys
cooling produces an honest 503 `rate_limited`, never a silent degrade to
template text. A key that returns 403 is marked **dead on the first one** and
leaves rotation permanently, because a revoked key does not un-revoke and
retrying it costs a request every time (D39).

`N` is config and the pool accepts any `N` generically. The trace records the
serving key **by label only** — `key_id: "groq-reserved"` — never raw material
(I16). ([`test_providers.py`](tests/unit/test_providers.py),
[`test_dead_key_health.py`](tests/failure/test_dead_key_health.py))

### Demo-run arithmetic, at the shipped 30 alerts/min

| | Per minute | 10-minute demo | Free-tier cap | Headroom |
|---|---|---|---|---|
| **Gemini reasoning** | 10 (20 eligible, 10 admitted by budget) | ~100 | ~15 RPM, ~1500/day | 33% RPM, 15× daily |
| **Groq classification escalation** | ~0.1 | ~1 | ~30 RPM | ~300× |
| **AbuseIPDB** | ~1 (9.5% of sources are publicly routable; 15-min per-IP cache) | ~10 unique IPs | ~1000/day | 100× |
| **VirusTotal** | ~1, same cache | ~10 unique IPs | ~4/min, ~500/day | 50× |

**The two gates, and why they are separate:**

- **Classification escalation** at `escalation_confidence_threshold = 0.99`
  fires on **~3 alerts in 1,000** — 0/300 in the eval run above. Every alert the
  model handles confidently costs zero API calls and sub-millisecond latency.
- **Reasoning** at `reason_severity_floor = high` admits ~67% of replay alerts,
  which at 30/min is ~20/min against Gemini's ~15 RPM. The floor is a **policy**
  question (which alerts deserve a narrative); the cap is an **arithmetic** one.
  Choosing the floor to dodge quota would answer the wrong question with the
  wrong instrument, so the floor stays policy-correct and
  `reason_calls_per_minute = 10` enforces the cap — with every turned-away alert
  carrying a **traced skip that names the budget**, never a silent drop.

**A measured run at 12/min still drew 429s on bursts, which is why the shipped
value is 10 and not 12.** Retrieval costs nothing: embedding is local CPU
inference through ONNX, so there is no per-query spend for RAG at all.
Enrichment is cached per IP with a TTL. There is **one stream loop per server,
not one per connection** — otherwise every extra open browser tab would multiply
real API spend ([`test_bounded_under_pressure.py`](tests/load/test_bounded_under_pressure.py)).

`/health` never probes a provider: it serves a 60s-TTL cache so the frontend's
30-second dashboard poll costs zero quota. `/health/deep` is the real
four-provider probe and is manual-refresh only
([`test_health_deep.py`](tests/integration/test_health_deep.py)).

---

## Data

`data/splits/` is committed, so the app runs from a clone with no download. To
rebuild the partitions from source — a ~284 MB archive, digest-pinned:

```bash
.venv/Scripts/python.exe -m scripts.fetch_dataset --glf-hf --attack-days-only
.venv/Scripts/python.exe -m scripts.build_partitions
```

The source is CICIDS2017's `GeneratedLabelledFlows` distribution, not
`MachineLearningCSV`: it carries the real endpoints and capture timestamps the
frozen UI needs, so nothing in an alert is synthesized. Provenance, the defect
list and the verification run are in [`data/README.md`](data/README.md).

**Three-way disjoint partition** — train 5,400 / eval 1,800 / replay 1,800, six
balanced classes — enforced on the **feature vector**, not only on the row id,
and checked in CI. Identifiers (IPs, Flow ID, timestamps) are excluded from the
feature set by explicit allowlist, because CICIDS2017's IP topology is fixed and
a leaked IP column memorizes instantly.

---

## Models

Both artifacts are **committed**, so a cold clone runs with no network (D21).
To rebuild:

```bash
.venv/Scripts/python.exe -m scripts.train_classifier
.venv/Scripts/python.exe -m scripts.build_mitre_corpus
.venv/Scripts/python.exe -m scripts.build_index
.venv/Scripts/python.exe -m scripts.eval_retrieval
```

| Artifact | Location |
|---|---|
| LightGBM boosters, feature schema, metrics, model card | `models/classifier/` |
| MiniLM int8 ONNX weights + tokenizer, checksummed | `models/embeddings/` |
| Corpus embedding matrix + chunk manifest + recall report | `models/index/` |
| MITRE ATT&CK corpus, one JSON per technique | `app/rag/corpus/` |

`train_classifier.py` runs a leak guard on every training run. The original 0.98
absolute ceiling **was adjudicated and replaced** (PLAN §7.3a): it sat *below*
the no-training 1-NN baseline of 0.9844 for this configuration, so no honest
model could ever have stayed under it. The guard is now a relative test against
that baseline plus an unconditional exact-overlap check, with the absolute
ceiling demoted to a 0.995 backstop on the full partition. Evidence:
[`models/classifier/MODEL_CARD.md`](models/classifier/MODEL_CARD.md).

The classifier and the retriever both load in the app lifespan, so a missing,
corrupt or schema-mismatched artifact **stops the server** rather than surfacing
on the first alert.

**Why gradient boosting and not a neural network:** fifteen numeric tabular
columns at this sample size is where boosted trees win. A transformer would be
slower and worse, and fine-tuning one on a few hundred rows would overfit. The
transformer is used where it belongs — retrieval.

---

## Live staged-attack injection (PLAN D23, §4.4a)

`POST /api/v1/ingest/eve` accepts Suricata EVE records from a real Suricata
instance watching a staged attack on hardware we bring. **It is off by default,
and off means the route is not mounted at all** — not mounted and refusing.

```bash
LIVE_INGEST_ENABLED=true
INGEST_SERVICE_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
```

With the toggle on and no token, **the app refuses to start**: the one endpoint
that accepts unsolicited external input does not run unauthenticated.

| Control | Detail |
|---|---|
| Auth | A **dedicated service token**, `Authorization: ServiceToken <…>`, compared in constant time. **Never a user JWT** — a valid admin access token is refused, and there is a test that asserts it. |
| Rate limit | Its own budget (`INGEST_REQUESTS_PER_MINUTE`, `INGEST_BURST`), separate from the global limiter. |
| Size cap | Checked from `Content-Length` **before the body is read**, then re-checked against what arrived. |
| Schema | Strict per-event validation. A bad record is counted, not fatal — a tail on a live file routinely delivers a truncated line. |
| Batch cap | `INGEST_MAX_EVENTS_PER_BATCH`. |
| Escaping | Untrusted fields go through the **same** `app/security/sanitize.py` path as replay. There is no second prompt builder to bypass it with. |
| Isolation | Its **own bounded queue and its own worker task**. Live pressure cannot consume replay's triage slots, and a live failure cannot reach the replay task. |

**Routing (D25) is the demo dynamic.** EVE records have a signature and a
5-tuple and none of the 77 CICIDS flow features, so the LightGBM tier is
**skipped with an explicit traced reason** and the alert goes to the LLM.
Replay showcases the fast tier; live injection showcases the LLM tier. Feeding
the model a zero vector would be a fabricated feature vector scored as a real
prediction.

**Live alerts carry no ground truth** and can never enter the eval or training
partitions. `parse_eve_record` sets `ground_truth_class=None` and `features={}`
by construction and takes no parameter that could set either; `to_eval_rows`
raises on any source outside `SCORABLE_SOURCES = {"cicids_replay"}` (I15/D24).

The response reports `accepted` **and** `dropped` with a per-reason breakdown,
because an `eve.json` is mostly `flow`/`dns`/`http`/`stats` records and an
operator needs to tell a normal ratio from a broken forwarder.

The forwarder is [`tools/eve_forwarder.py`](tools/eve_forwarder.py) — standalone,
runs on the target box, imports nothing from `app/`. See
[`tools/README.md`](tools/README.md).

---

## Security

| Control | Where |
|---|---|
| No JWT in a query string — WebSocket uses a first-message handshake | `app/api/deps.py`, `app/api/routes/stream.py` |
| Password change or deactivation invalidates outstanding tokens | `User.token_version`, exact integer comparison |
| Prompt injection: JSON-escape, length cap, delimiter + untrusted-data preamble, enum-clamped output | `app/security/sanitize.py` |
| MITRE technique IDs dropped unless the retriever actually returned them | `app/agent/nodes/reason.py` |
| CORS closed by default; `*` never together with credentials | `app/main.py` |
| Provider key material never enters a trace, a log, a payload or an error | I16 |
| Secret scan over the tree | `scripts.ci.run secrets` |

Both halves of the injection defence are present — input escaping *and* output
clamping. Clamping alone would leave a model that can be talked into writing
anything it likes in the narrative an analyst reads.

---

## Checks

`make check` is the commit gate — lint, types, tests. `make` is not installed on
Windows, so `./make.ps1 check` runs the identical commands and a test fails the
build if the two target lists diverge
([`tests/ci/test_tooling_parity.py`](tests/ci/test_tooling_parity.py)).

```bash
make check          # lint + types + tests
make ci             # everything CI runs, in CI's order
./make.ps1 check    # the same, on Windows PowerShell
```

Warnings fail the test run (PLAN §12). The suite runs against a throwaway
database in a temp directory, pinned before any app import, and refuses to start
if the resolved URL looks like a runtime database (PLAN I10).

The layers are addressable, and `--strict-markers` makes a typo a collection
error rather than a silently unselected test:

```bash
.venv/Scripts/python.exe -m pytest -q -m failure     # 40 tests: provider down, 429, timeout, dead key, DB locked, queue full
.venv/Scripts/python.exe -m pytest -q -m load        # 11 tests: bounded queues, 503-not-hang, one loop N clients
.venv/Scripts/python.exe -m pytest -q -m invariant   # 84 tests: one named test per PLAN §5 invariant
.venv/Scripts/python.exe -m pytest -q -m contract    # 37 tests: the frozen-frontend response shapes
```

`tests/invariants/test_invariants.py` **parses PLAN §5 out of the plan file** and
fails the build on an invariant with no mapped test, so the mapping cannot rot.

The data and artifact checks run outside pytest so CI can report each as its own
line, and **every one is proven to fail on a deliberately broken input** by
[`tests/ci/test_checks_fail_on_broken_input.py`](tests/ci/test_checks_fail_on_broken_input.py):

```bash
.venv/Scripts/python.exe -m scripts.ci.run           # disjointness, artifacts, skew, label leak, secrets, gitignore, metric literals, env template
.venv/Scripts/python.exe -m scripts.ci.smoke         # cold clone: migrate, boot, /health, network blocked
```

`scripts.ci.run label_leak` writes `build/prompt_corpus.json` — every prompt the
LLM tier would send, with the withheld answer recorded beside it rather than in
it. CI uploads it as a build artifact so the no-leak claim is **auditable rather
than asserted**.

---

## Known limitations

Stated here rather than found by a reader. The full list, with the deliberate
cuts, is in [`REAL_VS_SIMULATED.md`](../REAL_VS_SIMULATED.md).

- **The LLM tier is not a classifier on single CICIDS flows** — 0.2333 against a
  0.1667 random baseline. Measured, understood, and the reason the fast tier
  owns classification.
- **`PROMPT_FEATURES` sends 15 of the 77 columns** the classifier sees.
  `Bwd Packet Length Min` is in the model's feature set and not in the prompt.
  The fifteen were chosen for prompt size in Phase 3, *before* the LLM tier had
  ever been scored, and they are **not changed now** — adding columns after
  seeing a 0.23 is tuning toward an eval number.
- **`webattack-brute-force` retrieves T1505.003 over T1110.** Documented
  retrieval ambiguity, not fixed by hand.
- **`export.ready` is a valid notification event type with no producer.**
  Exports are synchronous — `POST /export` returns the file in the response — so
  there is no later "ready" moment. The enum is pinned by the frozen contract.
- **`Rule.is_enabled` has no toggle endpoint**, because the frozen frontend has
  none. The field is set at create and update and is honoured by the engine.
- **The stale-presence window is 900s**, sized for the frontend's frame cadence:
  FE-2 sends presence on connect and on `visibilitychange` and nothing periodic.
  A periodic heartbeat would let it shrink to a minute or two.
- **Escalation is rare by design** (~3/1000, 0/300 in the published run), so the
  as-shipped system number equals LightGBM-alone. It is reported as **equality,
  not as a win**.
