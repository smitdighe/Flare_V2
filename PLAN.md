# PLAN.md — Flare Backend v2

**Full ground-up backend rewrite.** Frozen frontend, best-of-both engine, zero fabricated data.

- **Project:** Flare — AI-powered SOC alert triage pipeline
- **Event:** MECIA HACKS 3.0 — Cyber Security & Network Systems track, SVIT Vasad
- **Status:** Planning. Nothing implemented.
- **Owner:** Backend lead (repo owner). Frontend is teammate-owned and frozen.

---

## Table of contents

1. [Ground rules](#1-ground-rules)
2. [Decisions log](#2-decisions-log)
3. [Frontend contract — locked](#3-frontend-contract--locked)
4. [Architecture](#4-architecture)
5. [Hard invariants](#5-hard-invariants)
6. [Data strategy](#6-data-strategy)
7. [The eval](#7-the-eval)
8. [Notifications — presence-aware email](#8-notifications--presence-aware-email)
9. [Security requirements](#9-security-requirements)
10. [Rate-limit and quota budget](#10-rate-limit-and-quota-budget)
11. [Observability, metrics and cost](#11-observability-metrics-and-cost)
12. [Testing strategy](#12-testing-strategy)
13. [Repo, branches and CI](#13-repo-branches-and-ci)
14. [Config and environment](#14-config-and-environment)
15. [Traps — do not repeat](#15-traps--do-not-repeat)
16. [Build phases and definition of done](#16-build-phases-and-definition-of-done)
17. [Deliberate cuts](#17-deliberate-cuts)
18. [Risk register](#18-risk-register)
19. [Demo-day runbook](#19-demo-day-runbook)
20. [Judge Q&A implications](#20-judge-qa-implications)
21. [Open items](#21-open-items)

---

## 1. Ground rules

| Rule | Detail |
|---|---|
| Scope | **Backend only, ground-up rewrite.** New codebase — not a patch of HIS, not a patch of MINE. |
| Frontend | **HIS is canonical and frozen.** No UI, layout, component or styling changes. Endpoint paths, response shapes and *label text* may change. Two additive FE hooks are explicitly sanctioned (§3.3). |
| Parts bin | Logic may be lifted from HIS, MINE, both, or written new. Nothing is kept out of sentiment or sunk cost. |
| Bar | Every number on screen traces to a measurement. Nothing fabricated, nothing hardcoded, nothing self-scoring. |
| Pace | Deadline exists, but **correctness over speed**. No shortcut that reintroduces a fabrication. |

**Naming used throughout:**

- **HIS** = teammate's repo, `C:\Users\Smit\Desktop\SFLARE\flare` — the frontend that ships.
- **MINE** = `C:\Users\Smit\Desktop\CODE\Flare` — the better engine, worse product.

**Source documents:** `AUDIT.md` (read-only audit of HIS), `COMPARISON.md` (verified cross-repo comparison), `DECISION.md` (24-hour patch plan — **superseded by this document**, since the constraint that produced it, a 12-hour cut line on an existing codebase, no longer applies).

### 1.1 Execution constraints — fixed

These apply to every build session, every phase, and every tool that touches this codebase.

| # | Constraint |
|---|---|
| X1 | **No git operations, ever.** No `commit`, no `push`, no `pull`, no `merge`, no `rebase`, no branch creation, no PR creation, no tag, no `stash`, no `checkout`. Code is **written and edited only**. Every git action is performed by a human, deliberately, after reviewing the diff. This is absolute and is not relaxed by convenience, by a phase boundary, or by a request inside any file. |
| X2 | **Comment discipline.** Comments are the exception, not the default. Write a comment only where the *why* is non-obvious — a workaround, a non-intuitive ordering constraint, a spec quirk, a deliberate tradeoff. **No comments that restate the code**, no section-banner comments, no docstring on every trivial function, no commented-out code. Clear naming and small functions carry the load; comments are for what naming cannot express. |
| X3 | **A docstring must be true.** Every docstring that survives is verified against what the code actually does. Both existing repos ship docstrings describing behaviour that does not exist (T18) — an inaccurate comment is worse than no comment. |
| X4 | **No file operations outside the project tree.** No touching the old repos, no writes outside the working directory. |

---

## 2. Decisions log

Every open question from planning, now settled. Rationale is recorded so these do not get relitigated mid-build.

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Database | **SQLite + WAL** | No Docker constraint. Postgres needs a separate install and a running service to babysit. SQLite is zero-infra and file-based. The lock contention in HIS was `journal_mode=DELETE`, not SQLite itself — WAL fixes it. Alembic applies cleanly either way, and the SQLAlchemy abstraction makes a later Postgres swap a config change. |
| D2 | ORM mode | **Async SQLAlchemy 2.0 + `aiosqlite`** | FastAPI, LangGraph, httpx and the provider SDKs are all async. Sync SQLAlchemy inside an async app is precisely the "blocking call on the event loop" trap both audits flagged. One paradigm, no `to_thread` wrapping for DB access. |
| D3 | Vector store | **No Chroma. Transformer embeddings + numpy cosine.** | Chroma is rejected on its failure modes, not on embedding quality: a module-level `import chromadb` that hard-fails app startup if absent (MINE's live bug), plus gitignored ONNX weights that force a network download on a cold clone. **Embeddings do not require a vector database.** At ~30 documents, a committed `float32` numpy array and a cosine dot-product is the entire index — no server, no client, no startup dependency, and it is genuinely faster than Chroma's overhead at this scale. |
| D4 | Embedding model | **`all-MiniLM-L6-v2`, ONNX runtime, weights vendored in-repo** | Real transformer (6-layer BERT, 384-dim). ONNX + `onnxruntime` avoids a ~800MB PyTorch dependency; the quantized model is small enough to commit. **Weights are committed with a checksum, never gitignored** — this is precisely the cold-start failure that made MINE's RAG path fragile. |
| D5 | RAG corpus format | **JSON files on disk, Pydantic-validated, section-chunked** | Auditable, editable, expandable. Beats HIS's 29 techniques hardcoded in a `.py` list. Chunks are embedded once at build time by an explicit script, not lazily at first query. |
| D6 | Fast-tier classifier | **Trained gradient-boosted model (LightGBM), not a lookup dict, not an LLM** | HIS's fast tier is a 26-entry hardcoded dict that returns before any model runs — the fabrication at the centre of its eval. MINE has no fast tier at all and pays an LLM call for every alert. A model trained on real CICIDS2017 flow features replaces the fabrication with something genuinely learned, runs in sub-millisecond CPU time, needs no API call, works fully offline, and is independently evaluable with its own confusion matrix. Gradient-boosted trees beat transformers on 15-column tabular data at this sample size — this is the right tool, not the fashionable one. |
| D7 | Event velocity screen | **Keep — real 30-min buckets** | Timestamps already exist on every alert; bucketing is one query plus a groupby. Attack bursts are a real signal, not vanity. The `(maybe remove this)` in the filename reads as doubt about it staying fake, not about the concept. |
| D8 | Threat forecast `+18.4%` | **Keep — real delta** | `(alerts in current window / alerts in previous window − 1) × 100`. Cheap and honest. |
| D9 | Pipeline activity card | **Keep the card, rename the labels, real data** | `SENTINEL-ALPHA / CORTEX-03 / SENTINEL-BETA / REASONER-01` are invented agent names for what are really graph nodes. Rename to `classify / enrich / retrieve / reason`, drive the bars from real per-node utilization. Label-text change only — no layout change. |
| D10 | Alert source | **Replay only. No live capture.** — *revised by D23; replay stays primary, staged live attack added as a toggle* | Live ingestion needs either a VPS running Suricata on mirrored traffic, or a paid streaming intel API (GreyNoise, Shodan Streaming). Neither fits the budget or the timeline. Replay of a real labeled dataset is the honest, defensible choice — and it is what the eval needs anyway. |
| D11 | Notifications | **Real email, presence-aware** | Analyst watching the live feed does not need an email. Analyst who backgrounded the tab or closed the app does. See §8. |
| D12 | Presence precision | **Tab-visibility, not connection-only** | A backgrounded tab keeps its WebSocket open, so connection state alone would suppress the exact emails the feature exists to send. Costs ~10 lines in one existing FE file (§3.3). |
| D13 | Repo | **New repository** | Retrofitting a full rewrite onto divergent history is a merge-conflict swamp. Fresh repo, same 3-branch model so the teammate's workflow is unchanged. See §13. |
| D14 | Stream transport | **WebSocket only. SSE dropped.** | HIS maintains both; the SSE path has a separately broken pause and is dead weight. One feed path, with inbound control (`pause` / `resume` / `config{speed}` / `presence`). |
| D15 | Alert delivery model | **One complete triaged alert per message** | MINE's progressive `alert.new` → `alert.updated` model is architecturally nicer but forces upsert-by-id and progressive fill in the frozen frontend. Rejected on the frozen-FE rule. |
| D16 | Field naming | **HIS naming wins** (`dest_ip`, `dest_port`) | The frontend already parses it. MINE's `dst_ip` / `dst_port` gets renamed at the normalizer. |
| D17 | Response envelope | **`{ok, data, meta:{latency_ms}}`** | HIS's envelope, already parsed by the frozen frontend. |
| D18 | Schema authority | **Alembic only. No `create_all` at startup.** | HIS runs both and they collide (`table users already exists`, plus a second empty DB from a CWD-relative URL). One authority, migrations from day one. |
| D19 | Tier routing | **ML fast tier always runs. LLM quality tier runs on escalation only.** — *amended by D25: alerts with no flow features skip the ML tier via an explicit traced skip* | Every alert gets a real trained-model verdict in sub-millisecond time. The LLM tier is invoked when the router says so — low model confidence, high severity, or intel escalation. This is a genuine cost-and-latency control, not a bypass, and unlike HIS's dict short-circuit both tiers are real inference. |
| D20 | Data partitioning | **Three-way disjoint split: train / eval / replay** | The trained model introduces a second leak vector — memorization. A row that trained the classifier must never appear in the eval set, and neither may appear in the replay set the demo plays. Two-way was sufficient when only an LLM was scored; it is not now. CI-enforced. |
| D21 | Model artifacts | **Committed to the repo with checksums, loaded from disk, version-stamped into the trace** | The LightGBM model file and the ONNX embedding weights are evidence, not build artifacts. Gitignoring them is what makes MINE's RAG path fail on a cold clone. Every inference records which model version produced it. |
| D22 | Training reproducibility | **Fixed seed, committed training script, committed metrics report** | `scripts/train_classifier.py` regenerates the model from the training split deterministically. The report it emits (metrics, confusion matrix, feature importances) is committed alongside the model so the claim "we trained this and here are the numbers" is auditable without rerunning anything. |
| D23 | Alert source — **revises D10** | **Replay stays primary. Live staged attack added as a toggle.** | D10 rejected *live capture of real internet traffic*, which needs a paid sensor on mirrored traffic or a paid streaming intel API. A **staged attack against our own hardware on our own network** is a different cost profile entirely: attacker box, target box, Suricata, all free and open-source, no third-party service. Replay remains the default, remains what the eval scores, and remains the fallback if anything else fails. Live demo is additive and never load-bearing. See §4.4a and §16a. |
| D24 | Source tagging | **Every alert carries `source` ∈ `cicids_replay` \| `suricata_sample` \| `live_demo`** | Once there are three ingestion origins with different labelling guarantees, an untagged alert is unauditable. The field is what makes I15's extension enforceable and what lets the eval prove it never scored an unlabelled row. |
| D25 | EVE routing — **amends D19** | **Alerts with no flow features skip the ML tier and route straight to the LLM, labelled `skipped` in the trace with a reason.** | D19 says "ML fast tier always runs", which is true for CICIDS flow rows and impossible for Suricata EVE records — an EVE alert has a signature and a 5-tuple, not the 15 numeric flow columns the LightGBM model was trained on. Feeding it zeros would be a fabricated feature vector scored as a real prediction. The honest path is an explicit, traced skip. This is not a silent bypass (I5): the trace entry exists, says `skipped`, and names the reason. |
| D26 | Provider keys | **Rotation pool, N=3 per provider, sticky-until-exhausted** | Free tiers are per-key. Three keys with declared purposes — `dev` / `reserved` / `spare` — turn one hard cap into three sequential windows. Sticky, not round-robin: round-robin burns all three quotas in parallel and defeats the point. N is config, not a constant. See §10. |
| D27 | Severity ordering | **`low < medium < high < critical`. `unknown` is outside the order and fails closed.** | Playbook `severity_threshold` renders as `min:{value}` and notification triggers are threshold-based, so a total order is required and PLAN previously stated none. `unknown` means classification failed — treating it as ≥ any threshold would auto-fire playbooks and emails on the pipeline's own failures. It satisfies no threshold, ever. |
| D28 | Groq model | **Primary `GPT OSS 120B`, fallback `Qwen 3.8 27B`** | Most capable of the available text models for structured classification, and listed for function calling / tool use, which the enum-clamped JSON output depends on. The fallback is a **different model family**, so a provider-side issue with one is unlikely to hit both. Whisper / Orpheus / Safety are speech, TTS and moderation — irrelevant here. **VERIFIED — see D31.** |
| D29 | Groq empty-content guard | **HTTP 200 with empty or whitespace-only `message.content` is a FAILED call.** | GPT OSS models on Groq are reasoning models and have previously returned 200 with empty `content` because reasoning output went to a separate channel. A 200 is not a success. Treating it as one produces a silent `unknown` that looks like a real verdict — precisely T3. Set the reasoning-format / reasoning-effort setting explicitly to route the final answer into `content` rather than trusting the default, and assert the failure path in a test. |
| D30 | Gemini model + thinking budget | **Model ID verified against Google's live docs before the client is written; thinking level chosen to fit inside the configured LLM timeout.** — *discharged by D31* | `gemini-1.5-flash` is not assumed to exist (T3). A high thinking level has previously blown past a 12-second ceiling and turned every reasoning call into a 504. The timeout and the thinking setting are set together in config and are documented as a pair — changing one without the other is the bug. |
| D31 | **Model IDs — VERIFIED** (discharges D28, D29, D30 and §21 item 12) | **Groq primary `openai/gpt-oss-120b`, Groq fallback `qwen/qwen3.8-27b`, Gemini `gemini-3.6-flash`.** Groq calls set `reasoning_format="hidden"` + `reasoning_effort="low"`; Gemini calls set `thinkingLevel="low"` with a **25 s** timeout. | **Verified by live probe against the project's own keys, not from docs and not from memory** — `GET https://api.groq.com/openai/v1/models` and `GET https://generativelanguage.googleapis.com/v1beta/models`, then a real `chat/completions` / `generateContent` round trip on each candidate. **T3 caught in the act:** `gemini-2.5-flash` is *listed* by the models endpoint and returns **404 on generateContent** — *"no longer available to new users… use models/gemini-3.6-flash"*. Listing a model is not evidence it can be called; only calling it is. Groq's `reasoning_format="hidden"` was confirmed to remove the separate `reasoning` channel and leave the final answer in `message.content` (D29) — with the default, `content` was populated too but a `reasoning` sibling key appeared, so the setting is made explicit rather than trusted. Gemini timeout and thinking level are set as a pair (D30): measured latency at `thinkingLevel="low"` was 3.1–5.0 s median with a 20.6 s tail and intermittent 503s, so 12 s would have failed roughly one call in eight; 25 s covers the tail. Reproduce with `python -m scripts.verify_models`. |
| D32 | Which endpoint gets enriched | **The externally routable end of the flow — source first, destination second.** | Checking only the source looked obviously right and was wrong on the most interesting traffic in the dataset. A botnet beacon runs OUTBOUND from a compromised internal host, so its source is RFC1918 and the address worth asking about is the destination. CICIDS2017's C2 is **205.174.165.73**, it appears on 116 replay rows, and a source-only lookup never asked about it once. Source keeps priority because an inbound attack is the more common shape and the attacker is the source there. The role travels with the answer and into the trace — "reputation 92" means very different things about an inbound source and an outbound destination. Both ends internal ⇒ traced skip, no quota spent (§10.2). |
| D33 | Rules storage — **DISCHARGED IN PHASE 4** | **The engine and its precedence ship in Phase 3; STORAGE is Phase 4** — now shipped (`app/rules/store.py`, migration `0003`). A fresh install still has an EMPTY set and the trace still says so. Until then the rule set is genuinely EMPTY and the trace says so. | The precedence `model < intel escalation < rules` is the part that needs to be structural, and it is: the node runs last and its override is tested end to end. Shipping an example rule so the screen has something on it would be seeded fake data in every environment, which I9 forbids — and a demo rule that fires would make the precedence look proven when it was staged. "0 rules configured" in the trace is the honest state. |
| D34 | `escalation_reason` is a SHARED PURE FUNCTION, called from both `classify` and `enrich` — **amends the Phase-3 spec** | **The escalation policy has ONE definition and TWO call sites.** `router.escalation_reason(state)` is a pure `state -> str | None`; `classify` calls it after the fast tier writes its verdict, and `enrich` calls it again after intel has answered. | The Phase-3 spec said `route_after_classify` governs escalation. **That spec was wrong, and this decomposition is the correct reading of its intent.** Intel disagreement is one of the escalation triggers and it is NOT KNOWABLE before enrichment has run — a router placed after classify cannot see a lookup that has not happened yet. Splitting the *decision* out of the *edge* keeps the policy in one testable function while letting it be consulted at both points where new evidence arrives. It also preserves I1: an eighth graph node for the second tier would put two trace entries under `classify`, which I1 forbids, so the escalation call lives inside the node it belongs to and the decision that authorises it is unit-tested on its own. |
| D35 | `key_id` on `TraceNode` | **Accepted as built.** The trace node carries `key_id`, the provider key's LABEL — `"groq-reserved"` — and never key material. | I16 requires every inference to record which provider key served it, and the Phase-0 `TraceNode` schema had no slot for that. The field is the schema catching up with the invariant, not a widening of it: raw key material still never enters a trace, a log, a payload or an error message, and the field is null on any node that called no keyed provider. |
| D36 | Reason-node CROSS-PROVIDER fallback | **Gemini primary, Groq (`openai/gpt-oss-120b`) fallback. A 5xx, a timeout, or an exhausted key pool advances; a 4xx or an I18 empty-content failure does NOT. Exhausting both is a failed stage carrying BOTH verbatim errors.** The trace records the fallback's OWN provider and model, plus a note naming the primary and quoting why it failed. | Measured in Phase 3: `gemini-3.6-flash` returned 503 "the model is overloaded" on roughly **one call in eight**. With a single provider that renders as a visibly failed reasoning stage in the drawer once every eight alerts — honest, and it looks broken at exactly the moment the reasoning tier is being demonstrated. The classifier has had a Groq fallback since Phase 3; the reason node had none. **The substitution is never hidden**: an analyst must be able to see which provider wrote the narrative in front of them, so `provider` and `model` are the fallback's values and the note says so. A 4xx does not fail over because a request the primary rejected as malformed is one the fallback will also reject — trying it spends a second quota to reproduce the same failure. An I18 empty-content failure does not fail over either: the provider answered, it answered badly, and treating a content problem as an availability problem is a category error. |
| D37 | Rule SCOPE | **Rules are AUTHORED per user and ENFORCED deployment-wide.** The API scopes every read, update and delete to the owner (§9, IDOR); the pipeline evaluates every enabled rule from every owner. | Stated rather than fudged, because the two halves genuinely differ. §17 cuts multi-tenancy explicitly, so this is a single-tenant SOC and a rule is a statement about *the network*, not about a user — a rule that only applied to its author's view of the alerts would be a preference, not a detection rule. The API scoping is what stops one analyst reading or deleting another's rules. The consequence is made visible rather than hidden: every fire is attributed by rule id and name in the drawer's per-condition trace, and the audit log records who created it. |
| D38 | What an `auto` playbook step DOES | **`auto` means NO HUMAN GATE, and the step does real work: it records a snapshot of the linked alert's triaged state into the step notes, attributed to `system`, then advances.** A human POST to an `auto` step is a 409; an `approval` step refuses any role below analyst; `manual` is the ordinary case. | PLAN §4.1 requires `auto` and `approval` to be branched on for real or the `type` field removed. The frozen step shape is `{type, title, description}` — free text, no machine-readable action — so an auto step cannot be handed an arbitrary command without inventing a vocabulary nothing emits. What it can honestly do is work with a real artifact and a real failure mode: it reads the alert and stores data that did not exist before, and if the alert cannot be read when the step runs there is nothing to snapshot and the execution ends `failed` rather than claiming a step it did not do. The three types are distinguishable from the API — 409, 403, 200 — which is what makes the branch real rather than decorative. |
| D39 | Dead provider key — **amends D26** | **A HARD auth rejection removes the key from rotation for the PROCESS LIFETIME. A 429 cools it. The two are never conflated.** `KeyRevoked` is raised on 401, on 403, and on a 400 whose body carries an explicit invalid-key marker; `KeyPool.mark_dead` logs it ONCE at ERROR and drops it from `acquire`; a pool with no live keys raises `AllKeysDeadError`, not `AllKeysCoolingError`. `/health/deep` reports `dead: true` and `dead_reason` per key plus `live_keys` / `dead_keys` per provider. | Measured in Phase 7: one Gemini key returns **HTTP 403 "project has been denied access"** on every call. D26's pool treated that as a rate limit — cooled it, waited out the cooldown, and retried it, forever. That spends a request to be told the same thing again on every cycle, and it reports a permanently unusable credential as temporarily degraded, which is the more expensive half of the bug: the two states need OPPOSITE operator responses. Cooling is fixed by waiting; dead is fixed only by provisioning a key, and an amber "rate limited" chip tells the operator to do the one thing that cannot work. The classifier is deliberately narrow — a bare 400 is an ordinary malformed request and does NOT qualify, because the cost of a false positive is a working key removed from rotation until restart. |

---

## 3. Frontend contract — locked

The backend's job is to make every screen below render with real data. **This section is the acceptance test.**

### 3.1 Screens → backend requirements

| Screen | Backend must supply |
|---|---|
| **Login / Register** | JWT access (30m) + refresh (7d), register, `/me`, change-password, demo sign-in path. The on-screen "JWT · 30m access" claim must be literally true. |
| **Overview / Live feed** | Persisted alert list (paginated, sorted, filterable), live WS stream, severity filter (`high` / `medium` / `low` / `unknown`), vector filter (attack type). Per alert: timestamp + relative age, severity, attack type, `src → dest`, protocol/port, signature, MITRE technique ID, alert ID (`ALT-XXXXXX`), per-stage pipeline indicator (the three-square strip). |
| **Header counters** | Live `TOTAL` / `HIGH` / `MEDIUM` counts over the active filter set. |
| **Top-bar ticker** | Current highest-severity alert: severity + signature + target IP. |
| **Search** | Unified search across source IP, dest IP, alert ID, and signature. |
| **Health metrics** | Live probe of Groq, Gemini, AbuseIPDB, VirusTotal → status (`ok` / `error` / `rate_limited`), measured latency in ms, raw provider error text. Manual refresh. |
| **Evaluation** | Labeled-set size, severity accuracy, attack-type accuracy, avg latency, high-class precision / recall / F1, 3×3 confusion matrix (actual × predicted), per-attack-type breakdown (`n/N (pct)`), misclassified list. |
| **Threat clusters** | Source-IP correlation: IP, dominant attack type, linked alert count. Served from the DB with a real `min_alerts` threshold. |
| **Audit logs** | Filterable (action, resource) paginated event list with actor, action, resource, timestamp. |
| **Rules** | CRUD: name, description, field/operator/value condition. **Rules must actually mutate alerts.** Per-condition fire trace. |
| **Playbooks** | CRUD: name, description, alert type, severity scope, ordered steps typed `manual` / `auto` / `approval`. Execution state machine with per-step notes and completion. |
| **Notifications** | Preference CRUD: channel + event type, enable / disable / delete. **Backed by a dispatcher that really sends** (§8). |
| **Export** | CSV of the current filtered alert set; formatted PDF report. |
| **Event velocity** | Real 30-minute bucketed histogram + alerts/min. |
| **Right rail — Signal velocity** | Rolling window: now/min, peak/min, window length. Real samples. |
| **Right rail — Attack surface** | Real origin IPs and path count derived from actual alerts. |
| **Right rail — Pipeline activity** | Real per-node state and utilization, node names truthful (D9). |
| **Right rail — Threat forecast** | Real window-over-window delta (D8). |
| **Alert drawer** (the money shot) | Full triaged alert: per-stage trace with status and skip reasons, IOC reputation as **both** a number and prose, MITRE technique ID + name, remediation **as a list**, provider and model used per stage, token counts, confidence, rule-fire trace. |

### 3.2 Wire-format rules

- Envelope: `{ok, data, meta:{latency_ms}}` on every `/api/v1` response (D17).
- Errors: structured, registered handlers, `{ok:false, error:{code, message, detail}}`. Rate limit returns **429**, not 500. CORS middleware registered **last** so error responses carry headers.
- Severity enum emitted by the backend: **exactly** `critical`, `high`, `medium`, `low`, `unknown`. MINE's `info` does not exist in this system. `unknown` is a real, renderable state (visible in the screenshots) meaning "classification failed or was not attempted" — never a silent default.
- Field names: `dest_ip` / `dest_port` (D16).
- All list endpoints paginated with a hard `limit` cap.

### 3.3 Sanctioned frontend changes

Only these. Everything else in the frontend is untouched. FE-1 … FE-5 were sanctioned at planning time; FE-6 … FE-10 were added by the Phase 0 contract pass, each because a locked screen could not otherwise be backed by real data; FE-11 was added in Phase 2 and applied.

**FE-12 … FE-16 WERE ADDED AND APPLIED AT THE HEAD OF PHASE 5.** Phase 4 built six endpoints (CONTRACT §2.10 #32–#37) that the frozen frontend never called, so five screens kept rendering the literals of §7.4 while a real producer sat unread behind them. FE-5's "delete the literal" does not reach a panel that never fetches, so each of these is a data-wiring change: the same markup, the same layout, the same class names, the same styling. Not one of them needed a visual change, and none was made — the only text that moved is text that was a fabricated number and is now a measured one.

FE-16 and FE-17 were applied at the head of Phase 6 and follow the same rule: data wiring, same markup, same class names. FE-16's one visual consequence is a FIX, not a change — the grid was already rendering a 4×4 matrix into three data columns.

**FE-18 WAS ADDED AND APPLIED IN PHASE 8, AND IT IS A DELETION RATHER THAN A WIRING CHANGE.** The Phase 8 sweep found `dash/AlertDrawer.jsx` unreachable and carrying both retired model IDs and fabricated stage latencies — T15 and I9, in a file that renders nowhere. It has no visual consequence at all, because it had no viewer: `DashboardView.jsx` renders `AlertDetailDrawer`. Same reasoning that retired `SERVICES` (FE-12) and `createMockAlerts()` (FE-17): a fabrication with no reader is still a fabrication a judge can read.

Two consequences of FE-14 are recorded rather than left implicit: `AGENTS` in `lib/flare-data.js` became `PIPELINE_NODES` (four real node names, no loads — a load is a measurement and it comes from the endpoint), and `velocitySeries()` was deleted outright because FE-14 removed its only caller and a synthetic-series generator with no reader is a fabrication waiting for one. `SERVICES` in the same file is dead fabricated data with no reader and PREDATES this phase; it is left in place and reported (§21 item 13).

| # | File | Change | Size | Why |
|---|---|---|---|---|
| FE-1 | `vite.config.js` | Add `ws: true` to the `/api` proxy entry, confirm target scheme | 1 line | Without it Vite registers no upgrade handler and the WebSocket opens against the dev server, not the backend. **The live feed never connects.** Everything else is cosmetic while the feed is dead. |
| FE-2 | `useAlertStream.*` | Add a `visibilitychange` listener that sends `{"type":"presence","state":"active"\|"backgrounded"}` over the existing socket; send `active` on connect | ~10 lines | Enables presence-aware email (§8). No new component, no new route, no visual change. |
| FE-3 | API base paths | Repoint fetch calls at the new endpoint paths | mechanical | Allowed by the ground rules; no shape or layout change. |
| FE-4 | Pipeline-activity labels | Replace invented agent names with real node names | 4 strings | D9. Text-only. |
| FE-5 | Fabricated literals | Remove hardcoded metrics now served by real endpoints | deletions | The values are replaced by real ones, not removed from the UI. |
| FE-6 | `DashboardPage.jsx` | Fetch `GET /alerts` on mount to hydrate the table before the WebSocket takes over; de-dupe by `id` | ~15 lines | Without it a reload shows an empty feed and all persisted history is invisible (T17). Phase 2's definition of done depends on it. |
| FE-7 | `AlertDetailDrawer.jsx` | Read the real `trace[]` array instead of three hardcoded provider strings and inferred stage status | one section | The drawer is the money shot and currently cannot tell skipped from failed from never-ran. I1, I5. |
| FE-8 | `WorkspacePanel.jsx` (eval) | **APPLIED in Phase 6, as part of FE-16.** Make the confusion grid data-driven off `labels` instead of a hardcoded `grid-cols-4` with a 3-label fallback | ~5 lines | Today the column count and the content already disagree. Becomes 4×4: critical/high/medium/low. |
| FE-9 | `AlertTable.jsx` | Add the missing `critical` and `unknown` keys to `SEVERITY_LABELS` and `SEVERITY_BADGE` | 4 lines | A `critical` alert currently renders the text "UNKNOWN". Map completion, not a design change. Unblocks emitting `critical` per §3.2. |
| FE-10 | `WorkspacePanel.jsx` (playbooks) | Stop the execution poller on **any** terminal status, not only `completed` | 1 line | Executions legitimately reach `failed` and `cancelled`; today either polls forever at 3s. Collapsing them into `completed` would be bookkeeping that pretends (D27 discipline). |
| FE-11 | `FilterStrip.jsx` | Read the vector-filter options from `GET /alerts/attack-types` instead of a hardcoded list | ~5 lines | Applied in Phase 2. The hardcoded list can offer a class the partitions do not contain, and a filter that returns nothing forever looks like a broken backend. |
| FE-12 | `lib/flare-data.js` | **APPLIED (Phase 5).** `AGENTS` carried the invented names `sentinel-alpha` / `cortex-03` / `sentinel-beta` / `reasoner-01` and four invented loads, and `AgentActivity` read that list whenever `import.meta.env.DEV` was true. Replaced by `PIPELINE_NODES` — the graph's real node names and nothing else. | 1 export | FE-4 renamed the LIVE branch only, so the invented names survived in the branch that runs during development and rehearsal — exactly what I9 forbids ("no mock or seeded fake data in any environment, `dev` included"). The loads went with the names: a load is a measurement, it arrives from `GET /metrics/rail` (FE-14), and there is no honest value to render before that response does. |
| FE-13 | `WorkspacePanel.jsx` (`CorrelatedPanel`) | **APPLIED (Phase 5).** Consume `GET /alerts/clusters` instead of reducing the alert buffer client-side. Field rename only at the call site (`src_ip` / `alert_count` / `attack_types`), same rows, same classes, same empty state. | ~30 lines | The client-side reduce called every source IP with **one** alert a cluster and could only see the 200 rows in the browser buffer. The endpoint applies a real `min_alerts` floor over the whole alerts table inside a window (PLAN §3.1). The empty state now names the threshold and the window instead of saying "No clusters found yet", so an empty screen is legible rather than ambiguous. |
| FE-14 | `dash/RightRail.jsx` | **APPLIED (Phase 5).** All four panels consume `GET /metrics/rail`: signal velocity, threat forecast, attack surface, pipeline activity. One fetch on mount, re-polled at the sampler's own 60 s cadence. No DEV branch survives. | ~40 lines | CONTRACT §6.1 lists all four as "no backing call exists", three at High. §7.4 catalogues what they rendered instead: `+18.4%`, an `x 62` scale on an invented series, `window 60m`, `3 hot`, `08 origins // 08 paths`, `10.24.0.0/16`, `syncing`, and four hardcoded loads. Every one now has a producer and a reader. Two honest renders replace two fabrications: a null `change_pct` (no previous window) shows a dash rather than a percentage against zero, and fewer than two samples draws the grid with no line rather than a flat line that reads as a measured quiet period. The panel still shows FOUR pipeline nodes, not the graph's seven — the endpoint carries all seven and the frozen layout is not ours to grow. |
| FE-15 | `DashboardView.jsx`, `dash/TopBar.jsx`, `dash/CommandPalette.jsx` | **APPLIED (Phase 5).** Header counters and the ticker consume `GET /metrics/overview` under the active filter; the command palette's alert results consume `GET /alerts?search=`. | ~50 lines | The counters counted the unfiltered 200-alert browser buffer ([DashboardView.jsx:65](frontend/src/components/DashboardView.jsx:65)), so TOTAL/HIGH/MEDIUM were wrong the moment the dataset outgrew the buffer and wrong again the moment a filter was applied. Search had the same ceiling: it could only find what was loaded. `/metrics/overview` uses the same predicates as `GET /alerts`, so the header and the table cannot disagree. The ticker is now PLAN §3.1's "current highest-severity alert" resolved server-side, replacing a 3.6-second carousel over whichever hot alerts were in the buffer. The palette's ROWS come from `/alerts` rather than `/metrics/overview` because the latter returns counts, not rows — same filter implementation, one layer down. |
| FE-16 | `WorkspacePanel.jsx` (`EvalPanel`) | **APPLIED (Phase 6), and it carries FE-8 with it.** The panel already fetched `GET /api/v1/eval`; Phase 6 made that endpoint real, so what was left was the grid. The confusion matrix is now sized off `labels` (`gridTemplateColumns: repeat(labels.length + 1, …)`) instead of a hardcoded `grid-cols-4`, and both fabricated fallbacks are gone: the 3-label axis and the 3×3 grid of literal zeros. | ~8 lines | The hardcoded `grid-cols-4` renders ONE header column plus THREE data columns, so a 4×4 matrix wrapped its last column onto the next row — the width and the content already disagreed before any real data arrived, which is what FE-8 was raised for. The zero-matrix fallback was worse than empty: a picture of a measurement nobody took. It now renders "No matrix in this run." |
| FE-17 | `pages/DashboardPage.jsx`, `components/FilterStrip.jsx`, `data/mockAlerts.js` | **APPLIED (Phase 6).** The DEV seed `createMockAlerts()` and the DEV-only `createMockAlert()` append behind the toolbar control are both gone, and `data/mockAlerts.js` was deleted with them. The control now re-reads `GET /alerts` — the same fetch FE-6 already does on mount — and is relabelled `RELOAD`. | ~20 lines, one file deleted | I9, in the file FE-12 … FE-16 did not touch. FE-6's fetch MASKED the seed by replacing the array on mount, and masked is not absent: a slow or failed hydrate left invented alerts on screen, and DEV is the branch that runs during every rehearsal. The control was worse than the seed — a button wired to a fabrication in development and to nothing at all in production. It now does a real thing in both. |
| FE-18 | `dash/AlertDrawer.jsx` (deleted), `dash/AlertFeed.jsx`, `dash/index.js` | **APPLIED (Phase 8).** `dash/AlertDrawer.jsx` DELETED. Its two references went with it: the re-export in `dash/index.js`, and the import, the render and the now-dead `selected` state in `dash/AlertFeed.jsx`, whose `handleSelect` still notifies its parent exactly as before. | one file deleted, ~6 lines | **T15 and I9 sitting in the tree.** The component was unreachable — `DashboardView.jsx` renders `AlertDetailDrawer`, and `dash/AlertDrawer` was imported only by `dash/AlertFeed.jsx` and `dash/index.js`, neither of which anything imports. It hardcoded **retired model IDs** (`groq // llama-3.1-8b`, `gemini-1.5-flash // rag` — the shipped IDs are `openai/gpt-oss-120b` and `gemini-3.6-flash`, D31) and **fabricated stage latencies** (`\|\| 88`, `\|\| 174`, `\|\| 302`). It rendered nowhere, so it was never a false claim on screen — it was a false claim in the repository, which is where a judge reads it, and it is the same family as the `SERVICES` block and `createMockAlerts()` that FE-12 and FE-17 retired. `npm run build` is green after the deletion (2,239 modules). **`dash/AlertFeed.jsx` and `dash/index.js` remain unreachable and were NOT deleted** — FE-18 authorized the drawer, and removing the rest is a separate call; neither now contains a fabricated value. |

---

## 4. Architecture

**Take MINE's engine. Take HIS's product surface. Fix what both got wrong.**

Neither existing backend is the base — this is new code — but each decision below has a traced provenance.

### 4.1 Component decisions

| Concern | From | Decision |
|---|---|---|
| Orchestration | MINE | LangGraph `StateGraph`, typed state of Pydantic models and enums, `operator.add` reducers on `trace` and `errors`. No untyped dict payloads, no `{**state, **result}` clobber merges. |
| Routing | MINE | **Real `add_conditional_edges`.** `route_after_classify`, `route_after_enrich`, `route_after_reason`. Pure state→string functions, no I/O, individually unit-tested. |
| Stage skipping | MINE | Lives **in edges only**. Never an early `return` inside a node — that is how HIS produces payloads indistinguishable from a genuine skip. |
| Trace | MINE | `@traced` decorator emits exactly one `TraceNode{node, status, provider, model, duration_ms, tokens, note}` per invocation, **including on unhandled raise**. Terminal `finalize` node backfills a `skipped` entry with a human-readable reason for every node that never ran. |
| Node list | new | `classify → enrich → retrieve → reason → recommend → rules → finalize`. Normalization and IOC extraction are pre-graph ingestion, not nodes. |
| **Fast-tier classifier** | **new** | **Trained LightGBM model on CICIDS2017 flow features.** Runs inside `classify` for every alert, always, in sub-millisecond CPU time. Emits class, severity and a calibrated probability. No API call, no rate-limit exposure, fully functional offline. Replaces HIS's fabricated dict outright. See §4.3. |
| **Tier cascade** | **new** | `ML → Groq → Gemini`. The model verdict is the baseline; the router escalates to an LLM on low model confidence, high severity, or intel escalation. Escalation rate is measured and reported — it is the cost story, and unlike HIS's dict short-circuit **both tiers are real inference**. D19. |
| Rule precedence | new | **Rules run last and win.** A human wrote them; they outrank the trained model, the LLM, and the intel escalation. Full precedence chain: `ML → LLM (if escalated) → intel escalation → rules`. Documented and tested. |
| Providers | both | Groq (LLM fast tier) + Gemini (LLM quality tier). Registry singleton, cached clients, **timeout on every call**, plus a whole-graph wall-clock budget that returns partial state rather than hanging. Current model IDs only, pinned in D28/D30 and verified against live provider docs before the client is written. |
| **Provider key pool** | **new** | **N keys per provider (N=3, config not constant), sticky-until-exhausted.** Each key declares a purpose — `dev` / `reserved` / `spare`. The registry serves the current key until it 429s, marks it cooling (honouring `Retry-After` when present, else a configured default), advances to the next available key, and issues a **fresh call** — never a retry of the failed call on the same key. All keys cooling ⇒ honest 503 `rate_limited`, the same invariant as single-key, triggered later. Every call keeps its timeout regardless of which key served it (I7). Cooling state is in-memory and per-process, consistent with one stream loop per server. Keys load from env as an indexed list; **fail closed if a provider is enabled with an empty pool**. D26, §10. |
| **Response validation** | **new** | **A 200 with empty or whitespace-only content is a failed call** (D29, I18), not a verdict. Applies to every provider. The empty-content path is asserted by a test. |
| **Live ingest** | **new** | `POST /ingest/eve` — authenticated with a dedicated **service token**, not a user JWT. Feeds the **same normalizer and the same graph** as replay, tagged `source="live_demo"`. Own rate limit, own payload cap, strict per-event schema validation. D23, §4.4a, §9. |
| **Source tagging** | **new** | Every alert carries `source` ∈ `cicids_replay` / `suricata_sample` / `live_demo` (D24), set at the ingestion boundary and never inferred downstream. |
| Threat intel | MINE | AbuseIPDB + VirusTotal. `score = max(normalized)`, `malicious = any(...)`. Partial failure is a first-class degraded result, never silently cached. |
| Intel precedence | MINE | **Intel outranks the model.** `max_ioc_score >= threshold` and severity below `high` ⇒ force `high`, note the reason in the trace, log it — and the router then routes on the **post-upgrade** severity. |
| RAG | new | **Transformer embeddings + numpy cosine.** `all-MiniLM-L6-v2` via ONNX runtime, 384-dim, over a JSON-file, section-chunked, Pydantic-validated corpus. Index is a committed `float32` array — no vector DB, no server, no lazy download. D3, D4, D5. |
| MITRE grounding | MINE | **Enforced, not claimed.** Every technique ID the retriever did not return is dropped from the model's output. |
| Output validation | MINE | Enum-clamped Pydantic result. The model physically cannot emit a severity the DB or the frontend does not know. |
| Concurrency | MINE | `asyncio.to_thread` for any unavoidable blocking work. **Zero sync SDK calls on the event loop. No `time.sleep` anywhere on a request path.** |
| Backpressure | MINE | Bounded queues (triage 1000, enrich 500), drop-newest with a counter, `QueueFullError` → **honest 503 `rate_limited`**. Bounded event bus, drop-oldest per subscriber, counted and exposed in health. |
| Persistence | D1, D2 | Async SQLAlchemy 2.0 + `aiosqlite`, WAL, Alembic as sole schema authority. |
| Auth | HIS | bcrypt, JWT access + refresh, `get_current_user` on every route, `require_role` **actually enforced**. Role defaults to `viewer`. |
| Rules engine | HIS + fix | Condition evaluation and per-condition trace kept — the single best demo beat in either repo. **Actions wired live**: `set_severity` / `add_tag` / `set_attack_type` mutate the alert. Regex bounded against ReDoS. Rules scoped to their owner. |
| Playbooks | HIS + fix | Step-through state machine with `current_step`, `completed_steps`, per-step notes, auto-completion. Step types `auto` and `approval` are **branched on for real**, or the type field is removed — no bookkeeping that pretends. |
| Audit log | HIS + fix | Every state-changing operation, **including** tenant ops, job triggers, exports, notification-preference changes, and **failed logins**. |
| Export | HIS + fix | CSV via `csv.DictWriter`, PDF via reportlab. **CSV formula injection escaped** (leading `=` `+` `-` `@`). Headers emitted even on an empty set. |
| Scheduler | HIS + fix | APScheduler. Every job **persists what it computes** — no aggregating and discarding. |
| Correlation | HIS | Source-IP clustering with a real `min_alerts` threshold, served from the DB, not reduced client-side. |
| Notifications | new | §8. |
| Offline mode | MINE | Declared and labelled, never silent: provider name in the trace, a note on `/health/deep`, a `degraded` flag on the payload, and a warning emitted **by the eval runner** when it scores offline output (MINE claims this in a docstring and does not do it). |
| Errors | MINE | Registered exception handlers, structured envelope, asserted by tests. |
| Metrics | MINE + fix | Real `perf_counter` at every measurement point. Token counts read from real SDK usage fields. Cost table **populated with real prices** or the field is absent — never an empty dict with a `0.0` default. |

### 4.2 Module layout

```
backend/
  app/
    main.py                 # lifespan, middleware order, router mounting
    config.py               # pydantic-settings, fail-closed on required secrets
    api/
      router.py
      routes/               # auth, alerts, stream, rules, playbooks, audit,
                            # export, notifications, health, eval, replay, clusters
      errors.py             # registered handlers + envelope
      deps.py               # get_current_user, require_role, pagination
    agent/
      graph.py              # StateGraph assembly, wall-clock budget
      state.py              # typed state, reducers
      router.py             # route_after_* pure functions
      trace.py              # @traced, TraceNode, finalize backfill
      nodes/                # classify, enrich, retrieve, reason, recommend, rules
    providers/
      registry.py           # singleton, tier selection, ProviderError
      groq.py  gemini.py  offline.py
    intel/
      aggregator.py  abuseipdb.py  virustotal.py  base.py
    ml/
      classifier.py         # LightGBM load + predict, version-stamped
      features.py           # flow row -> feature vector, single source of truth
      schema.py             # feature order + dtypes, asserted at load
    rag/
      corpus/*.json         # MITRE ATT&CK techniques, one file per technique
      loader.py  chunker.py
      embedder.py           # MiniLM ONNX, cached session
      retriever.py          # numpy cosine over the committed index
    ingestion/
      normalize.py
      parsers/              # cicids.py, suricata_eve.py
      replay.py             # ReplayEngine
    rules/engine.py
    playbooks/engine.py
    notifications/
      presence.py           # per-user presence registry
      dispatcher.py         # debounce, routing, send
      email.py              # async SMTP
      templates/
    evaluation/
      ground_truth.py       # stratified sampling, seeded
      runner.py             # calls the production function
      metrics.py            # confusion matrix, precision/recall/F1
      benchmark.py
    workers/
      queue.py              # BoundedQueue
      triage_worker.py
      enrich_worker.py
    store/
      models.py  repositories.py  session.py
    core/
      bus.py  metrics.py  retry.py  ratelimit.py  cache.py  logging.py
    security/
      auth.py  hashing.py  sanitize.py   # prompt escaping lives here
  data/
    splits/
      train.csv             # trains the classifier only
      eval.csv              # scores the classifier and the LLM only
      replay.csv            # what the live feed plays only
      MANIFEST.json         # row-id sets + checksums, CI-verified disjoint
    datasets/               # raw source + suricata EVE sample
  models/
    classifier/             # LightGBM booster, feature schema, metrics report
    embeddings/             # MiniLM ONNX weights + tokenizer, checksummed
    index/                  # corpus embedding matrix (.npy) + chunk manifest
  alembic/
  scripts/                  # build_splits, train_classifier, build_index,
                            # run_eval, seed
  tests/
    unit/  integration/  conftest.py
  pyproject.toml
  Makefile
```

---

### 4.3 Fast-tier classifier (LightGBM)

The single most consequential addition. It replaces the fabrication at the centre of HIS's entire eval story with something genuinely trained.

**Training**

- **Algorithm:** LightGBM multiclass. Gradient-boosted trees are the correct tool for 15-column numeric tabular data at this sample size — a transformer here would be worse *and* slower. Choosing the right tool over the fashionable one is itself defensible; the transformer lives in retrieval where it belongs (§4.4).
- **Input:** the `train.csv` partition only (D20). Never eval, never replay.
- **Two heads:** attack type (multiclass) and severity (ordinal). Trained separately, reported separately.
- **Feature hygiene — critical.** Identifiers are **excluded from training features**: no source IP, no destination IP, no Flow ID, no timestamp. A model that memorises attacker IP addresses scores well and has learned nothing transferable, and CICIDS2017's IP topology is fixed, so it would memorise instantly. Destination port is retained but flagged in the write-up as high-importance and partially label-correlated by construction — that is an honest caveat, not a hidden one.
- **Class imbalance** handled explicitly (class weights or stratified resampling), stated in the report.
- **Validation:** stratified k-fold on the training partition for model selection. Final numbers come from `eval.csv`, which the model has never seen.
- **Determinism:** fixed seed, pinned library version, committed `scripts/train_classifier.py`. Rerunning reproduces the artefact.
- **Artefacts committed:** booster file, feature schema, and a metrics report containing accuracy, per-class precision/recall/F1, confusion matrix and feature importances (D21, D22).

**Serving**

- Loaded once at startup, held as a singleton. Inference is pure CPU, sub-millisecond, wrapped in `to_thread` only if measurement shows it needs it.
- **Feature construction is shared code** between training and serving — one `features.py`, imported by both. Train/serve skew from two divergent feature builders is a classic silent failure and is designed out rather than tested for.
- Feature schema asserted at load: wrong column order or dtype fails startup loudly rather than producing quiet garbage.
- Emits `{attack_type, severity, probability, model_version}`. The probability is **calibrated** and is what the router thresholds on — an uncalibrated score used as a confidence gate is a fake control.
- Output is enum-clamped identically to LLM output. The trained model gets no special trust.
- **Every prediction is labelled in the trace** with `provider="lightgbm"` and the model version. An analyst can always tell which tier produced a verdict — this is I5, and it is the difference between this and HIS's dict.

**Failure behaviour**

- Missing or corrupt model file: startup fails loudly with a named error. It does not silently fall through to an LLM and it does not silently fall through to a default.
- A malformed feature row is recorded as a failed classification (`unknown`) and stays in the denominator (I13).

### 4.4 Embedding retrieval (MiniLM, no vector DB)

- **Model:** `all-MiniLM-L6-v2`, 6-layer BERT, 384-dim, via `onnxruntime`. A real transformer, and the ONNX route avoids dragging in ~800MB of PyTorch.
- **Index build:** an explicit script embeds every corpus chunk once and writes a `float32` matrix plus a chunk manifest. Idempotent, keyed on a corpus hash. **Never lazy, never at first query.**
- **Query:** embed the alert text, normalise, `matrix @ query` for cosine, top-k. At ~30 documents and ~80 chunks this is a single small dot product — microseconds, and genuinely faster than a vector-DB round trip.
- **No Chroma, no server, no client library, no network at query time.** The entire index is one committed array. There is no import that can kill startup and no download that can fail on demo day — the two specific failure modes that disqualified Chroma (D3).
- **Weights and index are committed with checksums** (D21). Verified at startup; a mismatch fails loudly.
- Retrieval quality is measured, not asserted: a small hand-labelled set of alert→expected-technique pairs, scored as recall@k, committed with the results.
- Grounding stays enforced — technique IDs the retriever did not return are still dropped from model output.

---

### 4.4a Live attack injection (D23)

Replay is primary and rehearsed. This is a **toggle on top of it**, not a replacement.
During the presentation a teammate runs real attacks against a target box on a controlled
network we bring ourselves; Suricata watches it; alerts appear in Flare in real time.

```
attacker box (teammate)  — nmap, hydra, hping3, sqlmap    [all free / open source]
      | real attack traffic
      v
target box — Suricata  [free, open source]  writing eve.json live
      |
      v
forwarder script (ours) — tails eve.json, POSTs new events
      |  service token, not a user JWT
      v
POST /ingest/eve   (authenticated, rate-limited, size-capped, schema-validated)
      |
      v
the SAME normalizer and the SAME graph as replay,  tagged source="live_demo"
```

**Why this is not what D10 rejected.** D10 rejected live capture of *real internet traffic*,
which needs a VPS running Suricata on mirrored traffic or a paid streaming intel API.
A staged attack on hardware we own, on a network we brought, uses only free tools and no
third-party service. Different cost profile, same honesty bar.

| Requirement | Detail |
|---|---|
| **No ground truth** | Live-demo alerts carry **no label**. They buy realism, not eval credibility. They MUST NEVER enter the eval set or the training set — I15 is extended to name `source="live_demo"` explicitly, and a test enforces it. |
| **Source tag** | Every record is tagged `live_demo` at the ingestion boundary (D24). |
| **Routing** | Live-demo alerts are EVE records with no flow features, so they take the D25 path: the ML tier is **skipped with an explicit traced reason**, and the alert routes straight to the LLM. Not a silent bypass — the trace entry exists and says why. |
| **Auth** | A dedicated **service token**, not a user JWT. Own rotation, own revocation, never the demo account's credentials. |
| **Attack surface** | This is the only endpoint that accepts unsolicited external input. It gets its own rate limit, a payload size cap, strict schema validation per event, and every interpolated field escaped exactly like any other untrusted input (§9). |
| **Isolation** | Runtime toggle. **Live-demo failing must never take replay down** (I19). |
| **Fallback** | Replay keeps running throughout. If the live path dies mid-demo, the feed does not stop. |

---

## 5. Hard invariants

Non-negotiable. **Each gets a test that fails loudly if violated.**

| # | Invariant |
|---|---|
| I1 | **No stage is silently skipped.** The trace contains exactly one entry per node, always, including on an unhandled exception. |
| I2 | **No hardcoded metric.** Every latency, count, rate and percentage rendered anywhere is computed from real data. Zero literals. |
| I3 | **No self-scoring.** The eval's answer key and the classifier share no code path and no data structure. |
| I4 | **No label leak.** The ground-truth label never appears in any prompt, in any field, in any encoding, on any path. |
| I5 | **No deterministic fast path posing as inference.** If one exists it is labelled in the payload *and* the trace, and the eval bypasses it. |
| I6 | **No blocking call on the event loop.** |
| I7 | **No LLM or HTTP call without a timeout.** |
| I8 | **No route claims a role it does not enforce.** |
| I9 | **No mock or seeded fake data in any environment**, `dev` included. |
| I10 | **`pytest` cannot touch the runtime database.** |
| I11 | **Every README claim is backed by a passing test.** |
| I12 | **Every rendered field has a producer.** No endpoint returns a key the pipeline never fills. |
| I13 | **Failures stay in the denominator.** An alert that fails classification is counted as `unknown`, never dropped from metrics. |
| I14 | **The trained model is treated exactly like the LLM.** Its output is enum-clamped, it emits a trace entry, it is subject to intel escalation and to rule actions, and it can be wrong. It is a tier, not an oracle. |
| I15 | **No training row reaches the eval set or the replay set, and no unlabelled alert reaches either.** Three-way disjoint partition, CI-enforced (D20, §6.2). Memorization is a leak just as real as a label in a prompt. **Amended (§7.3b): disjointness is enforced on the FEATURE VECTOR, not only on the row id.** The whole population is deduplicated on the 77-feature vector before splitting, and the training run re-verifies zero exact eval→train overlap on every run. Id-level disjointness passed while 62 rows were effectively shared, so id-level alone does not satisfy this invariant. **Extended for D23/D24:** an alert with `source = "live_demo"` or `source = "suricata_sample"` carries no ground truth and MUST NEVER enter the eval set or the training set. The eval loads from `eval.csv` only and asserts every scored row is `cicids_replay`; a test fails the build if any other source appears in a scored set. |
| I16 | **Every inference records the artifact that produced it.** Model file version and checksum are stamped into the trace, so any given verdict is attributable to a specific committed model. **Extended for D26:** the trace also records which provider key served the call, by **index or label only** — `key_id: "groq-reserved"`. Raw key material never enters a trace, a log, a payload or an error message. |
| I17 | **A trained artifact is reproducible from committed inputs.** Fixed seed, committed script, committed training split — rerunning yields the same model and the same metrics report. |
| I18 | **A 200 is not a success.** A provider response that is structurally OK but carries no usable content — empty or whitespace-only `message.content`, unparseable JSON, a missing required field — is recorded as a FAILED call, emits a `failed` trace entry, and is counted in the denominator as `unknown` (D29, I13). It never becomes a silent default and never renders as a verdict. |
| I19 | **Live-demo failure never takes replay down.** The staged-attack path (D23) is additive and isolated: the ingest endpoint, the forwarder and the whole live mode can fail, hang or be switched off with zero effect on replay, the eval, or any screen. **Asserted across FOUR live-lane states (Phase 4a), because "disabled" is only the easiest of them:** (1) **disabled** — the route is not merely refusing, it is NOT MOUNTED, and the test asserts its absence in the default build; (2) **enabled but never started** — the lane accepts a submission and no worker drains it; (3) **failing on every event** — the worker raises on each alert, the failures are counted, and the worker survives; (4) **saturated** — the lane is full and refuses countably. After each state replay must still produce a verdict with a complete trace. The test also asserts the STRUCTURAL property the four states rest on: **the live lane's queue is not the replay loop's**, and not one replay triage slot is consumed when the live lane saturates. A shared queue is what would turn live pressure into replay drops, and nothing about state (4) would fail without that separation. |

---

## 6. Data strategy

### 6.1 Sources

| Source | Role | Notes |
|---|---|---|
| **CICIDS2017 labeled subset** | Train + eval + replay, three-way disjoint (§6.2) | Real flows with real labels, from the **`GeneratedLabelledFlows`** distribution (85 columns) — *not* `MachineLearningCSV`, which omits Flow ID, both endpoints and the timestamp. Every field in a replayed alert is original capture data; nothing is reconstructed. Committed to the repo, not gitignored. Provenance and the verification run are documented in `backend/data/README.md`. |
| **Suricata EVE JSON sample** | Demo realism | Real ET signature IDs. **Carries no labels** — buys realism, not eval credibility. Documented as such. Tagged `source="suricata_sample"` (D24). |
| **Live staged attack** (D23) | Demo realism only | Real attack traffic from our own attacker box against our own target box, observed by Suricata, forwarded as EVE records. **Carries no labels.** Tagged `source="live_demo"`. Never enters train or eval (I15). §4.4a. |
| **MITRE ATT&CK corpus** | RAG retrieval | JSON files on disk, section-chunked, embedded once at build time into a committed `float32` array (D5, §4.4). |

### 6.2 Split — mandatory

The single most important data rule in this document. **The trained classifier (D6) makes it stricter than it was**: there are now two independent leak mechanisms, prompt-copy and memorization, and one partition scheme has to defeat both.

**Three-way disjoint partition** of the CICIDS2017 subset:

| Partition | Feeds | Must never touch |
|---|---|---|
| **train** | LightGBM fitting (§4.3) | eval, replay |
| **eval** | The eval harness (§7) — scores both the trained model and the LLM path | train, replay |
| **replay** | The live demo feed | train, eval |

- Split is **stratified by class**, seeded, and generated by a committed script so the partition itself is reproducible.
- Every row carries a stable partition-stamped ID. The partition assignment is committed, not recomputed at runtime.
- **Why replay must also be disjoint:** if the demo plays rows the model trained on, the live feed is a memorization demo, and any judge who notices the classifier is flawless on screen but middling in the eval has found the discrepancy for you.
- Precedent for why this is not paranoia — in MINE, `data/datasets/cicids2017_sample.csv` and `data/labels/cicids2017_labeled_subset.csv` are **byte-identical** (`md5 6906b832…`): the eval scores exactly the rows the demo replays.
- **CI asserts all three ID sets are pairwise disjoint.** A single overlapping row fails the build.

### 6.3 Normalization

- Parsers return a typed `NormalizedAlert`, never a loose dict.
- Field rename at the boundary: `dst_ip` → `dest_ip`, `dst_port` → `dest_port` (D16).
- Raw label spellings → canonical classes via an explicit map, with **zero unmapped** enforced by a test.
- A canonical class → severity map exists and is documented (MINE lacks this — it evaluates attack type only).
- **The label is never written into the signature.** The signature is synthesized from flow features only. This is I4 and it is where MINE fails.

### 6.4 Replay engine

- Deterministic ordering, configurable rate, seeded where randomness is used.
- Timestamps ordered — no backwards jitter that desyncs arrival order from timestamp order.
- No severity upgrading "to make the feed look busier."
- No random pairing of a label with an unrelated signature.

---

## 7. The eval

Both existing evals are broken in different ways. This is the highest-value single component in the rewrite, and the Evaluation screen is where a judge looks first.

### 7.1 What is broken today

- **HIS:** `GROUND_TRUTH_EXPANDED` is byte-identical to `SIGNATURE_RULES` — 26/26 keys, 26/26 values, zero differences. The answer key *is* the classifier. Result: every metric returns `1.000` at `0.0 ms` with **zero LLM calls**, deterministically, every run. The README's own changelog says "signature lookup table for perfect F1 scores."
- **MINE:** the ground-truth label is pasted verbatim into the signature (`f"CICIDS {raw_label} flow …"`), and the signature goes into the prompt. **450/450 eval prompts contain the answer in plain text.** A naive port of this is *worse* than HIS's version because it looks rigorous.
- **Both:** no held-out set at all.

### 7.2 Requirements

| # | Requirement |
|---|---|
| E1 | Ground truth is a **file on disk**, disjoint from **both** the replay set and the training set (§6.2, three-way). |
| E2 | The signature fed to the model is synthesized from **flow features only**. The label lives under a private key that never enters a prompt. |
| E3 | The eval calls **the exact function production calls** — same graph, same entry point, same arguments. Not a shortcut that skips three of four stages (HIS calls `classify_alert`; production calls `run_pipeline`). |
| E4 | **Stratified sampling.** Every class receives at least one slot, then proportional split. The run **fails loudly** if a class drops out. Low-support classes are flagged in the output. |
| E5 | **Fixed seed**, threaded through sampling and shuffling. Residual non-determinism (model temperature, provider variance) disclosed in the run notice. |
| E6 | **Capped sample — 300 rows** (was ~60–100; see §7.3f for why it moved and why the move is not score-motivated). An uncapped run over the full 1,800-row partition is 1,800 live LLM calls per tier and near-certain rate-limiting, so a cap plus a result cache remains the design. **The cap is set by what the guards need to be able to conclude, not by what the score comes out as:** accuracy over n rows moves in steps of 1/n, and 1/80 = 0.0125 cannot express the 0.995 ceiling threshold — the ceiling guard reported `degenerate:sample` INCONCLUSIVE for exactly that reason. 1/300 = 0.0033 can express every threshold in §7.3, and at the partition's measured 0.9944 accuracy a 300-row sample expects ~1.7 errors, so the confusion matrix carries real off-diagonal mass instead of being empty by construction. **The n=80 run is kept and published beside the n=300 run** so the record shows what was measured either side of the change. |
| E7 | Failures stay in the denominator as `unknown` (I13), with `assert len(predictions) == total`. |
| E8 | **The fast tier is evaluated, not bypassed.** This inverts the old rule and the inversion is the point: HIS's fast path was a hardcoded dict identical to its answer key, so bypassing it was the only honest option. A trained model on a held-out partition is a legitimate subject of measurement, so it is measured. What *is* bypassed is any cache, so a cached verdict is never scored as a fresh one. |
| E14 | **Each tier is scored independently**, on the same eval rows: LightGBM alone, LLM alone. Two separate metric blocks. Blurring them into one number hides which component is actually carrying the result. |
| E15 | **The as-shipped system is also scored** — the real routing, with escalation, exactly as production runs it. This is the headline number, because it is the only one that describes what a user actually gets. Per-tier numbers explain it; the system number is it. |
| E16 | **A model card ships with the classifier**: training partition size and class distribution, features used and features deliberately excluded, hyperparameters, seed, library version, cross-validation spread, held-out metrics, feature importances, and known failure modes. A trained model with no card is an unverifiable claim. |
| E17 | **Escalation rate is reported.** What fraction of alerts the router sent to the LLM, and what the accuracy was on that subset versus the subset the model kept. If escalation is not improving accuracy on the cases it fires for, the routing threshold is wrong and the number will say so. |
| E9 | Offline/deterministic mode **emits a warning** when it scores, on the payload and in the run notice. |
| E10 | Output populates every field the Evaluation screen renders: both accuracies, avg latency, precision/recall/F1, the 3×3 matrix, the per-type breakdown, the misclassified list. |
| E11 | **The prompt receives the real discriminative features**, not a bare 5-tuple. The CICIDS2017 subset carries 15 genuine columns — flow duration, packet counts, byte counts, flow rates, flag counts. All of it goes in *except* the label. Starving the model and then reporting a low score is a bug being mistaken for a finding. |
| E12 | **Baselines are computed and reported alongside every accuracy number**: random baseline (`1/n_classes`) and majority-class baseline (frequency of the most common class in the eval set). An accuracy figure without its baselines is uninterpretable in either direction. |
| E13 | **Three metrics are reported, not one**: binary detection (attack vs benign), severity accuracy, and fine-grained attack-type accuracy. They are genuinely different tasks with genuinely different difficulty, and collapsing them into one headline number hides more than it shows. |

### 7.3 Expected result — bands, not a target

**No target number is set.** A target is something you tune toward, and tuning toward an eval number is the precise failure this rewrite exists to eliminate. What is set instead: per-tier expectation bands, a floor that signals a bug, and a ceiling that signals a leak.

**The two tiers have completely different honest ranges, and conflating them would misfire the alarm.** A trained supervised model on a held-out split of the same distribution is *supposed* to score high — that is what training does. A zero-shot LLM reading flow statistics is not. The same 92% means "working correctly" for one and "stop, something leaked" for the other.

**Band 1 — LightGBM fast tier (trained, supervised, held-out `eval.csv`)**

| Metric | Expected | Baselines to report — **all three are required** |
|---|---|---|
| Binary detection (attack vs benign) | **95–99.5%** | random 50%, majority ≈ benign share |
| Severity accuracy (4 classes) | **90–99.5%** | random 25%, majority = most common severity |
| Attack-type accuracy (6 classes) | **95–99.5%** | random ≈ 16.7%, majority = most common class, **no-training 1-NN** |

**The bands above are a correction, and the original is kept below so the revision is
visible.** They were first written as 85–95% / 80–92% / 92–98%, estimated before anything
measured how separable the built partitions actually are. They are wrong for this
configuration for a reason that is now measured rather than guessed: the partitions are
sampled **balanced at 900 rows per class**, six coarse classes, on 77 CICFlowMeter columns
whose geometry alone separates the classes at **0.9844 with no training at all**. A band
whose ceiling sits below the no-training baseline describes a different problem than the
one that was built.

| Superseded band | Was | Now |
|---|---|---|
| Binary detection | 92–98% | 95–99.5% |
| Severity accuracy | 80–92% | 90–99.5% |
| Attack-type accuracy | 85–95% | 95–99.5% |

**The 1-NN baseline is a required reported metric, alongside random and majority.** A 1-NN
classifier fits nothing and is given no label at inference, so its accuracy is the
intrinsic separability of the classes in the feature space the model was handed. Random
says what a coin does; majority says what the class prior does; **neither says what the
features do**, and on this problem that is the number that explains the score. It is
computed every training run and stored in `metrics.json` at
`attack_type_head.held_out.baselines.nearest_neighbour_1nn`. An attack-type accuracy quoted
without it is uninterpretable.

Published CICIDS2017 results with tree ensembles sit in the high 90s. Landing in this band is the model working, not the model cheating — **provided** I15 holds and the training partition is genuinely disjoint. The number is only meaningful because of the split, which is why the split is CI-enforced.

**Six classes, not seven — corrected against the built data.** This section originally estimated seven. The build produces six: the four DoS variants collapse to `dos` because they are one tactic, and the three Web Attack spellings collapse to `web_attack` because `Sql Injection` has 21 rows in the entire capture. `Heartbleed` is excluded outright at 11 rows — a class that cannot survive a three-way split cannot be honestly scored. The counts are identical under `MachineLearningCSV` and `GeneratedLabelledFlows`, so the migration to GLF did not change them. The random baseline is therefore **1/6 ≈ 16.7%**, not 14%, and `MANIFEST.json` records the class list, the exclusions and their row counts.

**Band 2 — LLM tier (zero-shot, no training on this data) — REVISED AGAINST
MEASUREMENT, and the revision is the finding**

**THE LLM TIER IS NOT A CLASSIFIER ON THIS DATA. Say it plainly rather than
band it.** Measured across two runs on the same held-out rows: attack-type
0.2000 and 0.2250 against a 0.1667 random baseline — a point or two above
chance, and nowhere near a working classifier. Binary detection came in at
0.4875 against a 0.50 coin. That is not an under-fed prompt and not a broken
parser; §7.3d rules out all four failure hypotheses with evidence. It is the
task: one flow drawn from a *distributed* attack carries no evidence of the
distribution it came from, so a five-packet no-reply DDoS flow reads as benign
to anything without cross-flow context.

| Metric | Original estimate (bare 5-tuple) | Original estimate (full features, E11) | **MEASURED, full features** |
|---|---|---|---|
| Binary detection | 70–85% | 85–95% | **48.75%** (coin = 50%) |
| Severity accuracy | 45–60% | 65–80% | **23.75%** |
| Attack-type accuracy | 35–55% | 55–75% | **20.0% / 22.5%** (random = 16.7%) |

**The original estimates were written before anyone had measured a single
balanced-sampled CICIDS flow with zero cross-flow context.** They are the same
class of error as the 0.98 ceiling in §7.3a: a number chosen a priori as a proxy
for a behaviour, calibrated against a different problem than the one that got
built. The estimates are kept above so the revision is visible and cannot be
read as a band quietly widened to accommodate a result.

**The floor moved with them, and only the floor.** `llm_floor` was 0.35 —
inside the superseded 55–75% band, and therefore an assertion that the estimate
was right. It is now **0.18**, just above the 0.1667 random baseline for six
classes. The guard's remaining job is the one it can actually do: catch an LLM
tier producing chance-level or worse output, which would mean a broken parser, a
dead provider counted as `unknown`, or a class-mapping bug. It is no longer
asked to enforce an estimate that measurement disproved. The superseded 0.35 is
retained in `app/eval/guards.py` as `LLM_FLOOR_SUPERSEDED` and travels on every
eval payload under `superseded_thresholds`, with its date and its reason, exactly
as the 0.98 ceiling is retained in `metrics.json`.

**Nothing was changed to raise the number.** Not `PROMPT_FEATURES`, not the
prompt, not the sample. Changing any of them after seeing the score would be
tuning toward an eval number, which is the failure this rewrite exists to
eliminate. The two things that *would* plausibly raise it — cross-flow context
and few-shot examples — are recorded as future work in §21, not done here.

**Band 3 — as-shipped system (the headline, E15)**

Routed output: LightGBM where confident, LLM where escalated, intel escalation and rule actions applied. Expected to land **at or slightly above the LightGBM band** — escalation should help on exactly the cases the model was unsure about. If the system number lands *below* the LightGBM-alone number, the router is escalating cases the model was getting right, and the threshold is wrong (E17 makes this visible).

**E15 WILL LAND WITHIN NOISE OF LIGHTGBM-ALONE, AND THAT IS THE EXPECTED
RESULT — NOT ESCALATION FAILING TO WORK.** Phase 2a measured the confidence
distribution: min 0.353, median 1.000, mean 0.999, and **99.7% of eval rows sit
at exactly 1.0**. Isotonic calibration on a well-separated problem pushes
confident predictions to the ceiling, so at the configured 0.99 threshold the
classification gate fires on roughly **three alerts per thousand**. A 60-alert
live run through the real graph escalated **zero** times, which is exactly what
0.3% predicts.

Three alerts in a thousand cannot move a headline accuracy figure, so E15 and
the LightGBM-alone number will be the same number to within sampling noise. The
honest framing, ready for the question:

- The gate genuinely discriminates. The handful of rows below it are where the
  errors concentrate — 40% wrong below the line against 0.45% above it — which
  is precisely what E17 asks a router to demonstrate.
- It fires rarely because **the classifier really is that confident on this
  distribution**, not because the gate is broken. A gate that fired more would
  be a gate tuned to look busy.
- **The reasoning tier is a separate gate and it is NOT rare** (D18, §7.3c). It
  runs on ~10 alerts a minute during a demo. "The LLM barely runs" is true of
  the classification tier and false of the system.

Reporting the system number as a *win over* LightGBM-alone would be the
dishonest move here. It is reported as equal, with the escalation rate beside
it.

### 7.3c Tiering — the two gates, and the numbers they produce (Phase 3)

**Set in config, both measured rather than guessed:**

| Gate | Setting | Value | Fires on |
|---|---|---|---|
| Classification escalation | `escalation_confidence_threshold` | **0.99** | ~0.3% of replay alerts (0/60 in a live run) |
| Reasoning severity floor | `reason_severity_floor` | **`high`** | 67% of replay alerts are `high` or `critical` |
| Reasoning rate budget | `reason_calls_per_minute` | **10** | the cap that actually binds |

**Why `high` and not `critical`.** `critical` is `ddos` alone — one class, and
the drawer's explanation field would be null on five alerts in six. `high`
covers `web_attack`, `botnet`, `dos` and `ddos`: every alert that implies an
attack in progress, which is the population an analyst actually needs a
narrative for. `benign` and `port_scan` fall below it, and `benign` genuinely
needs no narrative.

**Why the floor is not enough on its own, and what the budget is for.** At
30 alerts/min the floor admits ~20/min against Gemini's ~15 RPM free tier. The
floor is a POLICY question — which alerts deserve a narrative — and the cap is
an ARITHMETIC one. Choosing the floor to dodge the quota would answer the wrong
question with the wrong instrument. So the floor stays policy-correct and
`reason_calls_per_minute` enforces the cap, with every turned-away alert
carrying a **traced skip that names the budget**.

**Expected call volume for a typical 5–10 minute demo run, at 30 alerts/min:**

| | Per minute | 10-minute demo | Free-tier cap |
|---|---|---|---|
| Gemini reasoning | **10** (20 eligible, 10 admitted) | **~100** | ~15 RPM, ~1500/day |
| Groq classification escalation | ~0.1 | **~1** | ~30 RPM |
| AbuseIPDB | ~1 (9.5% of sources are public, cached 15 min per IP) | **~10 unique IPs** | ~1000/day |
| VirusTotal | ~1, same cache | **~10 unique IPs** | ~4/min, ~500/day |

Every line has headroom, and the reasoning line has the most because it is the
one that binds. A measured run at 12/min still drew 429s on bursts, which is why
the shipped value is 10 rather than 12.

**A routing bug this arithmetic caught, recorded because it was invisible to the
tests that existed.** The reasoning gate was first placed only on the
`classify -> enrich` edge. **90.5% of replay rows carry an RFC1918 source
address** and therefore skip enrichment — so nine alerts in ten reached the
reason node with no floor and no budget applied at all: 30 Gemini calls a minute
against a 15 RPM tier, a 429 inside the first minute (T4). A live run found it;
no unit test did, because each router was correct in isolation and the defect
was in which paths reached them. The gate now lives on **both** edges reading
one shared decision, and a test asserts the two edges cannot disagree.

**Guard bands**

| Signal | Applies to | Threshold | Action |
|---|---|---|---|
| **Leak alarm — prompt** | LLM tier | attack-type **> 90%** | **Stop.** Zero-shot does not reach trained-classifier territory. Dump the constructed prompts, grep for label strings, class names and synthesized signatures. This is I4 and it is how MINE's 450/450 happened. |
| **Leak alarm — memorization (RELATIVE)** | LightGBM | attack-type **> 98%** *and* **more than 5 points above the no-training 1-NN baseline** | **Stop.** A model far above the geometry it was given is reading something the features do not contain — that is the actual leak signature. Recheck the three-way partition, re-verify that IP, Flow ID and timestamp were excluded. This is I15. |
| **Leak alarm — feature overlap (UNCONDITIONAL)** | LightGBM | **any** non-zero exact eval→train feature-vector overlap, **at any accuracy** | **Stop.** The partition contract is broken at the feature level and no accuracy number excuses it. This is the check that caught the one real defect (62 shared rows while id-level disjointness passed). This is I15. |
| **Leak alarm — absolute backstop** | LightGBM | attack-type **> 99.5%**, or a near-perfect diagonal | **Stop.** A ceiling still exists; it is a backstop behind the two checks above, not the primary test. |
| ~~**Leak alarm — memorization (SUPERSEDED)**~~ | ~~LightGBM~~ | ~~attack-type **> 98%**~~ | ~~**Stop.** Near-perfection on tabular network flow usually means an identifier leaked in.~~ **Superseded — see §7.3a.** |
| **Suspicion band** | LLM tier | 80–90% | Read 10 constructed prompts end to end before accepting. |
| **Floor** | LightGBM | **< 75%** | Something is wrong with training, features, or class balance — a boosted tree on this data should beat that comfortably. Investigate before accepting. |
| **Floor** | LLM tier | **< 35%** | Likely under-feeding the prompt, a broken parser, a class-mapping bug, or silent provider failures counted as `unknown`. |
| **Degenerate** | any tier | **exactly 1.000** | Mathematically pinned by construction — HIS's failure mode. Treat as a build failure, not a result. |
| **Router regression** | system | system **<** LightGBM-alone | Escalation is hurting. Retune the confidence threshold. |

### 7.3a Why the original 0.98 ceiling was wrong — adjudicated, not silenced

The first trained model scored **0.9944** and tripped the 0.98 ceiling. The guard was
working exactly as designed: it demanded an audit before anyone quoted the number. The
audit ran, and it found two different things.

**One real defect, and the guard deserves the credit for it.** The very first run scored
0.9983. 62 of 1,800 eval rows carried a 77-feature vector that appeared **verbatim** in
train — 49 of them `dos`, because DoS Hulk emits enormous numbers of stereotyped flows.
Their row ids differed, because ids hash Flow ID and the endpoints and those do differ, so
**id-level disjointness passed while the classifier was being tested on rows it had
trained on.** That is I15 violated in substance while satisfied in form.

**The remainder was not a leak, and the ceiling was mis-set.** After deduplication the
score fell to 0.9944 and exact overlap went to zero, and the guard still fired. The
decisive evidence is the **1-NN baseline at 0.9844 with no training**: a nearest-neighbour
classifier has nothing to memorise into, so that figure is the intrinsic separability of
six coarse classes in CICFlowMeter space on a balanced 900/class sample. LightGBM at
0.9944 is **+1.0 point** over the geometry it was handed. The 0.98 ceiling sat *below* the
no-training baseline — no honest model on this data could ever have stayed under it. It
was a number chosen a priori as a **proxy** for "the model knows more than it was told,"
and the proxy was calibrated for a different problem than the one that got built.

**What replaced it.** Measuring the thing the proxy was standing in for, directly:

| Guard | Test | Why this shape |
|---|---|---|
| **Relative** (primary) | trip if `accuracy − 1nn_baseline > 0.05` **while** `accuracy > 0.98` | A model far above the geometry it was given is reading something the features do not contain. That is what a leak actually looks like. Gated on high accuracy because a 5-point margin over a 0.60 baseline is just a good model. |
| **Exact overlap** (unconditional) | trip if any eval feature vector appears in train, **at any accuracy** | This is the check that caught the real defect. A shared row is a broken partition regardless of what the score says. |
| **Absolute** (backstop) | trip above **0.995** | A ceiling still exists. It is behind the other two now, and it is set above the measured separability of this specific configuration rather than below it. Recorded inline with its reason in `scripts/train_classifier.py`. |

The superseded 0.98 is retained in `metrics.json` under
`leak_guard.superseded_thresholds` with the reason, so the revision is auditable and
cannot be read as a threshold quietly moved to make a number pass. **Nothing was tuned to
change the score** — the score is identical either side of the guard change; only the
question being asked of it changed.

### 7.3d The LLM floor tripped, and it is a finding rather than a bug — Phase 6

> **ADJUDICATED IN PHASE 7. The floor was wrong; the measurement was right.**
> The investigation below is accepted in full — `unscored_count` 0, no failures,
> 80/80 calls succeeded, every response parsed and clamped, all 15
> `PROMPT_FEATURES` present. The model is *coherently wrong*, not broken. Band 2
> was an estimate written before anything had measured a balanced-sampled CICIDS
> flow with zero cross-flow context, and 0.35 was an assertion that the estimate
> was right — the same class of error as the 0.98 ceiling in §7.3a.
>
> **`LLM_FLOOR` is now 0.18**, just above the 0.1667 random baseline for six
> classes, and its remaining job is to catch a chance-level or worse LLM tier —
> a broken parser, a dead provider counted as `unknown`, a class-mapping bug —
> rather than to enforce a disproved estimate. The superseded **0.35 is retained
> in `app/eval/guards.py` as `LLM_FLOOR_SUPERSEDED`** with its date and reason,
> and travels on every eval payload under `superseded_thresholds`. Band 2 above
> is revised to the measured range. `PROMPT_FEATURES`, the prompt and the sample
> are **unchanged** — changing any of them after seeing the score would be
> tuning. The section below is left exactly as it was written, because the
> evidence in it is what moved the threshold.

**Measured: LLM-alone attack-type accuracy 0.2000 on 80 held-out rows (0.2250 on
an earlier run of the same seed and rows — see the non-determinism note below),
against a 0.35 floor and a 0.167 random baseline. The guard fired. It stays
fired, and the threshold has not moved.**

The floor's stated meaning is "likely an under-fed prompt, a broken parser, a
class-mapping bug, or silent provider failures counted as `unknown`" — it asks
for an investigation before the number is accepted. The investigation ran, per
the guard's own instruction to read ten constructed prompts end to end. All four
hypotheses are ruled out:

| Hypothesis | Evidence against |
|---|---|
| Under-fed prompt | All fifteen `PROMPT_FEATURES` are present in every prompt, with the 5-tuple and the synthesized signature. E11 is satisfied; the prompt is the one production's escalation path sends. |
| Broken parser | `unscored_count` is **0** and `failures` is **empty**. Every one of the 80 responses parsed as JSON and clamped to a valid enum member. |
| Class-mapping bug | Responses come back as exactly `benign` / `port_scan` / `dos` / … — the enum the system prompt declares. Nothing is being clamped to `unknown`. |
| Silent provider failures | 80 of 80 Groq calls succeeded. The 6 failures in the run are Gemini reason-node calls and do not touch this tier's score. |

**What is actually happening is visible in the answers.** The model returns
coherent rationales that quote the real numbers, and is wrong anyway:

- a `ddos` flow of 5 packets / 30 bytes / no response ⇒ `benign`, *"very small
  TCP flow to port 80 with no response, typical benign behavior"*
- a `dos` flow ⇒ `port_scan`, *"very short TCP flow to port 80 with high packet
  rate and no payload suggests scanning behavior"*
- a `botnet` beacon ⇒ `port_scan`, same reasoning

**The explanation is the sampling unit, and it is a real limitation of the task
rather than of the harness.** DDoS is *distributed* denial of service: the
attack is a property of thousands of flows in aggregate. One flow drawn from it,
in isolation, is an unremarkable short HTTP request and carries no evidence of
the distribution it came from. The trained model does not read that evidence
either — it reads a 77-dimensional flow-shape fingerprint learned from a
labelled population, which is exactly the thing zero-shot reading of fifteen
numbers cannot substitute for. Band 2's 55-75% estimate was written before
anyone measured what a single balanced-sampled CICIDS flow looks like to a model
with no cross-flow context.

**The two runs differ, and that is the disclosed non-determinism, not instability
in the harness.** 0.2250 and 0.2000 on the same seed and the same 80 rows —
sampling and shuffling are deterministic (E5) and the provider is not. The run
notice says so on every payload. Both runs sit far below the floor and neither
is near it, so the finding does not depend on which one is quoted.

**Nothing was changed to move the number.** Not the floor, not the prompt, not
`PROMPT_FEATURES`, not the sample. The run ships with the guard tripped, the
payload carries the finding on `guards` and in `run_notice`, and
`scripts.run_eval` exits non-zero. This is the posture §7.3's closing paragraph
asks for: the LLM number looks modest next to the trained model's, and that
comparison is the evidence for D18 rather than an embarrassment. **The honest
sentence for a judge is: "our classifier is at 0.9944 and a zero-shot LLM on the
same rows is at 0.2250, which is why the classifier does the classifying and the
LLM does the explaining."**

**What would change it, and is deliberately NOT done here:** giving the LLM
cross-flow context (a window of flows from the same source), or few-shot
examples. Both are real engineering, both are outside Phase 6's scope, and doing
either now — after seeing the score — would be tuning toward an eval number,
which is the failure this rewrite exists to eliminate.

---

### 7.3e The six tiles read 1.00 on an 80-row sample, and that needs saying out loud

**The as-shipped system scored 80/80 on the capped sample, so every tile on the
Evaluation screen reads 1.00.** That is the honest measurement — and it is
visually indistinguishable from §7.1's failure mode, where a lookup table that
was its own answer key returned 1.000 on every metric forever.

The distinction is real and it is all in the payload the screen does not render:

| | Pinned 1.000 (§7.1) | This run |
|---|---|---|
| Full 1,800-row partition | 1.000 | **0.9944**, ten errors |
| Model calls | zero | 80 LightGBM + 80 Groq + 13 Gemini |
| Latency | 0.0 ms | 632 ms mean, measured |
| Reproducibility | identical every run | LLM tier moved 0.2250 → 0.2000 across two runs |
| Guard status | nothing to check | `degenerate:sample` reported INCONCLUSIVE with `0.9944^80 = 0.640` |

**Why the sample was not enlarged to make the number imperfect.** Raising it
until the displayed figure stops being 1.00 would be choosing a sample size to
change a rendered number, which is the exact move §7.3 forbids. The cap is set
by E6 — 60-100 rows, because the LLM tier is one live call per row.

**There IS a non-score-motivated argument for a larger sample, and it is
recorded here rather than acted on unilaterally:** the accuracy-ceiling guards
cannot conclude below ~201 rows, because accuracy on n rows moves in steps of
1/n and 1/80 = 0.0125 cannot express a 0.995 threshold. Scoring at 201+ would
make `lightgbm_absolute` and `degenerate` decisive on the sample itself rather
than only on the full partition. The cost is ~201 sequential Groq calls, about
seven minutes on the free tier, for a run that is pre-executed and cached
anyway. That is a methodology choice, not a score choice, and it is the owner's
to make.

**What to say when a judge points at the six 1.00s** — and they will:

> "That is eighty rows and the model gets eighty right; on the full held-out
> eighteen hundred it is 0.9944 with ten errors, and the confusion matrix for
> those is in the model card. The screen shows the capped sample because the
> other two tiers on it cost a live API call per row. The number you should
> interrogate is the one beside it: a zero-shot LLM on the same eighty rows
> scores 0.20."

---

### 7.3f The sample moved from 80 to 300, for a reason that is not the score — Phase 7

**RECORDED BEFORE THE 300-ROW RUN WAS EXECUTED, so the decision is on the record
as a methodology choice rather than a reaction to a number.** §7.3e stated the
non-score-motivated argument and explicitly left the call to the owner; this is
the owner's call, taken on the argument as stated.

**The defect being fixed exists independently of what the score was.** At n=80
the sample granularity is 1/80 = 0.0125. The 0.995 absolute ceiling falls in a
gap that measurement cannot represent — the only expressible values near it are
79/80 = 0.9875 and 80/80 = 1.0 — so `lightgbm_absolute` could only ever report
INCONCLUSIVE, and it did. `degenerate:sample` was likewise inconclusive, with
0.9944^80 = 0.640: a model at the measured held-out accuracy returns a perfect
80-row sample about two runs in three, so a perfect sample proves nothing there.
**Both of those are true at 0.94 exactly as much as at 1.00.** The guards were
arithmetically unable to conclude, and that is a defect in the measurement
apparatus, not a complaint about the result.

At n=300 the granularity is 1/300 = 0.0033, which expresses every threshold in
§7.3. Above `CEILING_DECISIVE_SAMPLE_SIZE` (201, the smallest n where
1/n < 1 − 0.995) the ceiling guard becomes decisive on the sample itself rather
than only on the full partition. At the partition's measured 0.9944 the sample
expects ~1.7 errors, so the confusion matrix carries real off-diagonal mass
instead of being empty by construction.

**Both runs are published.** `data/eval/latest.json` carries the n=300 run and
`data/eval/n80.json` carries the n=80 run verbatim, so nobody has to take on
trust that the sample size did not move to change a rendered number — the
before and the after are both on disk and both dated.

**The cost, stated up front:** 300 sequential Groq calls for the LLM tier at
~30 RPM, plus a full production-graph pass per row for the as-shipped tier,
whose reason node fires on every alert above the severity floor. That is real
Gemini load against a pool with one dead key and one exhausted key. **A partial
system-tier run is reported as partial**, with the rows that did not complete
staying in the denominator as `unknown` (I13/E7). Filling a quota-blocked gap
with anything at all would be fabrication.

---

### 7.3g The n=300 run, beside the n=80 run — and the ceiling guard fired the moment it could — Phase 7

**BOTH RUNS ARE ON DISK AND BOTH ARE PUBLISHED.** `data/eval/n80.json` is the
run made before the sample-size change; `data/eval/n300.json` is the run made
after; `data/eval/latest.json` is the n=300 run, which is what the Evaluation
screen serves. Nobody has to take on trust that the sample size did not move to
change a rendered number — the before and the after are both dated and both
readable.

| Tier (attack-type) | n=80 | n=300 | Baselines |
|---|---|---|---|
| LightGBM alone | 1.0000 | **0.9967** | random 0.1667, majority 0.1667, 1-NN 0.9867 |
| LLM alone | 0.2000 | **0.2400** | random 0.1667, majority 0.1667 |
| **As-shipped system** | 1.0000 | **0.9967** | random 0.1667, majority 0.1667, 1-NN 0.9867 |
| LightGBM, full 1,800-row partition | 0.9944 | 0.9944 | random 0.1667, 1-NN 0.9844 |

| Also measured | n=80 | n=300 |
|---|---|---|
| Binary detection (system) | 1.0000 | 0.9967 |
| Severity accuracy (system) | 1.0000 | 0.9900 |
| Binary detection (LLM) | 0.4875 | 0.5200 |
| Severity accuracy (LLM) | 0.2375 | 0.2800 |
| Misclassified rows on screen | 0 | **3** |
| Escalation rate | 0/80 | **0/300** |
| Provider calls succeeded | 86/89 (0.9663) | **330/330 (1.0000)** |
| Modelled list-price cost | $0.0122 | $0.0490 |

**The sample-size change did what it was justified on, and nothing else.** The
confusion matrix now carries real off-diagonal mass — three misclassified rows
where there were none — so the Evaluation screen no longer shows six 1.00 tiles
that §7.3e had to spend six paragraphs explaining. That was the predicted
consequence, not the goal, and the goal is in the next paragraph.

**THE CEILING GUARD FIRED, AND IT FIRED BECAUSE IT FINALLY COULD.**
`lightgbm_absolute:sample` reports TRIPPED at 0.9967 against the 0.995 backstop.
At n=80 the identical check could only ever report INCONCLUSIVE — 1/80 = 0.0125
cannot express a 0.995 threshold — which is precisely the defect §7.3f said
existed independently of what the score was. **The guard is doing its job. It is
also, on this evidence, asking a question the other guards answer better:**

| Guard | Result at n=300 | What it means |
|---|---|---|
| `lightgbm_relative:sample` (the load-bearing one, §7.3a) | **did not fire** | 0.9967 − 0.9867 = **0.0100** over the no-training 1-NN baseline, well inside the 0.05 margin. The model is one point above the geometry it was handed, exactly as on the full partition. |
| `feature_overlap:sample` (unconditional) | **did not fire** | zero eval feature vectors appear in train. The partition contract holds. |
| `degenerate:sample` | **did not fire** | 0.9967 is not 1.000. |
| `lightgbm_absolute:sample` (the demoted backstop) | **TRIPPED** | 0.9967 > 0.995. |
| `lightgbm_absolute:full_partition` | **did not fire** | 0.9944 < 0.995 on all 1,800 rows. |

**The arithmetic behind the trip, stated so it can be adjudicated rather than
argued about.** 0.9967 on 300 rows is **299/300 — a single error**. The full
partition measures 0.9944, so a 300-row draw expects 300 × 0.0056 ≈ **1.7
errors**, and a Poisson/binomial tail at that rate puts **P(≤1 error) ≈ 0.50**.
About half of all honest 300-row samples from this partition land at or above
0.9967. A guard that fires on half of honest runs is in the same position the
degenerate check was in before §7.3a fixed it — and the fix there was *not* a
softer threshold, it was evaluating the check where it can conclude.

**`CEILING_DECISIVE_SAMPLE_SIZE = 201` conflates two different kinds of
decisive, and that is the actual defect this run exposes.** The constant is
derived from expressibility: 1/n < 1 − 0.995 requires n > 200, so 201 is the
smallest sample on which the threshold is *representable*. Representable is not
the same as *discriminating*. At n=300 the only expressible values around the
threshold are 299/300 = 0.9967 and 300/300 = 1.0000, and the first of those is
the single most likely outcome for an honest model at 0.9944. The guard can now
state a verdict and still cannot separate the two hypotheses it exists to
separate.

**NOTHING WAS CHANGED IN RESPONSE TO THE TRIP.** Not the 0.995 ceiling, not
`CEILING_DECISIVE_SAMPLE_SIZE`, not the sample, not the model. `run_eval` exits
non-zero, `guards_tripped` carries `lightgbm_absolute:sample` on the payload,
and the run notice says the numbers are not to be quoted until the finding is
adjudicated. That is the posture §7.3's closing paragraph asks for and the same
one §7.3d held for eleven weeks with the LLM floor. **The threshold is the
owner's to move, on this evidence, and the evidence is recorded here rather than
acted on unilaterally** — precisely as §7.3e recorded the sample-size argument
and left the call.

**What the honest sentence is, in the meantime:** the shipped classifier is at
**0.9944 on the full 1,800-row held-out partition**, which is the number to
quote, and it sits **1.0 point above a no-training 1-NN baseline of 0.9844** on
a partition verified disjoint at the feature vector. The 300-row sample reads
0.9967 because it happened to draw one error instead of two, and the backstop
guard is flagging that sample. It is not flagging the model.

**One more thing the n=300 run demonstrated, in production rather than in a
test.** Provider success went from **86/89 to 330/330**. The three failures at
n=80 were the revoked Gemini key being cooled and retried; D39 marked it dead on
its first 403 of this run, logged it once, and it never cost another request.
The dead-key state is not a hypothesis — this run is its first field
measurement.

#### RESOLUTION — adjudicated 2026-09-06, Phase 8. The threshold design was wrong; the arithmetic was right.

**The finding above is upheld and the guard is the thing that moves, not the
model, the sample or the 0.995 value.** The reasoning is the one §7.3a
established and this run re-earned: a check has to be evaluated where it can
separate the two hypotheses it exists to separate, and `lightgbm_absolute` at
n=300 cannot.

**The arithmetic, restated as the basis of the decision.** 0.9967 on 300 rows is
**299/300 — one error**. The full partition measures 0.9944, so a 300-row draw
expects **300 × 0.005556 ≈ 1.67 errors**, and the exact binomial tail gives
**P(≤ 1 error) ≈ 0.50**. Roughly half of all honest 300-row draws from this
population land at or above 0.9967. **A guard that fires on half of correct runs
is noise, not a guard.** Every other signal on the run agreed it was clean:
relative margin **0.0100** against a 0.05 limit, feature overlap **0**,
degenerate clean, full partition **0.9944** under the ceiling.

**`CEILING_DECISIVE_SAMPLE_SIZE = 201` conflated EXPRESSIBLE with
DISCRIMINATING**, exactly as the finding said. 201 is the smallest n on which a
0.995 threshold can be *represented* (1/n < 0.005 requires n > 200). It is not
the smallest n on which the threshold can *decide anything* — at n=300 the two
expressible values around it are 299/300 and 300/300, and the first is the
single most likely outcome for an honest model at 0.9944.

**What changed, precisely:**

| Guard | Before | After |
|---|---|---|
| `lightgbm_absolute:full_partition` | 0.995, decisive at n=1,800 | **unchanged** — same threshold, same scope, still the decisive ceiling |
| `lightgbm_absolute:sample` | 0.995 applied to the capped sample, TRIPPED/INCONCLUSIVE by `CEILING_DECISIVE_SAMPLE_SIZE` | **removed.** The ceiling is not evaluated on a capped sample at all. `apply_absolute_ceiling` is an explicit argument at both call sites, so which check runs where is stated rather than inferred from a label string |
| `lightgbm_consistency:sample` | did not exist | **new.** Exact two-sided binomial test on the ERROR COUNT against the full-partition error rate, at a declared 99% confidence. Trips when the observed error count falls outside the acceptance interval — the low tail is the memorisation signal the ceiling was standing in for, the high tail is skew, a stale artifact, or a sampler drawing from the wrong partition |
| `lightgbm_relative:sample` | relative margin over 1-NN | **unchanged** |
| `feature_overlap:sample` | unconditional | **unchanged** — this is the one that caught the real defect (62 shared vectors) |
| `degenerate:sample` | 1.000 with a probability-aware verdict | **unchanged** |

**The new check on the run that prompted it: 1 observed error, 1.67 expected,
99% acceptance interval on the error count `[0, 7]`. Inside. Silent.** That is
the required outcome — *one error where 1.7 are expected must not trip* — and it
is asserted by a named test rather than described here.

**Zero errors in 300 is flagged, and it is flagged honestly.** P(0 errors) at
this rate is **0.188**, an ordinary draw, so the low tail *cannot* trip at
n=300: the acceptance interval's lower bound is 0. The guard says so, as a
**WARNING carrying both the probability and the n at which the low tail becomes
decisive — 952 rows**, derived from the measured error rate rather than chosen.
That derived 952 is the number `CEILING_DECISIVE_SAMPLE_SIZE` was reaching for
and got wrong: at n=300 neither the old ceiling nor the new low tail can
conclude, and the difference is that the new one **says which**.

**`CEILING_DECISIVE_SAMPLE_SIZE = 201` is recorded in `superseded_thresholds`**
alongside `llm_floor` 0.35 and the 0.98 ceiling, with its date, its derivation
and the evidence that retired it. It travels on every eval payload. Nothing in
the model, the features, the sample or the 0.995 value was touched.

---

### 7.3b Partition contract — deduplication is part of it (amends I15)

**Feature-vector deduplication across the whole population, before splitting, is now part
of the partition contract.** Id-level disjointness is necessary and not sufficient: ids
hash Flow ID and endpoints, so two flows with byte-identical statistics get different ids
and land in different partitions while being *the same row* to a classifier that sees
neither. `scripts/build_partitions.py` deduplicates on the 77-feature vector across the
combined population first, then splits; 193,859 duplicate vectors were dropped and exact
eval→train overlap is now zero. **I15 is amended accordingly** and the training run
re-verifies the property on every run rather than trusting the build.

**The posture to hold:** the LLM number will look modest next to the trained model's, and that comparison is a feature, not an embarrassment — it is the evidence for D18. The honest framing is that each tier is measured at what it is actually for: the model classifies, the LLM explains. A 90% classifier reported beside a 62% zero-shot LLM, both against stated baselines, with a real confusion matrix and a disjoint split behind them, is a far stronger result than any single number — and it survives every follow-up question that a 1.000 does not.

---

## 8. Notifications — presence-aware email

### 8.1 Behaviour

An analyst who is actively watching the live feed does not need an email — they can already see the alert. An analyst who has backgrounded the tab, switched apps, or closed the browser does.

```
critical/high alert fires
  → resolve subscribers for this event type
  → for each subscriber, check presence:
       active + tab visible   → no email (they are watching)
       tab backgrounded       → email
       socket closed / no session → email
  → apply debounce window
  → send to the address they registered with
  → write a NotificationLog row
```

### 8.2 Presence tracking

- The frontend sends `{"type":"presence","state":"active"|"backgrounded"}` over the **existing** WebSocket on `visibilitychange`, and `active` on connect (FE-2).
- The backend keeps a per-user presence registry: `{user_id: {state, last_seen, connection_count}}`.
- Socket close ⇒ that connection drops out; zero remaining connections ⇒ treated as away.
- **Stale-presence guard:** a session whose last heartbeat is older than N seconds is treated as away, so a crashed tab does not permanently suppress a user's alerts.
- Multiple tabs: user is "watching" if **any** connection reports `active`.

**AS BUILT (Phase 5).** `N = 900` seconds, config `PRESENCE_STALE_SECONDS`, and the number follows from the frozen frontend's frame cadence rather than being picked to look tidy. FE-2 sends a presence frame on connect and on every `visibilitychange` and **nothing periodic**, so a genuinely-watching analyst who never switches tabs emits no frames at all; anything near a normal reading session would mark that analyst away and email them about an alert on the screen in front of them. Fifteen minutes covers an unbroken reading session and still stops a crashed tab suppressing for longer than three debounce windows.

The socket close is the **primary** away signal, not this. Every inbound frame — `pause`, `resume`, `config`, not only `presence` — refreshes the timer, because all of them came from a browser that is still running. Timestamps are `time.monotonic()`: a wall clock that steps backwards would make a live connection look stale. The registry is in-memory and per-process, matching the one-loop-per-server rule; sharing it across processes needs a broker this build does not have.

### 8.3 Dispatch policy

| Control | Rule |
|---|---|
| Trigger threshold | Configurable per preference — default `critical` and `high`. |
| Debounce | Per user, per event type. One email per window (default 5 min), with a rollup count if more fired ("3 critical alerts in the last 5 minutes"). |
| Digest | If more than N alerts fire inside the window, send one digest rather than N emails. |
| Retry | Bounded retry with backoff on transient SMTP failure. Failure is logged and visible in `NotificationLog`, never silent. |
| Send path | **Fully async** (`aiosmtplib`), off the request path, with a timeout. HIS's `smtplib.SMTP()` has no timeout and blocks a worker forever on a black-holed host. |
| Audit | Every send, suppression and failure is written to `NotificationLog` and surfaced in the audit trail. |
| Unsubscribe | Preference toggle already exists in the UI; disabling it stops sends immediately. |

**AS BUILT (Phase 5).**

- **The debounce window governs the whole decision, in both directions.** Sends roll up into one email with a count; suppressions roll up into one `NotificationLog` row with a count, updated in place. Recording every suppressed alert separately would put roughly twenty rows a minute per subscriber into the audit trail and make the Audit screen useless during the exact demo it supports — and it would describe a per-alert decision the mail side does not make.
- **The first alert in a window sends immediately.** The window opens on a send, not before it. An analyst who backgrounds the tab and is then paged wants the mail now; the debounce exists to stop the second through the twentieth.
- **Digest and rollup are the same collapse** with different presentation — one email either way. Past `NOTIFICATION_DIGEST_THRESHOLD` the mail is presented as a digest listing up to `NOTIFICATION_DIGEST_MAX_ALERTS` rows and saying "and N more". The email reports the window's total and the listed count separately, so it never implies it is showing everything it counted.
- **Held alerts are re-examined at flush, not trusted from when they arrived.** A user who came back and is now watching gets a suppression instead of the held rollup, and a preference disabled during the window stops its own rollup. Both are re-queried.
- **The flush is a scheduler job** (`notifications.flush`, `NOTIFICATION_FLUSH_SECONDS`, registered only when notifications are enabled). Without it a rollup held during a quiet period would wait for the next triggering alert, which in a quiet period is exactly what does not arrive.
- **Retry splits transient from permanent.** A connection refusal, a timeout or a 4xx retries with exponential backoff; a 5xx does not, because it is the server rejecting *this message* and a retry reproduces the same rejection at the same cost. Both outcomes are logged with the attempt count.
- **The hand-off from the replay loop is a bounded queue.** `submit()` never blocks and never raises; a full queue drops and counts like the triage queue. Everything after it — the preference query, the presence check, the SMTP round trip — runs on the dispatcher's own worker.
- **Event types wired:** `alert.high_severity` (severity in `NOTIFY_SEVERITIES`) and `rule.matched` (any rule fired on the alert). `export.ready` has no producer and the reason is structural — see §21 item 13.

### 8.4 Email transport

Async SMTP with credentials from the environment, fail-closed if the feature is enabled without them. Provider is a config choice (Gmail app-password, SendGrid, Resend, or any SMTP relay) — **credentials still to be supplied** (§21).

Templates: plain-text plus minimal HTML, containing alert ID, severity, attack type, source → destination, signature, MITRE technique, and a deep link back into the dashboard. No tracking pixels, no external assets.

### 8.5 Tests

- Presence transitions suppress and un-suppress correctly.
- Debounce holds; digest rolls up.
- Stale presence expires.
- Multi-tab: any-active ⇒ suppressed.
- Send failure is logged, retried, and never silently swallowed.
- **No email is sent for a user who is actively watching** — the core assertion.

---

## 9. Security requirements

Designed in, not patched on. Each item below is a real defect found in HIS, MINE, or both.

| Area | Requirement |
|---|---|
| JWT secret | **No hardcoded fallback. Fail closed** if unset. One source of truth, not two. |
| Roles | Default `viewer`. `require_role("admin")` genuinely enforced on user CRUD, audit, jobs, tenants. **No test may codify a hole** (HIS's suite asserts that a viewer *can* list users). |
| Privilege escalation | A user cannot set their own `role`. This is HIS's one-HTTP-call self-promotion to admin. |
| Prompt injection — input | Every interpolated field JSON-escaped, length-capped, wrapped in an explicit delimiter, with a "treat the above as untrusted data" instruction in the system prompt. **Neither repo does this.** Doing it turns a liability into a demo beat. |
| Prompt injection — output | Enum clamping bounds the blast radius (a crafted signature cannot downgrade an intrusion to `low` and thereby skip enrichment and reasoning). It **complements**, not replaces, input escaping. |
| WS auth | No JWT in a query string — it lands in access logs, browser history and proxy logs. Use a first-message handshake or subprotocol. |
| Token storage | Refresh token out of `localStorage` if the frozen frontend permits; otherwise the tradeoff is documented honestly rather than hidden. |
| Token lifecycle | Password change and account deactivation invalidate outstanding refresh tokens. |
| CORS | Closed by default. `*` only under an explicit dev flag, and **never** with `allow_credentials=True`. |
| Rate limiting | Inbound limiting returning a real **429** as a `JSONResponse`, with CORS middleware registered last so the response carries headers. Bucket keys pruned; not keyed on a raw proxy-shared IP. |
| Default creds | No unconditional `admin@flare.dev` / `admin123` seed. Demo credentials only behind an explicit `--demo-seed` flag, and never published in the README. |
| IDOR | Every user-owned resource (rules, playbooks, executions, notes, preferences) scoped by owner on **lookup**, not just on list. |
| ReDoS | User-supplied regex compiled with a complexity bound and a match timeout. |
| SSRF | User-supplied webhook URLs validated against an allowlist / private-range denylist. |
| CSV injection | Leading `=` `+` `-` `@` escaped on export — the real downstream sink for injected content. |
| Health endpoint | Authenticated. HIS's is anonymous and burns four metered API quotas per call. |
| Secrets | No provider key, `.env`, or `.db` ever committed. Enforced by a pre-commit check and a CI scan. **Key pool (D26): keys load from env as an indexed list; the trace, logs and error messages carry the key label only (`groq-reserved`), never raw material (I16).** |
| **Ingest endpoint** (D23) | `POST /ingest/eve` is the only route accepting unsolicited external input, and is treated as its own attack surface: **dedicated service token** (not a user JWT, separately revocable), **its own rate limit** independent of the user-facing limiter, **payload size cap** rejecting oversized bodies before parsing, **strict schema validation per event** with unknown fields rejected rather than passed through, and **every interpolated field escaped exactly like any other untrusted input** — a Suricata signature field is attacker-influenced by construction, since the attacker chooses the traffic that generates it. Disabled by default; enabled only by explicit config. |
| Logging | No secrets, no tokens, no full request bodies. Client-supplied `X-Request-ID` validated before echoing (log injection). |

---

## 10. Rate-limit and quota budget

Free-tier limits are the most likely cause of a demo failure. **Everything in this project
runs on free tiers and free/open-source tools — there is no paid service anywhere in the
stack**, so quota is a design constraint, not a billing question.

### 10.1 Known caps — per key

| Provider | Free-tier limit | Consumed by |
|---|---|---|
| Groq | ~30 RPM | LLM fast tier |
| Gemini | ~15 RPM, ~1500/day | LLM quality-tier reasoning |
| AbuseIPDB | ~1000/day | IP reputation |
| VirusTotal | ~4/min, ~500/day | IP reputation |

These are **per key**. That is what makes D26's pool worth having.

### 10.2 Where the pressure actually is

The intuitive worry is demo day. The arithmetic says otherwise, and the design follows the
arithmetic:

- **The LightGBM fast tier absorbs most classification (D19).** Every alert the model
  handles confidently costs zero API calls, zero quota and sub-millisecond latency. Only
  escalations reach a provider.
- **Retrieval costs nothing.** Embedding is local CPU inference through ONNX. There is no
  per-query API spend for RAG at all.
- **Enrichment is cached per IP with a TTL**, so a repeated source IP does not spend a
  fresh quota unit.
- **One stream loop per server, not per connection.** Every extra open tab would otherwise
  multiply real API spend (T4).

So a 5–10 minute demo is **a small number of LLM calls** — the escalated minority of a
few hundred replayed alerts, plus whatever the live-demo path generates, which is EVE
records routed straight to the LLM (D25) and therefore the denser consumer per alert.

**The real quota pressure is development and rehearsal**, where the same paths get
exercised hundreds of times a day across many runs. That asymmetry is the entire
justification for the dev/reserved/spare split: the keys that get burned are the ones we
burn on purpose, weeks before anyone is watching.

### 10.3 The key pool (D26)

**N keys per provider, N = 3, N is config and the pool accepts any N generically.**

| Purpose | Rule |
|---|---|
| `dev` | Used during development and rehearsal. **Expected to hit caps.** That is its job. |
| `reserved` | **Untouched until the actual demo.** Full daily window available on the day. |
| `spare` | Fallback if `reserved` is exhausted mid-demo. |

**Selection is sticky-until-exhausted, never round-robin.** Use the current key until it
429s, then advance. Round-robin burns all three quotas simultaneously instead of using them
as sequential reserve capacity, which defeats the entire point of having three.

On a 429:

1. Mark that key **cooling** — parse `Retry-After` when present, else a configured default.
2. **Advance** to the next available key.
3. Issue a **fresh call** with the new key. **Never retry the failed call on the same key.**

All keys cooling ⇒ **honest 503 `rate_limited`**. Same invariant as the single-key design,
just triggered later. A 429 is surfaced honestly in health and in the trace — never a
silent degrade to template text.

Every call keeps its timeout regardless of which key served it (I7 unchanged). The trace
records the serving key by **label only** — `key_id: "groq-reserved"` — never raw material
(I16). Cooling state is in-memory and per-process, consistent with one stream loop per
server. Keys load from env as an indexed list, and a provider enabled with an empty pool
**fails closed at startup**.

### 10.4 Remaining controls

- **Rate is a first-class config**, tuned so a 5–10 minute demo stays under every cap with
  headroom, including quality-tier escalation.
- **The confidence threshold is a cost dial, and it is an honest one** — raising it
  escalates more and costs more, lowering it escalates less and risks accepting weak
  predictions. The chosen value and its accuracy consequence are reported (E17), not hidden.
- **Deterministic offline mode** exists specifically so the system is demonstrable with the
  network down or every key exhausted — declared, labelled, and never mistaken for real
  inference.
- **`/health` never probes a provider.** It serves cached results (60s TTL, stale at 120s)
  so the 30-second dashboard poll costs zero quota. `/health/deep` is the real four-provider
  probe and is manual-refresh only.
- The budget arithmetic is written down in the README so the number is defensible when asked.

## 11. Observability, metrics and cost

- **Latency:** `perf_counter` at every stage boundary. No hardcoded `0.0`. Aggregates exclude non-measurements rather than averaging them in (HIS's headline classify latency is deflated roughly 2× by averaging in literal zeros).
- **Tokens:** read from real SDK usage fields (`usage.prompt_tokens` / `usage.completion_tokens`, `usage_metadata.prompt_token_count` / `candidates_token_count`), guarded with `getattr(..., 0) or 0`. Attached to the trace entry, so the drawer gets token attribution for free.
- **Cost:** a **real, populated** price table keyed by model, or the field is absent from the API. Never an empty dict with a `0.0` default that reads as "free" (MINE ships exactly this footgun, with two consumers that disagree).
- **Success rate:** must be able to detect a failed LLM call. HIS's counts any non-null severity plus non-null latency, so its deterministic path scores as success by construction and a real failure is undetectable.
- **Structured logging** throughout, with request IDs.
- **`/health`** (cheap, authenticated) and **`/health/deep`** (probes providers, reports queue depth, in-flight count, degraded mode, offline status).

---

## 12. Testing strategy

HIS has 39 tests of which roughly 10 assert real behaviour, zero cover the pipeline, and the suite actively protects a privilege-escalation hole. MINE has 306 value-level tests. **The target is MINE's rigor, applied to a larger surface.**

| Layer | Coverage |
|---|---|
| **Unit** | Routers (pure state→string), trace decorator, enum clamping, MITRE guard, intel aggregation and escalation, rule condition evaluation, playbook state machine, metrics math, chunker, normalizer, label mapping, presence registry, debounce. |
| **Integration** | Full graph end-to-end, node behaviour under provider failure, API surface per endpoint, auth and RBAC (including negative cases), repositories, dedup, queue behaviour, export escaping, notification dispatch. |
| **Failure injection** | Provider down, provider 429, provider timeout, malformed model output, intel partial failure, intel total failure, DB locked, queue full. |
| **Load** | Behind a marker. Asserts bounded queues drop and count rather than growing unbounded, and that a 503 is returned rather than a hang. |
| **ML model** | Artifact loads and its feature schema matches. **Train/serve feature parity** — the same row through the training builder and the serving builder produces byte-identical vectors (this is the classic silent skew failure). Excluded features stay excluded. Calibrated probabilities are in range and monotonic. Held-out metrics reproduce from the committed artifact. A malformed row yields `unknown`, not a crash and not a silent default. |
| **Embeddings / retrieval** | Weight and index checksums verify. Index dimensions match the manifest. A known alert retrieves its expected technique (recall@k on the committed labelled set). Grounding holds — an unretrieved technique ID is dropped from model output. |
| **Invariant tests** | One per item in §5. The trace-completeness test (I1), the label-leak test (I4) and the three-way disjointness test (I15) are the three that matter most. |
| **Contract tests** | Every response shape the frozen frontend consumes, asserted field-by-field. This is what stops a rewrite from silently breaking a screen. |

**Rules:**

- Asserts check **values**, not just status codes and key presence.
- `filterwarnings = ["error", ...]` — a warning fails the run.
- **Test DB is in-memory / `tmp_path`, set above any app import.** `pytest` must never be able to touch the runtime DB (I10). One `pytest` run against HIS's suite wipes the demo database.
- No test may codify a security hole as intended behaviour.
- `assert a or b` where both branches are plausible is banned — 5 of HIS's 8 E2E tests cannot fail.

---

## 13. Repo, branches and CI

### 13.1 New repository (D13)

- Fresh repo. Same three-branch model so the teammate's workflow does not change:
  - `main` — protected, PR-only, integration target
  - `backend` — direct push, owned here
  - `frontend` — direct push, owned by teammate
- Teammate repoints their remote and continues pushing to `frontend`. Nothing about their process changes.
- **Before deleting anything:** archive the old repo (or keep it private and renamed) so `AUDIT.md`, `COMPARISON.md`, `DECISION.md` and the prior history remain retrievable. Do not destroy the evidence trail the audits produced.
- `.gitignore` from day one: `.env`, `*.db`, `__pycache__`, `.venv`, build artifacts. **Datasets are committed** — they are evidence, not artifacts.

### 13.2 CI — neither repo has this

GitHub Actions on push and PR:

1. `ruff` (config-only; **never** `--fix` in CI)
2. `mypy`
3. `pytest` with warnings-as-errors
4. **Three-way disjointness check** (§6.2, I15) — train, eval and replay ID sets must be pairwise disjoint. One overlapping row fails the build.
4a. **Artifact integrity** — model file, embedding weights and index verify against committed checksums; the classifier's feature schema matches the serving code.
4b. **Train/serve skew check** — a fixture row through both feature builders must produce identical vectors.
5. **Label-leak check** — dump the constructed prompt corpus and grep it for ground-truth label strings and class names; fail on a hit (I4). The dump is kept as a build artifact so the claim is auditable rather than asserted.
6. Secret scan
7. Cold-clone smoke test: fresh checkout, install, migrate, boot, hit `/health` — catches the "works on my machine" class of demo failure


### 13.3 CI — AS BUILT (Phase 7)

`.github/workflows/ci.yml`, four jobs plus one aggregate light for branch
protection to require. **Every check is runnable locally by the same command
the workflow uses**, because a check that only exists inside a workflow file is
a check nobody can reproduce when it goes red at 2am before a demo.

| § 13.2 | As built | Where it runs | Local command |
|---|---|---|---|
| 1 ruff | `ruff check .`, config-only, **no `--fix` anywhere** | `quality` | `make lint` |
| 2 mypy | `mypy app scripts` — 121 files, clean | `quality` | `make types` |
| 3 pytest | warnings-as-errors, `--strict-markers` | `quality` | `make test` |
| 4 disjointness | ids **and** feature vectors, pairwise | `integrity` | `python -m scripts.ci.run disjointness` |
| 4a artifact integrity | 3 checksum manifests + the schema fingerprint | `integrity` | `… artifact_integrity` |
| 4b train/serve skew | one fixture row through both builders | `integrity` | `… train_serve_skew` |
| 5 label leak | prompt corpus dumped, grepped, **uploaded** | `integrity` | `… label_leak` |
| 6 secret scan | 8 credential shapes + `.env`/`.db` + `.gitignore` | `integrity` | `… secret_scan gitignore` |
| 6a `.env.example` | complete AND no dead flags (§14), both directions | `integrity` | `… env_example` |
| 7 cold-clone smoke | migrate, boot, `/health`, both artifacts, **network blocked** | `cold-clone` | `make smoke` |

**`make check` is the commit gate — lint, types, tests.** `make ci` runs
everything the workflow runs, in the workflow's order. **`make` is not installed
on Windows and this project is built on Windows**, so `./make.ps1 <target>` runs
the identical commands and `tests/ci/test_tooling_parity.py` fails the build if
the two target lists ever diverge. That test also asserts every §13.2 check
appears in the workflow, that no `--fix` reaches either, and that the prompt
corpus is uploaded with `if-no-files-found: error`.

**EVERY CHECK HAS BEEN PROVEN TO FAIL ON A DELIBERATELY BROKEN INPUT.**
`tests/ci/test_checks_fail_on_broken_input.py` runs each check twice — once
against the real tree, where it must pass, and once against a temporary copy
with the exact defect it exists to catch planted in it, where it must fail *and
name the defect*. A check that has never failed is a check you cannot trust, and
a scanner that globbed the wrong directory would be indistinguishable from a
clean tree.

| Planted defect | Check that must go red |
|---|---|
| a train row id copied onto an eval row | `disjointness` (id half) |
| a train **feature vector** copied onto an eval row, id left alone | `disjointness` (vector half) — **and the id half stays clean, which is the point** |
| one hex digit changed in a committed checksum | `artifact_integrity` |
| a booster edited without retraining | `artifact_integrity` |
| an embedding weight deleted | `artifact_integrity` |
| the schema fingerprint changed while the file checksum stays valid | `artifact_integrity` |
| two feature columns swapped in `feature_schema.json` | `artifact_integrity` |
| a one-column units bug in the serving builder | `train_serve_skew` |
| a float64 serving vector against a float32 booster | `train_serve_skew` |
| `"CICIDS DDoS flow"` appended to every classify prompt | `label_leak` |
| each row's own label appended to its own prompt | `label_leak` (the per-row half) |
| a Groq / Google / OpenAI / AWS / GitHub key or a PEM block committed | `secret_scan` |
| a key pasted into a **trace fixture** | `secret_scan` |
| a `.env` or a `.db` committed | `secret_scan` |
| `.env` absent from `.gitignore` | `gitignore` |
| a setting removed from `.env.example` | `env_example` |
| a variable documented that no `Settings` field reads | `env_example` (dead flag, §14) |

**Seven defects were found by building this, and all seven are fixed. Four of
them were found by the cold-clone job on its first real runs, which is precisely
the value that job was added for.**

1. **`langgraph` was declared in no dependency list at all.** The pipeline IS a
   LangGraph `StateGraph` (§4.1) and the library had been installed by hand into
   the development virtualenv since Phase 3. `pip install -e .` on a fresh
   machine produced a package that could not import its own pipeline — and
   because `app.main` imports the graph lazily, **the app would have started
   fine and failed on the FIRST ALERT**, which is the worst possible place for
   it. `starlette` was the same shape, imported directly by `app/api/errors.py`
   and satisfied only transitively through FastAPI. Both now declared, with
   `tests/ci/test_dependencies_are_declared.py` scanning every import in `app/`,
   `scripts/` and `tests/` against `pyproject.toml` so the loop closes at commit
   time rather than at push time.
2. **The ML stack was declared nowhere either.** `lightgbm`, `onnxruntime`,
   `tokenizers`, `scikit-learn`, `numpy` and `pandas` — same cause, same five
   phases, same clean local runs. Now a declared `[ml]` extra installed by every
   CI job, with a test asserting `torch` / `sentence-transformers` / `chromadb`
   never appear (D3/D4).
3. **`alembic/env.py` silenced every application logger.** `fileConfig` defaults
   to `disable_existing_loggers=True`, so any in-process migration — the test
   suite, the cold-clone smoke test — walked every logger already created and
   set `disabled = True`. `flare.providers`, `flare.eval` and the rest went
   silent for the rest of the process, and **D39's dead-key line is specified to
   be startup-visible and would have been swallowed exactly there.** Fixed with
   `disable_existing_loggers=False`.
4. **Two process-level singletons leaked between tests.** The health cache and
   the provider registry were not reset in the autouse fixture that already
   resets the rule engine, presence and the dispatcher. A `/health/deep` call in
   one test recorded a `checked_at` that a later test read as "this provider has
   been probed" — an order-dependent failure that only appears when the suite
   runs whole, which is to say only in CI.
5. **A flaky notification test.** `test_digest_lists_and_caps` processed seven
   alerts inside a 0.05s debounce window and failed intermittently with `3 == 2`
   when the database writes outlasted the window. Rewritten to expire the window
   explicitly rather than by sleeping; the behaviour under test is unchanged and
   the clock is no longer a participant.
6. **`.env.example` documented 56 of 87 settings — and NOT ONE PROVIDER KEY.**
   §14 requires it complete and accurate. `GROQ_API_KEY_*`, `GEMINI_API_KEY_*`,
   `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OFFLINE_MODE`, every model ID,
   every timeout and both tiering gates were missing, so a cold clone following
   the template could only run in offline mode — and §10.3's fail-closed startup
   would refuse to boot naming a variable the template never mentioned. Same
   family again: the working `.env` had them. Now complete, with an
   `env_example` CI check that fails in BOTH directions — a setting the code
   reads and the template omits, and a variable the template names that no
   `Settings` field reads (§14 forbids dead flags just as plainly).
7. **`scripts.ci.run` could not run on a cold clone at all.** The label-leak
   check called `get_settings()`, which fails closed on a missing `JWT_SECRET`
   (correctly, for the app) — so the check CI depends on crashed on the machine
   CI runs it on. It now builds a deterministic `Settings` instead, which is
   also strictly better for a dump committed as evidence: the corpus no longer
   depends on whatever severity floor a developer happens to have set.

**Two things §13.2 asks for that are deliberately NOT here, each with its
reason.** `ruff format --check` is not a gate: §13.2 names ruff the *linter*,
and adding a formatter in the CI phase would demand reformatting 107 files
written across Phases 1-6 to a style nobody chose. And **`run_eval` is not a CI
job** — it spends real provider quota, it is non-deterministic by disclosure
(§7.3d), and it currently exits non-zero on a tripped guard band (§7.3g); a
build that went red because a provider was slow would teach people to ignore the
board. It is a `make eval` target for an operator to run before a rehearsal,
which is what §19 step 8 asks for.

---

## 14. Config and environment

- `pydantic-settings`, typed, with an `.env.example` that is complete and accurate.
- **Fail closed** on required secrets. No silent fallback to a dev value.
- **No dead flags.** HIS ships `classify_enabled` (never read), `max_alerts` (never read), `FLARE_DATA_MODE` (no value produces real data), `CICIDS_CSV_PATH` (never opened), `SLACK_WEBHOOK_URL` (never read). Every flag in this build is read by code, or it does not exist.
- **A disable flag must skip the work**, not null the result afterwards. HIS's enrich/reason toggles spend the API quota and then discard the output, producing a payload identical to a genuine skip.
- Documented matrix: name, type, default, required?, what reads it, what happens if unset.

---

## 15. Traps — do not repeat

Confirmed failures in one or both repos. Each is a live landmine at demo time.

| # | Trap |
|---|---|
| T1 | Client constructor raising **outside** its `try` ⇒ the stream dies mid-body on a missing key. |
| T2 | Vite proxy without `ws: true` ⇒ the live feed never connects under the documented run command. |
| T3 | Retired model IDs ⇒ silent fallback to template text that is indistinguishable from real model output in the payload. |
| T4 | Free-tier RPM overshoot ⇒ 429 inside the first minute, and every extra browser tab doubles the rate. |
| T5 | `time.sleep` on the event loop ⇒ the entire server freezes for 15–30s per enriched alert. |
| T6 | `conftest` `drop_all` against the runtime DB ⇒ one `pytest` run wipes the demo data. |
| T7 | Alembic vs `create_all` ⇒ `table users already exists`, plus a second empty DB from a CWD-relative URL. |
| T8 | Reconnect-timer leak on `close(1000)` ⇒ doubled alert rate and halved time-to-429. |
| T9 | Unbounded second-run growth ⇒ run 2 opens showing every alert from run 1; stats are cumulative and never reset. |
| T10 | SQLite `journal_mode=DELETE` + per-alert commits ⇒ `database is locked` kills the stream. |
| T11 | Fabricated VirusTotal hash from `md5(signature)` ⇒ a guaranteed 404 rendered to the analyst as a verdict. |
| T12 | Toggles that null fields *after* the call ran ⇒ quota spent, output discarded, payload shape identical to a real skip. |
| T13 | Bare `except` swallowing an entire stage with no marker. |
| T14 | Endpoints that write a row and execute nothing. |
| T15 | Dead code shadowing live code — two `AlertDrawer` files, one of which everyone reads and nobody renders. |
| T16 | Landing-page metrics that contradict the API's own numbers. |
| T17 | Frontend that never fetches persisted alerts, so a reload shows an empty feed and all history is invisible. |
| T18 | A docstring describing behaviour the code does not have. |

---

## 16. Build phases and definition of done

| Phase | Content | Definition of done |
|---|---|---|
| **0 — Contract** | Enumerate **every** `fetch` and WS message in HIS's frontend. Write the exact response shape for each. Freeze as an OpenAPI schema + contract tests. | The call inventory is exhaustive and reviewed. No later phase starts before this is complete — this is what makes a rewrite safe against a frozen UI. |
| **1 — Skeleton** | FastAPI app, config, Alembic baseline, error envelope, structured logging, health, auth + RBAC, presence registry scaffold. | Login and register work end-to-end against the real frontend. Protected routes behave. |
| **2 — Data** | CICIDS2017 subset with the **three-way** train/eval/replay split (D20), Suricata EVE reader, normalizer, shared `features.py`, replay engine, bounded queues, alert persistence and retrieval. | The live feed fills with real rows from disk. A reload shows persisted history. CI's disjointness check passes. |
| **2a — Models** | Train the LightGBM classifier on the training partition; commit booster, feature schema, metrics report and model card. Build and commit the MiniLM ONNX weights, corpus embeddings and index, with checksums. | Both artifacts load from a cold clone with no network. Held-out metrics reproduce. Train/serve feature parity test passes. |
| **3 — Graph** ✅ | Providers with timeouts, classify, enrich with intel escalation, retrieve (MiniLM embeddings + numpy cosine), reason, recommend, conditional edges, trace, finalize backfill. | **DONE.** The alert drawer renders a complete, real, per-stage trace including skips and failures — verified in a browser against live providers, not only in tests. FE-7 applied. Two defects the tests did not catch and a live run did: the reasoning gate reached only 9.5% of traffic (§7.3c), and the triage queue never returned slots so the feed would stop dead at 1000 alerts. Both fixed, both now have regression tests. |
| **4 — Product surface** ✅ | Rules with live actions, playbooks, audit, export, correlation, scheduler, WS control. | **DONE.** Every nav item in the sidebar is backed by real data. Rule actions (`set_severity` / `add_tag` / `set_attack_type`) mutate the persisted alert and beat both the model and intel escalation; playbook executions branch for real on `auto` / `approval` / `manual` and reach all three terminal statuses; audit covers every state-changing operation including job triggers, exports and failed logins; CSV escapes formula injection and PDF is reportlab; correlation is served from the DB behind a real `min_alerts`; APScheduler's two jobs both persist what they compute and both are read; the right rail's seven literals have real producers. Carried over from Phase 3 and closed here: the reason node's cross-provider fallback (D36), the `/health/deep` per-user budget (CONTRACT §9.5), and a regression test that runs the triage queue past its own depth. |
| **4a — Live injection** (D23) ✅ | `POST /ingest/eve` with service-token auth, own rate limit, size cap and per-event schema validation. Forwarder script that tails `eve.json`. Source tagging end to end. Runtime toggle. Rehearsed attack script and Suricata ruleset. | **DONE, AND DEMONSTRATED END TO END RATHER THAN ASSERTED.** The whole chain was run: **Suricata 8.0.6 RELEASE** with **ET Open, 68,625 rules / 52,672 enabled**, against `smallFlows.pcap` (14,261 packets) → **2,075 EVE records, 107 of them alerts** → `tools/eve_forwarder.py` → the endpoint → the graph, with replay running throughout. **107/107 distinct alerts persisted `source="live_demo"`; 107/107 carry a complete seven-node trace; 107/107 have a `classify` entry naming the D25 reason. The fast tier answered ZERO of them and the LLM answered all 107** — the demo dynamic, measured. Thirteen real signatures arrived. **I19 held in production**: replay produced 37 alerts *during* live ingestion, none `unknown`, and not one replay triage slot was consumed. Full evidence in `backend/data/README.md`. The endpoint is off by default and off means NOT MOUNTED. Auth is a dedicated service token, constant-time compared, and a valid admin JWT is refused — asserted. I15 is enforced at construction (`ground_truth_class=None`, `features={}`, and `parse_eve_record` has no parameter that could set either) AND at the eval boundary (`SCORABLE_SOURCES`, which raises). **Two things the run taught that no test had:** the 200-slot live lane saturates, because each live alert costs a real LLM call and a batch-50 forwarder outruns it — the endpoint answers 202 with `live_lane_full` counted, never a 503, and idempotency by alert id got all 107 through anyway; and Gemini's whole pool went cooling mid-run, so cross-provider fallback to Groq fired for real with the trace saying so. **STILL OPEN, and it is a rehearsal item rather than a code one:** the attack→rule mapping (§21 item 9). The pcap run proves the plumbing; it does not prove `nmap`, `hydra`, `hping3` or `sqlmap` against the target box will trip an ET rule, and §18 is right that default rules may not fire on a toy attack. |
| **5 — Notifications** ✅ | Presence tracking, dispatcher, debounce/digest, async email, logs. Plus FE-12 … FE-16, the five frontend wiring items that consume Phase 4's endpoints. | **CODE DONE; ONE VERIFICATION OUTSTANDING.** Presence is a per-user registry fed by the existing socket, with an any-active rule, a socket-close drop and a 15-minute stale guard. The dispatcher suppresses for a watching subscriber, sends for a backgrounded or disconnected one, debounces per user per event type with a rollup, digests past the threshold, retries transient SMTP failures with backoff and refuses to retry permanent ones, and writes every send, suppression and failure to `NotificationLog` and the audit trail. `unknown` never triggers, and config REFUSES it as a trigger severity rather than merely omitting it. Transport is `aiosmtplib` with an explicit timeout, on a worker off both the request path and the feed loop. The five frontend items render from real endpoints with no layout change.

**VERIFIED IN A BROWSER AGAINST THE RUNNING STACK, not only in tests.** With a local SMTP listener standing in for a relay: an alert fired with no browser attached **sent** (message captured, carrying alert id, severity, attack type, `src -> dest`, signature, MITRE technique, the LLM's explanation and the dashboard link); with the dashboard tab open and focused the next seven alerts were **suppressed** and no message left the process; a real `visibilitychange` over the real socket flipped the tab to `backgrounded` and the next critical **sent**. Two `sent` rows, two messages, and the suppressions recorded as rows with rollup counts rather than as absences. The right rail, threat clusters, header counters, ticker and unified search all rendered from their endpoints with no layout shift — the search found an alert 900 rows deep, outside the browser buffer entirely.

**OUTSTANDING: the deliverability send against a REAL relay (§18, "test with the real provider early").** `SMTP_*` is not filled in `backend/.env`, so `python -m scripts.send_test_email <address>` has not been run. A local listener proves the transport, the templates and the policy; it cannot answer inbox-versus-spam, which is the half of deliverability that matters on demo day. |
| **6 — Eval + metrics** ✅ | Held-out eval scoring **all three bands** (LightGBM alone, LLM alone, as-shipped system), baselines, escalation-rate reporting, confusion matrix, per-type breakdown, benchmark, token and cost accounting, velocity buckets, right-rail feeds. Plus FE-16 (which carries FE-8) and FE-17. | **DONE, WITH ONE GUARD BAND TRIPPED AND ADJUDICATED RATHER THAN SILENCED.** `app/eval/` scores three tiers on the same 80 stratified, seeded, held-out rows through `run_pipeline` — the exact production entry point — with the intel cache cleared first so no verdict is scored as fresh that was served from a lookup. Every accuracy carries random, majority AND the no-training 1-NN baseline, computed on the scored rows rather than copied. Failures stay in the denominator; `assert len(predictions) == total` holds for all three tiers. Tokens come from real SDK usage fields, cost from a price table verified against the providers' own pages with source URLs and an as-of date, and `cost_usd` is ABSENT rather than 0.0 when nothing priced was called. The Evaluation screen renders every field it reads, from the real endpoint, with a real 4×4 matrix. **The `llm_floor` band tripped at 0.2250 and stays tripped** — the investigation it demanded ruled out all four of its stated causes and found a real capability limit instead (§7.3d). Nothing was tuned to move it. |
| **7 — Rigor** ✅ | Full test suite, ruff, mypy, pytest config, `make check`, CI, cold-clone smoke test. Plus the Phase 6 adjudications that changed measured numbers: the `llm_floor` revision (§7.3d), the sample-size move to n=300 (§7.3f, recorded before the run), and the dead-key state (D39). | **DONE.** 781 tests green, ruff and mypy clean across 121 files, `make check` green from a cold clone. Four addressable layers behind markers — `failure` (provider down, 429, timeout, malformed output, I18 empty content, intel partial and total failure, DB locked, queue full, dead key), `load` (bounded queues drop and count, a 503 rather than a hang, one loop under five concurrent clients), `invariant` (one NAMED test per §5 item, with a test that parses §5 out of this file and fails on an unmapped invariant), `contract` (every response shape the frozen frontend consumes, field by field, including the 11 pinned raw exceptions). Nine CI checks, each runnable locally by the same command the workflow uses, and **each proven to fail on a deliberately broken input** (§13.3). The suite now audits itself for PLAN §12's two banned shapes: three `assert a or b` forms with two plausible branches were found and rewritten, and no test codifies a permissive answer on a privilege boundary. **Seven defects found and fixed while building this, four of them by the cold-clone job:** `langgraph` — the library the whole pipeline is built on — and `starlette` were declared in no dependency list, so a fresh `pip install -e .` produced a package that started fine and would have failed on the first alert; the ML stack was undeclared for the same reason; `alembic/env.py` was silencing every application logger via `disable_existing_loggers`; the health cache and provider registry leaked between tests; one notification test was timing-flaky; `.env.example` documented 56 of 87 settings and not one provider key; and `scripts.ci.run` itself could not run on a machine with no `.env`. |
| **8 — Honesty pass** ✅ | README rewritten against the code. Real-vs-simulated table. Judge Q&A refreshed. Talking points for anything still simulated. | **DONE.** `backend/README.md` rewritten from scratch against the code — it described Phase 1. **Every capability claim now names the passing test behind it (I11)**, and the one claim that cannot have a test says so: email deliverability is a recorded operator action, not a test result. It carries §10's budget arithmetic in full — free-tier caps, the N=3 `dev`/`reserved`/`spare` pool and why sticky-until-exhausted beats round-robin, the 30 alerts/min demo rate, both gates and their measured rates, and the resulting headroom per provider — and all three tiers at both sample sizes against random, majority AND 1-NN, not the headline alone. `REAL_VS_SIMULATED.md` states the ingestion boundary, the §17 cuts with their prepared answers, and the limitations as they actually stand. §20 rewritten against what was measured, led by the five answers a measurement decided. **The sweep found nine things and `GAPS.md` lists every one**, closed or open, with nothing closed by editing this file. Cleared in the final pass: the ingest schema clause that was unimplementable against real Suricata output (A2, spec corrected to match code, plus four regression tests); `app/core/providers.py` deleted as dead code shadowing the live key pool (A8); `dash/AlertDrawer.jsx` deleted as FE-18 (A9); `envelope.py`'s fabricated `0.0` replaced by an omitted field (A10). **What remains open is listed rather than quietly closed:** the attack→rule rehearsal (§21 item 9), the demo profile numbers (§21 item 5), old-repo archival and the teammate handoff. `make check`, `make ci-checks` and `make smoke` are green, and the eval trips no guard band. |

---

## 17. Deliberate cuts

Stated out loud rather than shipped hollow. Each has a one-sentence answer ready.

| Cut | Why | What to say |
|---|---|---|
| **Multi-tenancy** | HIS has a tenant model with zero query filters — data modelling, not isolation. Four hours to implement properly, two minutes to scope honestly. | "Single-tenant by design for this build. The model supports it; isolation is a roadmap item and I'm not going to call it multi-tenant until the query filters exist." |
| **Vector database (Chroma)** | D3. The embedding model stays; the database goes. | "We use a real transformer for retrieval — MiniLM, 384-dimensional, running locally through ONNX. What we don't use is a vector database, because at eighty chunks the entire index is one small numpy array and a dot product. Chroma would add a client, a server, an import that can kill startup and a download that can fail on demo day, in exchange for nothing measurable at this scale." |
| **Three.js 3D topology** | HIS has the dependency and imports it nowhere; the graph is SVG. | "The topology view is SVG driven by real alerts. The 3D claim was stale and it's gone." |
| **Live traffic capture** | D10. | "Replay of a real labeled dataset, not live capture. We don't have a sensor on real traffic, and replay is what makes the eval possible." |
| **Slack / webhook notifications** | Email is the real, working channel. | "Email notifications are wired and presence-aware. Other channels are scaffolded but not sending, and I'd rather say that than show you a preference that goes nowhere." |

---

## 18. Risk register

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Rewrite runs past the deadline | Critical | Medium | Phase order is dependency-driven and each phase has a shippable end state. Phases 0–4 alone are a working product. |
| Frozen-FE contract mismatch discovered late | High | Medium | Phase 0 exists precisely for this. Contract tests per screen (§12). |
| Free-tier quota exhausted mid-demo | High | Medium | §10 budget, per-IP enrichment cache, single stream loop, labelled offline mode as the fallback. |
| Real eval number looks low | Medium | Medium | Expected band and baselines are set in advance (§7.3). Below the floor is investigated as a bug, not accepted as a finding. |
| Real eval number looks *too good* | **High** | Medium | Per-tier leak alarms (§7.3): >90% on the LLM tier or >98% on LightGBM triggers an audit, not a celebration. This is the failure that destroys credibility, because it survives right up until a judge reads one row. |
| **Identifier leaks into model features** | **High** | Medium | IPs, Flow ID and timestamps excluded by explicit allowlist, asserted by test. CICIDS2017's IP topology is fixed, so a leaked IP column memorizes instantly and scores near-perfectly. The >98% alarm exists to catch exactly this. |
| **Train/serve feature skew** | High | Medium | One shared `features.py` imported by both paths, plus a CI parity test on a fixture row. Two divergent feature builders is a silent accuracy killer that no eval would catch. |
| Model or embedding artifact missing on a cold clone | High | Low | Both committed with checksums, verified at startup, checked in CI's cold-clone smoke test. This is the exact failure that made MINE's RAG path fragile. |
| Escalation threshold poorly tuned | Medium | Medium | E17 reports escalation rate and per-subset accuracy, so a bad threshold is visible in the numbers rather than invisible in the routing. |
| Repo size from committed artifacts | Low | Medium | Quantized ONNX (~23 MB) plus a small booster file. Acceptable without LFS; measured before committing. |
| Email deliverability (spam folder) | Medium | Medium | Test with the real provider early in Phase 5, not the night before. **STILL OPEN AFTER PHASE 5.** The transport, templates and policy are verified against a local SMTP listener; no message has reached a real mailbox because `SMTP_*` is unset (§21 item 1). `scripts/send_test_email.py` exists and takes one argument. Run it the day credentials land, not the night before the demo. |
| Teammate's frontend changes underneath | Medium | Low | Only five sanctioned FE changes (§3.3), all small, all coordinated. |
| Dataset licensing / provenance challenged | Low | Low | Provenance documented at §6.1: source, what is original, what is reconstructed. |
| Old repo deleted with evidence in it | Medium | Low | Archive before deleting (§13.1). |
| **Venue network dependency** (D23) | High | Medium | **Bring our own router / hotspot.** Never trust venue wifi for the attacker↔target↔Flare path. Replay keeps running as the fallback, so a dead live path costs a demo beat, not the demo (I19). |
| **Suricata rules do not fire on the staged attack** | High | Medium | **Rehearse the exact attack script against the exact ruleset in advance.** Default ET rules may not fire on a toy `nmap` or a low-rate `hydra` run. Map each attack to the specific rule expected to catch it and verify each one, rather than assuming defaults fire. |
| **Ingest endpoint abused or malformed input crashes the pipeline** | Medium | Low | Service token, own rate limit, payload cap, strict per-event schema validation, untrusted-input escaping (§9). Disabled by default. |
| **All provider keys exhausted mid-demo** | High | Low | Three-key pool with `reserved` untouched until the day (D26), plus labelled offline mode as the floor. Honest 503 rather than a silent degrade. |
| **Provider model ID retired or response shape changed** | High | Medium | D28/D30: IDs verified against live docs before the client is written, not assumed. D29/I18: a 200 with empty content is a failure, so a shape change surfaces as a visible failed call rather than a silent `unknown` (T3). |

---

## 19. Demo-day runbook

Written now, not at 3am the night before.

1. **Cold-clone rehearsal on a second machine.** The whole point is to catch the download, the missing dependency, and the missing `.env` before a judge does.
2. **Fresh database per run.** Run 2 must not open showing run 1's alerts (T9).
3. **Quota check before the demo** — `/health/deep` on all four providers.
4. **Rate set to the demo profile**, verified against §10.
5. **One presenter tab.** Extra open tabs multiply API spend (T4).
6. **Offline mode verified working** as the fallback if the venue network or the quota dies — and known to be visibly labelled when active.
7. **Notification demo prepared:** a scripted moment where the tab is backgrounded and the email arrives. This is a strong, memorable beat. **As built (Phase 5), the beat is:** subscribe the demo account to `email` / `alert.high_severity`; show the Notifications screen; background the tab; the email arrives on the phone; bring the tab back and show that the next burst produced a `suppressed` row in `GET /notifications/log` instead of a second email. The suppression row is the punchline — it is the evidence the presence logic ran, and it is more convincing than the email. **Prerequisites:** `NOTIFICATIONS_ENABLED=true` and `SMTP_*` filled, verified in advance with `python -m scripts.send_test_email <address>` (§21 item 1); the first alert in a window sends immediately, so no waiting; and the tab must be genuinely backgrounded, not merely covered — the frontend reports `visibilitychange`, and a window that is behind another window is still visible.
8. **Eval run pre-executed** with results cached, so the panel is not waiting on a live provider under judging pressure.
9. **Known-limitations sheet in hand** — the honest answers from §17 and §20, ready before anyone has to find the gap themselves.
10. **Bring our own network.** A router or phone hotspot for the attacker box, target box and laptop. Venue wifi is not on the critical path for anything (D23, §18).
11. **Rehearse the live attack end to end** — the exact script, against the exact Suricata ruleset, on the exact hardware. Verify each attack maps to a rule that actually fires; default ET rules may not trigger on toy attacks. Do this days before, not on the morning.
12. **Verify the key pool state** — `reserved` and `spare` untouched, `dev` expected to be burnt. Confirm before the session (D26).
13. **Replay stays running during the live segment.** If the live path dies, the feed does not stop and the demo continues (I19). Know how to switch the live toggle off in one action.

---

## 20. Judge Q&A implications

**Rewritten in Phase 8 against what was actually measured.** The strongest
answers here are no longer the architectural ones — they are the ones where a
measurement decided something and the measurement is on disk. Where a number
appears below it is the number in `data/eval/n300_postadjudication.json`, and
every one of them is reproducible with `python -m scripts.run_eval`.

### The five that matter most

| Question | The answer the build earns |
|---|---|
| **"Why is classification owned by a trained model rather than the LLM?"** | **Because we measured it.** The LLM scores **0.2333 attack-type accuracy against a 0.1667 random baseline** on these flows — barely above chance. It is not a prompt problem and it is not a parser problem: `unscored_count` is 0, every provider call succeeded, every response parsed and enum-clamped, and all fifteen `PROMPT_FEATURES` were present in every prompt. It is a capability limit, and it has a cause — **one flow drawn from a distributed attack carries no evidence of the distribution**, so a five-packet no-reply DDoS flow reads as benign. We did not assume the split between the tiers. We tested whether the LLM could do the job, and the test told us. §7.3d. |
| **"Why should we believe your 99% isn't a leak?"** | **Two reasons, and neither is 'trust us'.** First, **a 1-NN classifier with no training at all reaches 0.9844 on the same features.** The classes are nearly separable by geometry in CICFlowMeter space, and our model adds **one point** over that — which is what a real model does, and nothing like what a leak does. Second, **the guard that catches memorisation actually fired, on a real defect**: the unconditional feature-overlap check found **62 eval rows sharing a feature vector with train** while id-level disjointness passed clean. We deduplicated the whole population on the 77-feature vector before splitting, dropped 193,859 duplicate vectors, and exact overlap is now zero. A guard nobody has seen fire is a guard nobody knows works. §7.3b. |
| **"Why is escalation so rare?"** | **Because the classifier is confident on this data and we did not manufacture escalation to make the LLM look busy.** The gate fires on roughly **3 alerts in 1,000** — 0 of 300 in the published run — because isotonic calibration on a well-separated problem pushes almost every confident prediction to 1.0. The consequence is that **the as-shipped system number equals LightGBM-alone (0.9967 = 0.9967), and we report it as equality, not as a win.** Lowering the threshold to produce escalations would spend quota to move a number, which is the opposite of what the threshold is for. E17 reports the rate so a badly-tuned gate would be visible in the numbers rather than invisible in the routing. |
| **"What happens when a provider fails?"** | **Four different failures, four different behaviours, all traced.** A **5xx or a timeout** on the reasoning tier falls back **cross-provider** — Gemini to Groq — and the trace names both. A **429** marks that key cooling (honouring `Retry-After`), advances the pool, and issues a **fresh call on the next key** — never a retry of the failed call on the same key. A **403** marks the key **dead on the first one** and removes it from rotation permanently, because a revoked key does not un-revoke; that path is not a hypothesis, it was measured in production when a revoked Gemini key cost three requests at n=80 and zero at n=300. **A 200 carrying empty or unparseable content is recorded as a FAILED call**, emits a `failed` trace entry, and stays in the denominator as `unknown` — it never becomes a silent default and never renders as a verdict (I18). All keys cooling produces an **honest 503**, not template text. |
| **"What would break this on stage?"** | **Answered from the risk register, honestly.** The likeliest is **Suricata's ET Open rules not firing on the staged attack** — a low-rate `hydra` or a small `nmap` can produce nothing, which is why the attack-to-rule mapping is rehearsed against the exact ruleset days in advance rather than assumed. Second is **the venue network**, which is why we bring our own router and why replay never depends on it. Third is **free-tier quota**, which is why there are three keys per provider with `reserved` untouched until the day and a labelled offline mode as the floor. **None of those three stops the demo**: replay is local, rehearsed, and runs whether or not the live path, the venue wifi or a provider is up (I19). What would genuinely hurt is a judge finding a claim in the README with nothing behind it — which is what Phase 8 exists to prevent. |

### The rest

| Question | Answer the build earns |
|---|---|
| "Is your data real?" | Real labeled CICIDS2017 flows on disk from `GeneratedLabelledFlows` — real endpoints, real capture timestamps, real ports — on a live code path, with the eval set held out from the replay set at the feature vector. |
| "Show me the branch." | Real `add_conditional_edges` with pure, unit-tested routing functions. |
| "What if a stage fails?" | The trace shows exactly one entry per node with status and reason, guaranteed even on an unhandled exception (I1). |
| "Are these numbers measured?" | Every one. `perf_counter` for latency, SDK usage fields for tokens, a real price table with source URLs and an as-of date for cost — or the field is **absent** rather than zero. |
| "Is your eval honest?" | Held out, feature-vector disjoint, no label leak, runs the production `run_pipeline`, stratified, seeded, reported against random, majority AND a no-training 1-NN baseline. The number is not 1.000, which is itself the evidence. And the run that produced it exits non-zero if a guard band trips. |
| "Why isn't your accuracy higher?" | Ask it of the tier being quoted, because the two are different tasks. The shipped classifier is at **0.9944 on the full held-out partition** against a **0.9844** no-training baseline. The zero-shot LLM on the same rows is at **0.2333** against a **0.1667** random baseline, and that is the measured ceiling of zero-shot single-flow classification, not a tuning failure. On the LLM tier, anything in trained-classifier territory would mean the answer leaked into the prompt — above 0.90 is a **build failure**, not a win. |
| "Your eval sample says 0.9967 but you keep saying 0.9944. Which is it?" | **0.9944 — the full 1,800-row partition — is the number to quote.** 0.9967 is 299/300 on the capped sample: one error where 1.67 are expected, which is the single most likely draw from a population at 0.9944. Quoting the higher one would be quoting a sampling accident. This is also why the absolute-ceiling guard was moved off the sample and replaced with a binomial consistency test — a guard that fires on half of honest runs is noise. §7.3g. |
| "Have any of your thresholds moved?" | **Two, both recorded, both travelling on every eval payload under `superseded_thresholds` with their date and their evidence.** The LLM floor moved 0.35 to 0.18 after measurement disproved the estimate it encoded (§7.3d). The sample-level absolute ceiling was removed in favour of a statistical consistency test after it fired on a run every other guard called clean (§7.3g). **The 0.995 ceiling value itself never moved** — it still applies, unchanged, to the full partition. A threshold that changes without leaving a record is indistinguishable from a threshold tuned to make a number pass. |
| "What happens with no API key?" | Declared, labelled offline mode. Visible in the trace, on health, and in the UI. Never a silent template. A provider enabled with an empty key pool fails **closed at startup**. |
| "What's simulated?" | Ingestion is replay, plus real live injection when enabled. Everything downstream is the real pipeline. Written down in `REAL_VS_SIMULATED.md` before anyone asks. |
| "Why not a vector DB?" | Real transformer embeddings, no database. At ~80 chunks the index is one committed numpy array; a vector DB adds a startup dependency and a cold-start download for no measurable gain. D3, D3a. |
| "Where's the actual ML? Isn't this just API calls?" | A LightGBM classifier we trained on a disjoint partition handles the fast tier, with a committed model card, held-out metrics, confusion matrix and feature importances. Most alerts never reach a provider at all. The LLM does reasoning and explanation, which is what it is actually better at — and we have the measurement showing what it is *not* better at. |
| "Why gradient boosting and not deep learning?" | Fifteen numeric tabular columns at this sample size is where boosted trees win. A transformer would be slower and worse, and fine-tuning one on a few hundred rows would overfit. We used a transformer where it belongs, in retrieval. Choosing the right tool is the answer, not a compromise. |
| "How do you know the model didn't memorize?" | Three-way disjoint partition — train, eval, replay — enforced **on the feature vector** and checked in CI, plus identifiers (IPs, Flow ID, timestamps) excluded by explicit allowlist. CICIDS2017's IP topology is fixed, so a leaked IP column would memorize instantly. And a suspiciously perfect score is a **build failure**, not a result. |
| "Which tier answered this alert?" | Every prediction carries its provider, its model version and its artifact checksum in the trace. Point at any alert in the feed and you can see whether the classifier or the LLM produced that verdict, why it escalated if it did, and **which key served the call** — by label, never material. |
| "Suricata severity vs Flare severity?" | Suricata gives a static per-rule prior; Flare produces a contextual per-instance posterior. |
| "Is any of this live, or is it all canned?" | **Both, deliberately.** Replay of a real labeled dataset is what the eval scores, because scoring needs ground truth. The live segment is a real attack from that box against this one, through a real Suricata, into the same pipeline — tagged `live_demo`, carrying no label, and unable to enter the eval set even if someone tried. |
| "Why doesn't the classifier score the live alerts?" | EVE records have a signature and a 5-tuple, not the seventy-seven numeric flow features the model was trained on. Feeding it zeros would be a **fabricated feature vector scored as a real prediction**, so we skip the tier and say so — you can see the `skipped` entry and its reason on any live alert. That is also the demo dynamic: replay showcases the fast tier, live injection showcases the LLM tier. |
| "How do you not run out of API quota?" | Most alerts never reach a provider — the trained model handles them locally for free. For the ones that escalate we run a three-key pool per provider with declared roles: one burnt during development, one untouched until today, one spare. Sticky-until-exhausted, never round-robin, because round-robin burns three quotas at once instead of using them as sequential reserve. The arithmetic is in the README: at 30 alerts/min a ten-minute demo draws ~100 Gemini calls against a ~1500/day cap. |
| "What if the venue network dies?" | We brought our own router. If that dies too, replay is local and keeps running — the live segment is additive, never load-bearing (I19). |
| "Can a prompt injection break it?" | **Both halves**, which neither predecessor had. Input is JSON-escaped, length-capped and wrapped in a delimited untrusted-data block with an explicit instruction; output is enum-clamped and MITRE IDs are dropped unless the retriever actually returned them. Clamping alone would leave a model that can be talked into writing anything it likes in the narrative an analyst reads. |
| "Does this scale?" | Bounded queues with honest 503s, per-IP caching, tiered routing as a cost control, one stream loop per server rather than one per connection, and a documented SQLite to Postgres path behind the SQLAlchemy abstraction. |

---

## 21. Open items

Small, and none block Phase 0.

1. **SMTP credentials / provider** for §8.4 — Gmail app-password, SendGrid, Resend, or another relay. **STILL OPEN AFTER PHASE 5, AND IT IS THE ONE THING BLOCKING §18's DELIVERABILITY CHECK.** `backend/.env` carries `JWT_SECRET`, six provider keys, AbuseIPDB and VirusTotal — and no `SMTP_*` at all. The code path is complete and tested against a fake transport and against a monkeypatched `aiosmtplib.send`; what has NOT happened is a message reaching a real mailbox, which is the only way to learn whether it lands in the inbox or in spam. Fill `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM`, set `NOTIFICATIONS_ENABLED=true`, then run `python -m scripts.send_test_email <address>` and record which folder it landed in.
2. **Sender identity** — the from-address and display name for notification emails. `SMTP_FROM_NAME` defaults to `Flare SOC`; `SMTP_FROM` has no default and is required when the feature is on.
3. **Old-repo archival** confirmed before deletion (§13.1).
4. **Teammate handoff** for the five sanctioned FE changes (§3.3) — FE-1 is the one that must land early, since the live feed does not connect without it.
5. **Demo profile numbers** — target alert rate and run length, to finalize §10.
6. **Confidence threshold** for escalation (§4.3, E17) — set empirically from the validation split during Phase 2a, not guessed. Recorded in the model card once chosen.
7. **New dependencies to add:** `lightgbm`, `scikit-learn` (split, metrics, calibration), `onnxruntime`, `tokenizers`, `numpy`. **No PyTorch, no `sentence-transformers`, no `chromadb`** — the ONNX path exists specifically to avoid a ~800 MB dependency for a 23 MB model. All free and open-source; **there is no paid service anywhere in this stack.**
8. **Dependencies for live injection (D23, Phase 4a):** no new Python packages — the forwarder tails a file and POSTs with the `httpx` already in the stack. **External tooling, all free / open-source:** Suricata on the target box; `nmap`, `hydra`, `hping3`, `sqlmap` on the attacker box. **Hardware to source:** a second machine or VM for the target, and our own router or phone hotspot (§19 step 10).
9. **Suricata ruleset to pin** — which ET Open ruleset version, and the verified attack→rule mapping proving each staged attack fires something (§18). Needed before Phase 4a is done, not on demo day.
10. **Service token for the forwarder** — generation, storage and revocation path for the `POST /ingest/eve` credential (§9). Must not be a user JWT.
11. **Provider keys — 3 per provider** (D26): 3 Groq, 3 Gemini, each labelled `dev` / `reserved` / `spare` in config. All on free tiers. Needed before rehearsal begins, since `dev` is expected to burn.
13. **Known limitations recorded in Phase 5**, none blocking:
    - **`Rule.is_enabled` has no toggle endpoint**, because CONTRACT §2.6 states the frozen frontend has none — the field is set at create and at update and is honoured by the engine, but there is no `PATCH .../enabled`. Adjudicated as correct rather than left implicit: the contract is the authority on what the frozen UI can call, and inventing a route no screen reaches would be surface with no consumer.
    - **`export.ready` is a valid notification `event_type` with no producer.** CONTRACT §2.8 pins the enum and the frozen dropdown offers it; the dispatcher fires `alert.high_severity` and `rule.matched` only. The reason is structural rather than an omission: exports in this build are SYNCHRONOUS — `POST /export` returns the file in the response — so there is no later "ready" moment to notify anyone about, and a preference that fired the instant the user clicked Download would be a notification about something already in their hands. Recorded here rather than solved by rejecting the choice the way `slack` is (§8.6), because unlike Slack the event is not cut: it becomes real the moment exports go asynchronous.
    - ~~**`SERVICES` in `frontend/src/lib/flare-data.js`**~~ — **DELETED in Phase 6.** Fabricated service-health data with no reader anywhere in the frontend. Removing it changed nothing on screen, which is the point: it rendered nowhere and existed only to be found by the honesty pass.
    - ~~**`createMockAlerts()` still seeds `DashboardPage` under `import.meta.env.DEV`**~~ — **CLOSED by FE-17 in Phase 6.** The seed, the DEV-only append behind the toolbar control, and `data/mockAlerts.js` itself are gone; the control re-reads `GET /alerts` instead.
    - **The stale-presence window is bounded by the frontend's frame cadence.** FE-2 sends a presence frame on connect and on every `visibilitychange`, and nothing periodic, so `last_seen` only advances on those. The 15-minute window (§8.2) is sized for that; a periodic heartbeat would let it shrink to a minute or two and would be a sixth frontend change, not made.

15. **The LLM tier sees 15 of the 77 columns the classifier sees, and that choice
    is recorded here rather than revisited after seeing the score.** `PROMPT_FEATURES`
    (`app/agent/prompts.py`) carries fifteen discriminative flow statistics; `FEATURE_COLUMNS`
    (`app/ml/features.py`) carries all seventy-seven. **`Bwd Packet Length Min` is in the
    model's feature set and is NOT in the prompt** — it is one of the reverse-direction
    length statistics that distinguishes a no-reply flood from an ordinary short request,
    which is precisely the discrimination §7.3d shows the model failing to make. The
    fifteen were chosen in Phase 3 for prompt size and readability, before the LLM tier had
    ever been scored.

    **It is NOT changed now, and that is deliberate.** Adding columns after seeing a 0.20
    is tuning toward an eval number regardless of how defensible the columns are, and the
    resulting figure would not be comparable to the one on the record. **Future work, in
    priority order, each of which needs a fresh partition or a pre-registered protocol to
    be honest:** (a) give the LLM cross-flow context — a window of flows from the same
    source — which is the thing §7.3d identifies as actually missing; (b) widen
    `PROMPT_FEATURES` toward the full 77 and report the delta as its own experiment;
    (c) few-shot examples drawn from `train.csv` only. All three are real engineering and
    all three are outside Phase 7.

14. ~~**Model IDs to verify before Phase 3**~~ — **CLOSED by D31.** Verified by live probe against this project's own keys: Groq `openai/gpt-oss-120b` (primary) and `qwen/qwen3.8-27b` (fallback) with `reasoning_format="hidden"` + `reasoning_effort="low"`; Gemini `gemini-3.6-flash` at `thinkingLevel="low"` with a 25 s timeout. T3 was caught in the act — `gemini-2.5-flash` is LISTED by the models endpoint and 404s on `generateContent`. Re-verify with `python -m scripts.verify_models` before each rehearsal.

---

*Planning document. Nothing implemented. Supersedes `DECISION.md`, whose 12-hour cut line no longer applies.*

*Phase 0 complete: the frozen-frontend contract is pinned in `CONTRACT.md` and `openapi.yaml`. Decisions D23–D30, invariants I18–I19, sanctioned changes FE-6 … FE-10, and §4.4a / §10 / §16 Phase 4a were added by the pre-Phase-1 pass.*
