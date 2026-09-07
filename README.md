<div align="center">

<pre>
███████╗ ██╗       █████╗  ██████╗  ███████╗
██╔════╝ ██║      ██╔══██╗ ██╔══██╗ ██╔════╝
█████╗   ██║      ███████║ ██████╔╝ █████╗  
██╔══╝   ██║      ██╔══██║ ██╔══██╗ ██╔══╝  
██║      ███████╗ ██║  ██║ ██║  ██║ ███████╗
╚═╝      ╚══════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝
</pre>

*Reads the alerts nobody has time to read, and shows its working.*

</div>

<div align="center">

A security operations centre generates more alerts in an hour than a person can
read in a day. Almost all of them are nothing. A few are the beginning of a
breach. Someone has to open each one, work out what the traffic was, check
whether the address involved has a reputation, decide how urgent it is, and
write down what to do next — and by the time they have done that forty times,
the one that mattered is an hour old.

**Flare does that first pass.** A network flow arrives, a trained classifier
names the attack type and the severity in under ten milliseconds, threat-intel
sources are queried for the externally routable end of the flow, the relevant
MITRE ATT&CK techniques are retrieved from a local embedding index, and a
language model writes the explanation and the remediation an analyst reads —
with a per-stage trace behind every field, so nothing on the screen is a number
without a source.

For an engineer: a FastAPI backend running a seven-node LangGraph state machine
over a two-tier classifier — LightGBM for the verdict, an LLM for the narrative
— with RAG grounding, a provider key pool, presence-aware email, and a held-out
eval that runs the production entry point.

**Ingestion is replay of a real labelled dataset, plus optional live injection
from a real Suricata instance. It is not a sensor on production traffic, and
that is stated here rather than extracted under questioning.** Everything
downstream of ingestion — classification, enrichment, retrieval, reasoning,
rules, playbooks, notifications, the eval — is the real pipeline. The full
boundary is in [`REAL_VS_SIMULATED.md`](REAL_VS_SIMULATED.md).

</div>

---

## 🔍 How It Works

One alert, from a row on disk to a rendered drawer:

```
  backend/data/splits/replay.csv          1,800 held-out CICIDS2017 flows
         │                                real endpoints, real capture timestamps
         ▼
  ReplayEngine  ── one loop per SERVER, not per connection ──► 30 alerts/min
         │        file order, no shuffle, ids must be `replay-` prefixed
         ▼
  normalize()  ─► NormalizedAlert{ id, src_ip, dest_ip, dest_port, protocol,
         │                          signature, features{77}, source:"cicids_replay" }
         │        `ground_truth_class` lives HERE and travels no further (I4)
         ▼
  triage_q  BoundedQueue(1000) ── full ──► dropped and COUNTED, never silent
         │
         ▼
  run_pipeline(alert)          ◄── the eval calls this exact function (E3)
         │
    ┌─ classify ──────────────────────────────────────────────┐
    │  tier 1  LightGBM, 77 features, ~7 ms, isotonic-calibr. │
    │          attack_type + severity + confidence            │
    │  tier 2  escalate ONLY if router says so:               │
    │            confidence < 0.99  |  attack_type == unknown │
    │            no flow features (D25)  |  intel disagrees   │
    │          -> groq openai/gpt-oss-120b, enum-clamped      │
    │  a failed escalation does NOT erase tier 1's verdict    │
    └─────────────────────────────────────────────────────────┘
         │
         ▼  route_after_classify — is either endpoint publicly routable?
         │
    ┌─ enrich ─────────────────┐        both ends RFC1918 ──► traced skip,
    │  AbuseIPDB + VirusTotal  │        no metered quota spent
    │  CONCURRENT, own timeouts│
    │  score = max, malicious  │
    │        = any             │
    │  >= 50 forces `high`     │  ◄── intel outranks the model
    │  partial failure = usable│
    │        AND degraded, and │
    │        NOT cached        │
    └──────────────────────────┘
         │
         ▼  route_after_enrich — THE REASONING GATE, on POST-upgrade severity
         │
         │   below `high`  ─────────────────────────────► traced skip
         │   no rate budget (10 calls/min) ─────────────► traced skip NAMING the budget
         │   severity `unknown` (D27) ──────────────────► traced skip
         ▼
    ┌─ retrieve ──────────────────────────────────────────────┐
    │  MiniLM-L6-v2, 384-dim, int8 ONNX, LOCAL CPU            │
    │  313 chunks over 61 ATT&CK techniques (v19.2)           │
    │  one numpy dot product — no vector DB, no network       │
    │  below 0.45 cosine -> reported low-confidence, NOT hidden│
    └─────────────────────────────────────────────────────────┘
         │
    ┌─ reason ────────────────────────────────────────────────┐
    │  gemini-3.6-flash  ──► 5xx / timeout / pool exhausted ──┐│
    │                        4xx or empty content: NO failover││
    │  groq openai/gpt-oss-120b ◄─────────────────────────────┘│
    │  the trace names WHICH provider answered and why         │
    │  every technique id the model cites that the retriever   │
    │    did NOT return is DROPPED                             │ ◄── grounding
    └─────────────────────────────────────────────────────────┘
         │
    ┌─ recommend ─────────────────────────────────────────────┐
    │  shapes the remediation into the analyst-facing action  │
    │  no explanation AND no remediation ──► node is SKIPPED  │
    └─────────────────────────────────────────────────────────┘
         │
    ┌─ rules ─────────────────────────────────────────────────┐
    │  runs LAST, over BOTH tiers. model < intel < rules      │
    │  per-condition fire trace into the alert payload        │
    │  empty on a fresh install, and the trace says so        │
    └─────────────────────────────────────────────────────────┘
         │
    ┌─ finalize ──────────────────────────────────────────────┐
    │  backfills a `skipped` entry with a HUMAN REASON for    │
    │    every node the routers did not reach                 │
    │  repairs strip inconsistency: a failed/skipped node may │
    │    not leave its field populated, or the table lights   │
    │    green for a stage the drawer calls broken            │
    └─────────────────────────────────────────────────────────┘
         │
         ├─► SQLite (upsert by id — replay loops the partition)
         ├─► notification dispatcher  ── presence-aware, off the feed loop
         └─► WebSocket fan-out ── one complete alert per message
                     │
                     ▼
         GET /api/v1/ws/stream   first-message auth handshake, no token in the URL
                     │
                     ▼
              AlertDetailDrawer — renders trace[] verbatim
```

**Where a live-injected Suricata alert diverges, and why.** With
`LIVE_INGEST_ENABLED=true`, `tools/eve_forwarder.py` tails a real `eve.json` on
the machine under attack and POSTs batches to `/api/v1/ingest/eve`. Those
records carry a signature and a 5-tuple and **none of the 77 CICIDS flow
features**, so `parse_eve_record` leaves `features` empty by construction. The
router sees an empty feature set, the LightGBM tier records an explicit
`skipped` entry naming the reason, and the alert routes straight to the LLM
(D25). Feeding the model a zero-filled vector and scoring the output as a real
prediction would be a fabricated verdict, so it is not done. Everything after
`classify` is identical to the replay path.

Two further consequences travel with it. Live alerts carry **no ground truth
and never can** — `parse_eve_record` sets `ground_truth_class=None` and takes no
parameter that could set otherwise, and `to_eval_rows` raises on any source
outside `SCORABLE_SOURCES = {"cicids_replay"}`. And the live lane has **its own
bounded queue and its own worker task**, so a forwarder pushing faster than the
pipeline drains saturates the live lane and leaves replay untouched.

What makes this a system rather than a demo is where the guarantees sit. Every
node emits exactly one trace entry whatever happens, including on failure, so a
gap in the array is impossible and the drawer can always distinguish *skipped*
from *failed* from *never ran*. Stage skipping lives in the conditional edges
and nowhere else — a node never returns early, because an early return produces
a payload byte-identical to a genuine skip. The whole graph runs under a wall
clock, and on expiry the alert emits with partial state and every unreached node
backfilled rather than holding a triage slot open forever. And the eval calls
`run_pipeline` — the same function the replay loop calls, with the same
arguments — so there is no path by which the measured system and the shipped
system can be different systems.

---

## 📐 The Two Tiers, and the Measurement That Chose Them

The design claim is that classification belongs to a trained model and narrative
belongs to a language model. That is not an assumption here; it is a
measurement, and it was taken before the split was defended.

**Scored on the same held-out rows, through the same pipeline, the LLM tier
reaches 0.2333 attack-type accuracy against a 0.1667 six-class random
baseline.** Barely above chance. The four hypotheses that a floor guard exists
to surface were each ruled out with evidence on the run itself:
`unscored_count` is 0, there were zero failures, 361 of 361 provider calls
succeeded, every response parsed and enum-clamped, and all fifteen
`PROMPT_FEATURES` were present in every prompt.

The model is coherently wrong, not broken. **One flow drawn from a *distributed*
attack carries no evidence of the distribution** — a five-packet, no-reply DDoS
flow, read on its own, looks like an unremarkable short request. The information
needed to call it is in the other ten thousand flows, and a single-flow prompt
does not have it.

That is the argument for the split. The fast tier reaches **0.9944** on the same
partition because gradient-boosted trees over 77 numeric columns *can* separate
these classes, and it does so in about 7 ms with no API call. So the trained
model owns the verdict, and the LLM is given the job it is actually good at:
reading the verdict, the retrieved ATT&CK context and the intel result, and
writing the paragraph an analyst reads.

The two gates are deliberately independent, and the measurement is why:

| Gate | Fires on | Rate | Why not the other gate |
|---|---|---|---|
| **Classification escalation** | calibrated confidence < 0.99, `unknown`, no flow features, or intel disagreeing with the model | **~3 in 1,000** (0/300 in the published run) | Isotonic calibration on a well-separated problem pushes 99.7% of confident predictions to exactly 1.0 |
| **Reasoning** | severity ≥ `high`, subject to a 10 calls/min budget | **~67% of replay alerts** | Wiring reasoning behind the confidence gate would run the LLM three times in a thousand alerts and leave `explanation` null on almost every alert |

A perfectly-classified critical alert still needs an explanation. Gating the
narrative on classifier confidence would silence the LLM on exactly the alerts
that most need it.

---

## 📊 The Numbers

Three tiers, two sample sizes, and **every accuracy against all three baselines
— random, majority and a no-training 1-NN**. A single accuracy figure is
uninterpretable on its own, which is why no figure here appears without them.

**What each baseline is for.** *Random* says what a coin does on six balanced
classes: 1/6 = 0.1667. *Majority* says what always guessing the most common
class does — it is the one that catches a model flattered by an imbalanced
sample. *1-NN with no training at all* says what the **feature space** does: it
is handed no labels at inference and cannot memorise, so it measures only
whether an eval row lands beside same-class training rows. On this problem 1-NN
is the informative one, because at 0.9844 the geometry alone nearly reaches the
booster's 0.9944 — the classes are simply far apart in CICFlowMeter space, and
that is the honest explanation of the score.

### Attack type, six balanced classes

| Tier | n=80 | n=300 | n=300 (post-adjudication) |
|---|---|---|---|
| **LightGBM alone** | 1.0000 | 0.9967 | **0.9967** |
| **LLM alone** (zero-shot) | 0.2000 | 0.2400 | **0.2333** |
| **As-shipped system** | 1.0000 | 0.9967 | **0.9967** |
| **LightGBM, full 1,800-row partition** | 0.9944 | 0.9944 | **0.9944** |

Baselines, recorded per run rather than carried across from one:

| Run | random | majority | 1-NN |
|---|---|---|---|
| n=80 sample | 0.166667 | **0.175000** | **1.000000** |
| n=300 sample (both runs) | 0.166667 | 0.166667 | 0.986667 |
| full 1,800-row partition | 0.166667 | 0.166667 | 0.984444 |

**The number to quote is 0.9944 on the full 1,800-row held-out partition**, one
point above a 1-NN baseline of 0.9844 on a partition verified disjoint at the
feature vector. The capped sample reads higher (0.9967) because 299/300 is the
single most likely draw from a population at 0.9944 — 1.67 errors are expected
and one occurred. Quoting the sample figure would be quoting a lucky draw.

### Also measured, on the same rows

| | n=80 | n=300 | n=300 (post-adjudication) |
|---|---|---|---|
| Binary detection — system | 1.0000 | 0.9967 | **0.996667** |
| Severity accuracy — system | 1.0000 | 0.9900 | **0.990000** |
| High-severity F1 — system | 1.0000 | 0.9899 | **0.989899** (P 1.000000 / R 0.980000) |
| Binary detection — LLM | 0.4875 | 0.5200 | **0.493333** |
| Severity accuracy — LLM | 0.2375 | 0.2800 | **0.270000** |
| High-severity F1 — LLM | 0.0000 | 0.0368 | **0.025157** |
| Escalations fired | 0 / 80 | 0 / 300 | **0 / 300** |
| Rows the harness could not score | 0 | 0 | **0** |
| Provider calls succeeded | 86 / 89 | 330 / 330 | **361 / 361** |
| Mean system latency | 632.176 ms | 656.050 ms | **1726.638 ms** |
| Mean LightGBM-tier latency | 8.496 ms | 7.037 ms | **7.116 ms** |
| Modelled list-price cost | $0.0121995 | $0.0489549 | **$0.0949452** |
| Guard bands tripped | `llm_floor` | `lightgbm_absolute:sample` | **none** |

Every provider key in this build is on a free tier, so **actual spend is zero**;
the cost row is what the identical traffic would have cost at published rates,
priced from a table with source URLs and an as-of date of 2026-09-05.

**All three runs are on disk and all three are published** —
`backend/data/eval/n80.json`, `backend/data/eval/n300.json` and
`backend/data/eval/n300_postadjudication.json`, with
`backend/data/eval/latest.json` (byte-identical to the third) serving the
Evaluation screen. The before and the after of every adjudication are both
readable, so no one has to take on trust that a number moved for a good reason.

**The LLM tier moved 0.2400 → 0.2333 between two runs on identical rows.** That
is provider temperature and server-side variance. It is disclosed in the run
notice that ships on every payload, not corrected.

### Full-partition detail, from the model card

Measured on all 1,800 eval rows, which is the sample the ceiling guards can
actually conclude on:

- Attack type **0.9944** accuracy, **0.9944** macro-F1, **10 errors in 1,800** — not a perfect diagonal
- Binary detection **0.9967** (precision 0.9980, recall 0.9980, F1 0.9980)
- Severity **0.9933**, macro-F1 0.9928
- Calibration: ECE 0.0047 raw, **0.0053 after isotonic** — isotonic did not improve it here, and that is reported rather than hidden
- Hyperparameters chosen by 5-fold CV on the training partition only: macro-F1 **0.9957 ± 0.0016** across four candidates, i.e. within noise of each other
- Removing `Destination Port`, the highest-gain and most label-correlated feature, costs **0.27 points** (0.9944 → 0.9917), so it is not carrying the result

### Retrieval

Measured against 18 hand-labelled attack-class → technique pairs
(`backend/data/retrieval_labels.json`), reported in
`backend/models/index/RETRIEVAL_REPORT.json`:

| recall@1 | recall@3 | recall@5 | MRR |
|---|---|---|---|
| 0.777778 | 0.888889 | **0.944444** | 0.844444 |

One miss at 5, and it is documented rather than corrected — see
[Known limitations](#️-known-limitations).

---

## 🔬 The Eval, Honestly

This is the section a sceptical reader should press on, so here is what it is
and what it is not.

**It is held out, and disjointness is checked on the feature vector rather than
the row id.** That distinction caught a real defect. The first training run
scored 0.9983; investigation found **62 of 1,800 eval rows (3.44%) whose
77-feature vector appeared verbatim in train** — 49 of them `dos`, because DoS
Hulk emits enormous numbers of stereotyped flows. Their row ids differed,
because ids hash Flow ID and the endpoints, so id-level disjointness passed
while the classifier was in effect being tested on rows it had trained on. The
partition builder now deduplicates on the 77-feature vector across the whole
population **before** splitting; **193,859 duplicate vectors were dropped**, exact
overlap is now 0, and the score fell to 0.9944. The check that found it runs
unconditionally on every eval, at any accuracy.

**It runs the production entry point.** The system tier calls `run_pipeline` —
the same function, the same graph, the same arguments the replay loop uses (E3).
The intel cache is cleared before it runs, so no verdict served from a lookup is
scored as a fresh one.

**Failures stay in the denominator.** A row that fails to classify is scored as
`unknown` and counts against the tier. `len(outcomes) == len(rows)` holds for
all three tiers. A metric that silently drops its hard cases is measuring a
different population than the one it names.

**The answer cannot reach a prompt.** `ground_truth_class` is not a field of
`PipelineState` at all, so `initial_state` cannot copy it and no node can read
it. `synthesize_signature` takes flow features only and has no label parameter —
a change that wanted to leak the label would have to alter the function's
signature, which a test asserts against. CI dumps every prompt the LLM tier
would send to `build/prompt_corpus.json` under `backend/` — generated per run,
never committed — greps it for all 20 label strings and class names, and uploads
the dump as a build artifact, so the no-leak claim is auditable rather than
asserted.

**The guard bands actually tripped, and were adjudicated rather than silenced.**
Two thresholds have been superseded, and both travel on every eval payload under
`superseded_thresholds` with their date, their old value and the evidence that
retired them:

| Guard | Threshold | Scope |
|---|---|---|
| `feature_overlap` | any non-zero eval→train feature-vector overlap | unconditional, at any accuracy |
| `lightgbm_relative` | > 0.05 over the 1-NN baseline while above 0.98 | sample and full partition |
| `lightgbm_absolute` | 0.995 | **full partition only** |
| `lightgbm_consistency` | exact two-sided binomial on the error count, 99% | sample |
| `degenerate` | exactly 1.000, probability-aware | both |
| `llm_floor` / `llm_prompt_leak` | 0.18 / 0.90 | LLM tier |
| `router_regression` | system strictly below LightGBM-alone | as-shipped |

- **`llm_floor` 0.35 → 0.18.** The 0.35 sat inside an *estimate* of 55–75% written before anything had measured a balanced-sampled CICIDS flow with no cross-flow context. Measurement disproved the estimate. The floor now sits just above the 0.1667 random baseline, where it can still do the job it can actually do: catch a chance-level or broken LLM tier. Nothing in the prompt, the feature list or the sample was changed — changing any of them after seeing 0.23 would be tuning toward an eval number.
- **`CEILING_DECISIVE_SAMPLE_SIZE` 201 → removed**, replaced by an exact binomial consistency test. The constant conflated *expressible* with *discriminating*: 201 is the smallest sample on which a 0.995 threshold can be represented at all, which is not the same as being able to separate the two hypotheses the guard exists to separate. At n=300 the expressible values around the threshold are 299/300 and 300/300, and 299/300 is the most likely single outcome for a classifier at 0.9944. **The guard fired on roughly half of honest runs.** The 0.995 ceiling itself is unchanged and still applies to the full partition, where n makes it decisive.

The n=80 run tripped `llm_floor`; the n=300 run tripped `lightgbm_absolute:sample`; the post-adjudication run trips nothing. All three are published.

**What it is not.** It is 300 sampled rows for the tiers that cost provider
calls, so a single misclassification moves the sample headline by 0.0033 — which
is exactly why the quoted figure is the full-partition 0.9944. The severity
number is not independent evidence: severity is a deterministic function of
attack type in this dataset, so that head solves a strictly easier problem. And
the sampling is balanced, at 16.7% benign against real traffic's ~65%, so
precision on `benign` would be materially different under the natural prior.

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | FastAPI + uvicorn, Python 3.13 | 38 route handlers across 14 modules, one of them the WebSocket, one conditional |
| Pipeline | LangGraph `StateGraph` | Seven nodes, three real conditional edges, one trace entry per node |
| Fast tier | LightGBM 4.x, two heads | Attack type (6-class) + severity (4-class ordinal), isotonic-calibrated |
| Quality tier | Groq `openai/gpt-oss-120b`, Gemini `gemini-3.6-flash` | Classification escalation, reasoning, recommendation |
| Embeddings | `all-MiniLM-L6-v2`, int8 ONNX via onnxruntime | 384-dim, local CPU, 23 MB committed with checksums |
| Retrieval | numpy dot product over a committed `float32` matrix | 313 chunks, 61 ATT&CK techniques (v19.2) |
| Threat intel | AbuseIPDB + VirusTotal via httpx | Concurrent, own timeouts, per-IP TTL cache |
| Database | SQLite + WAL, async SQLAlchemy 2.0 + aiosqlite | Alerts, traces, rules, playbooks, audit, notifications |
| Migrations | Alembic, 4 revisions | The **only** schema authority — no `create_all` anywhere |
| Auth | PyJWT HS256 + bcrypt, `token_version` invalidation | 30-minute access, 7-day refresh, RBAC on every route that declares a role |
| Scheduler | APScheduler | Correlation refresh, metric sampling, notification flush |
| Notifications | aiosmtplib | Async SMTP with a real timeout, presence-aware |
| Export | `csv.DictWriter` + reportlab | CSV and PDF, formula injection escaped |
| Frontend | React 19 + Vite 8 + Tailwind 4 | **Frozen.** The backend is built to fit it |
| Frontend motion/UI | motion, recharts, lucide-react, cmdk, vaul | Dashboard, drawer, workspace panels |
| E2E | Playwright | One auth spec against a running stack |
| CI | GitHub Actions — 4 working jobs + an aggregate gate | lint, types, tests, 6 integrity checks, cold-clone smoke, load layer |

**Why each piece, over the obvious alternative:**

- **LightGBM, not a transformer.** The input is 77 numeric tabular columns and 5,400 training rows. That is the regime where boosted trees win outright: a transformer would be slower and worse, and fine-tuning one on a few thousand rows would overfit. The transformer is used where it belongs — retrieval, over text. This is the right tool, not the fashionable one.
- **Transformer embeddings, no vector database.** The retrieval is genuinely semantic: a real 6-layer BERT producing 384-dim vectors. What is absent is Chroma, and the reason is failure modes rather than quality. At 313 chunks the entire index is one 480 KB numpy array and a dot product, which is faster than a vector-DB round trip at this scale. Chroma would add a client library, a server process, a module-level import that can kill app startup, and a weights download that can fail on demo day — in exchange for nothing measurable here. The predecessor's RAG path died on a cold clone for exactly the last of those.
- **LangGraph with fixed routing, not free-roaming agents.** Every edge is a pure `state -> str` function with no I/O, no settings read and no clock, so each branch is unit-testable by constructing a state and calling it. An agent free to choose its own path cannot be audited stage by stage, cannot guarantee one trace entry per node, and cannot be given a per-stage budget — and the trace is the product here as much as the verdict is.
- **SQLite + WAL, with a documented migration path.** No Docker, no service to babysit, one file. The lock contention that hurt a predecessor was `journal_mode=DELETE`, not SQLite. Everything goes through async SQLAlchemy 2.0 and Alembic, so Postgres is a `DATABASE_URL` change plus a driver, not a rewrite. Single-tenant is a stated cut, not an oversight.
- **ONNX, not PyTorch.** `sentence-transformers` drags in ~800 MB of PyTorch to run a 23 MB model. The ONNX route commits the quantised weights and the tokenizer, verifies both against checksums at load, and needs no network ever.

---

## 💸 Quota and Cost Budget

**Everything in this stack runs on free tiers and free/open-source tools. There
is no paid service anywhere.** Quota is therefore a design constraint rather
than an afterthought, and the arithmetic below is why the demo does not run out.

### Free-tier caps, per key

| Provider | Free-tier limit | Consumed by |
|---|---|---|
| Groq | ~30 RPM | Classification escalation, reasoning fallback |
| Gemini | ~15 RPM, ~1500/day | Reasoning |
| AbuseIPDB | ~1000/day | IP reputation |
| VirusTotal | ~4/min, ~500/day | IP reputation |

### The key pool — N=3, `dev` / `reserved` / `spare`

Free tiers are metered **per key**, so three keys turn one hard cap into three
sequential windows. The pressure is not demo day — it is development and
rehearsal, where the same paths run hundreds of times a day, and that asymmetry
is the whole justification for declaring purposes:

| Role | Rule |
|---|---|
| `dev` | Burned during development and rehearsal. **Expected to hit caps.** That is its job. |
| `reserved` | **Untouched until the demo.** A full daily window is available on the day. |
| `spare` | The third window, if `reserved` runs out mid-demo. |

**Selection is sticky-until-exhausted, never round-robin.** Round-robin spends
all three quotas in parallel and arrives at the same wall at the same time,
which buys nothing. On a 429 the key is marked cooling — honouring `Retry-After`
when the provider sends one — the pool advances, and a **fresh call** is issued;
the failed call is never retried on the cooling key, because that is how a rate
limit becomes a retry storm. All keys cooling produces an honest `503
rate_limited`, never a silent degrade to template text.

A **403 is not a 429.** A key that returns a hard auth rejection is marked dead
on the first one and leaves rotation for the process lifetime, because a revoked
key does not un-revoke and retrying it costs a request every cycle to be told
the same thing. The two states need opposite operator responses — cooling is
fixed by waiting, dead is fixed only by provisioning a credential — so
`/health/deep` reports `live_keys` and `dead_keys` separately. This was found in
practice: one Gemini key returns HTTP 403 "project has been denied access" on
every call.

`N` is config and the pool accepts any `N`. The trace records the serving key
**by label only** — `key_id: "groq-reserved"` — never key material.

### Demo-run arithmetic, at the shipped 30 alerts/min

Measured against the first 300 rows of `backend/data/splits/replay.csv`, which
is what a 10-minute run at 30/min plays, in file order. **The loop does not
actually reach 30/min while the reasoning tier is firing — real throughput is
~16/min** ([why](#️-known-limitations)) — so every figure below is an upper
bound on real spend rather than an estimate of it:

| | Measured over the 10 minutes | Free-tier cap | Headroom |
|---|---|---|---|
| **Gemini reasoning** | 207 of 300 alerts are `high`+ (69%) and therefore eligible; the 10/min budget admits **~100** | ~15 RPM, ~1500/day | 33% RPM headroom, 15× daily |
| **Groq classification escalation** | ~3 in 1,000 → **~1 call** | ~30 RPM | ~300× |
| **AbuseIPDB** | 84 enrichable alerts collapsing to **32 distinct IPs** under the 900 s cache | ~1000/day | ~31× |
| **VirusTotal** | the same 32 distinct IPs, but **peaking at 5 new IPs in one minute** | ~4/min, ~500/day | 15× daily, and **the per-minute cap can be exceeded on the worst minute** |

The VirusTotal per-minute exposure is real and is not smoothed over: a 429 there
returns a `rate_limited` result with **no score**, AbuseIPDB still answers, and
the aggregate is marked `degraded` and deliberately **not cached**, so a
transient limit cannot be pinned as a fact about the address for the whole TTL.
A failed lookup never defaults to 0 — rendering "we could not check" as "we
checked and it is fine" is the failure this whole design is arranged against.

**The two gates are separate, and the reason matters.** The reasoning *floor* is
a **policy** question — which alerts deserve a narrative. The *cap* is an
**arithmetic** one. At a `high` floor, 67% of replay alerts qualify, which at 30
alerts/min is ~20/min against Gemini's ~15 RPM. Choosing the floor to dodge
quota would answer the wrong question with the wrong instrument, so the floor
stays policy-correct and `REASON_CALLS_PER_MINUTE=10` enforces the cap — with
every turned-away alert carrying a **traced skip that names the budget**, never a
silent drop. A measured run at 12/min still drew 429s on bursts, which is why the
shipped value is 10 and not 12.

Retrieval costs nothing — embedding is local CPU inference through ONNX, so
there is no per-query spend for RAG at all. `/health` never probes a provider: it
serves a 60-second-TTL cache, so the frontend's 30-second dashboard poll costs
zero quota. `/health/deep` is the real four-provider probe, is manual-refresh
only, and carries its own per-user budget of 4/min on top of the global limiter —
without it, one operator holding Refresh would draw 480 provider calls a minute
through a 120/min global limit. And there is **one replay loop per server, not
one per connection**, so an extra open browser tab does not multiply real API
spend.

---

## ⚙️ Getting Started

This runs from a cold clone with no network access to anything but the package
index. The model weights, the ATT&CK index and the data partitions are all
committed.

### Prerequisites

- **Python 3.13.** `pyproject.toml` declares `requires-python = ">=3.11"`, but mypy targets 3.13 and CI runs 3.13; 3.13.7 is what the committed model was trained under. Treat 3.13 as the verified version.
- **Node.js** for the frontend. No `engines` field is set; the lockfile was produced under Node 22.
- **No Docker, no Postgres, no Redis, no vector database.** One Python process, one SQLite file.
- **API keys are optional to start** — see [`OFFLINE_MODE`](#offline-and-degraded-modes) — but a provider enabled with an *empty* pool fails closed at startup, deliberately.

### 1. Install

```bash
cd backend
python -m venv .venv
```

```bash
.venv/Scripts/python.exe -m pip install -e ".[dev,ml]"
```

On macOS or Linux use `.venv/bin/python` throughout instead of
`.venv/Scripts/python.exe`.

**`[ml]` is not optional in practice.** It carries LightGBM, ONNX Runtime,
scikit-learn and the tokenizer. Without it the app imports cleanly and fails at
the first inference. The cold-clone CI job installs exactly this string into a
runner that has never seen the project and fails if either artifact cannot load.

### 2. Configure

```bash
cp .env.example .env
```

`JWT_SECRET` is the only required variable. There is no fallback and no default
that silently works — the app refuses to start without it, and it must be at
least 32 characters.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Everything else has a working default. Fill in `GROQ_API_KEY_*` and
`GEMINI_API_KEY_*` to run against real providers, and `ABUSEIPDB_API_KEY` /
`VIRUSTOTAL_API_KEY` for enrichment. Absent intel keys produce an honest traced
**skip**, not a fabricated clean verdict.

### 3. Migrate

Alembic is the only schema authority. There is no `create_all` anywhere in the
tree, and startup asserts the migrations have run rather than creating tables
behind you.

```bash
.venv/Scripts/python.exe -m alembic upgrade head
```

### 4. Run the backend

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
```

The replay loop starts with the app (`REPLAY_AUTOSTART=true`), so alerts begin
flowing immediately. Interactive docs are at `/docs` unless `ENVIRONMENT=prod`.

### 5. Run the frontend

In a second terminal, from the repository root:

```bash
cd frontend && npm install && npm run dev
```

Open <http://localhost:5174>. The Vite dev server proxies `/api` to port 8000
**with `ws: true`**, which is what lets the WebSocket reach the backend rather
than terminating at the dev server.

### 6. Sign in

**The demo account does not exist on a default boot.** The frozen frontend's
"Quick demo sign in" button carries hardcoded credentials in the shipped bundle,
which is exactly why the account is not seeded by default — the button returns
401, and that is intended behaviour rather than a bug. Either register a normal
account through the UI, or seed the demo account explicitly:

```bash
.venv/Scripts/python.exe -m scripts.seed_demo --demo-seed
```

The seeder holds the credentials. Never enable `DEMO_SEED_ENABLED` outside a
demo.

### 7. Run the eval

**This spends real provider quota and can trip a guard band, so CI never runs
it.** It writes `backend/data/eval/latest.json`, which is what the Evaluation
screen serves.

```bash
.venv/Scripts/python.exe -m scripts.run_eval
```

`run_eval` exits non-zero when a guard band trips. That is the point of it.

### 8. Run the tests and the CI checks

```bash
.venv/Scripts/python.exe -m pytest -q
```

`make check` is the commit gate — lint, types, tests. `make` is not installed on
Windows by default, so `./make.ps1 check` runs the identical commands, and a
test fails the build if the two target lists ever diverge.

```bash
./make.ps1 ci
```

The data and artifact checks run outside pytest so CI can report each as its own
line:

```bash
.venv/Scripts/python.exe -m scripts.ci.run
```

```bash
.venv/Scripts/python.exe -m scripts.ci.smoke
```

### Rebuilding the data and the models (optional)

Nothing below is needed to run the project. The partitions and both model
artifacts are committed precisely so a cold clone works with no network.

```bash
.venv/Scripts/python.exe -m scripts.fetch_dataset --glf-hf --attack-days-only
```

```bash
.venv/Scripts/python.exe -m scripts.build_partitions
```

```bash
.venv/Scripts/python.exe -m scripts.train_classifier
```

```bash
.venv/Scripts/python.exe -m scripts.build_mitre_corpus
```

```bash
.venv/Scripts/python.exe -m scripts.build_index
```

```bash
.venv/Scripts/python.exe -m scripts.eval_retrieval
```

The source archive is a ~284 MB `GeneratedLabelledFlows.zip`, pinned by SHA-256;
`fetch_dataset` refuses to proceed on a digest mismatch, so a silently
re-uploaded mirror is a loud failure rather than a quiet change of dataset
underneath a committed model. Full provenance, the defect list and the
verification run are in [`backend/data/PROVENANCE.md`](backend/data/PROVENANCE.md).

### Offline and degraded modes

`OFFLINE_MODE=true` is the **declared** way to run with no provider keys at all.
No provider is called, every alert is marked `degraded`, and its trace names
`offline` as the provider with `deterministic-template` as the model. It never
activates by itself — a provider failure produces a `failed` trace entry and an
`unknown` verdict, not a quiet substitution. A fallback that silently swaps
template text for model output is the single failure this design is arranged
against.

Verify the model IDs against live provider endpoints before a rehearsal:

```bash
.venv/Scripts/python.exe -m scripts.verify_models
```

This is not ceremony. `gemini-2.5-flash` is *listed* by the models endpoint and
404s on `generateContent` — "no longer available to new users… use
models/gemini-3.6-flash". Being listed is not being callable.

---

## 📡 Live Staged-Attack Injection

> **This section needs hardware.** Everything above runs on one machine.
> This needs a second box to attack, a Suricata instance watching it, and a
> network you own. It is **off by default, additive, and never load-bearing** —
> replay runs identically whether the live lane is disabled, stopped, failing on
> every event, or saturated, and a test asserts all four states.

`POST /api/v1/ingest/eve` accepts Suricata EVE records from a real Suricata
instance watching a staged attack. **Off means the route is not mounted at all**
— not mounted and refusing. With the toggle off there is nothing to reach, no
schema to fuzz and no credential to guess.

### Server side

```bash
LIVE_INGEST_ENABLED=true
INGEST_SERVICE_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
```

With the toggle on and no token of at least 32 characters, **the app refuses to
start**. The one endpoint that accepts unsolicited external input does not run
unauthenticated.

| Control | Detail |
|---|---|
| Auth | A **dedicated service token** — `Authorization: ServiceToken <…>`, compared in constant time. **Never a user JWT**: a valid admin access token is refused, and a test asserts it. The forwarder runs unattended on a machine being deliberately attacked; a user token would put that account's whole authority there. |
| Rate limit | Its own budget (`INGEST_REQUESTS_PER_MINUTE`, `INGEST_BURST`), **on top of** the global limiter |
| Size cap | Checked from `Content-Length` *before* the body is read, then re-checked against what actually arrived |
| Schema | Strict on the fields the normalizer consumes; unknown top-level keys are discarded unread |
| Batch cap | `INGEST_MAX_EVENTS_PER_BATCH`, checked after parsing |
| Escaping | Untrusted fields go through the **same** `backend/app/security/sanitize.py` path as replay. There is no second prompt builder to bypass it with. |
| Isolation | Its **own** bounded queue and **own** worker task |

Rotation is: change the token, restart, re-point the forwarder. Revocation is:
clear it, which also fails the feature closed.

### The forwarder

[`backend/tools/eve_forwarder.py`](backend/tools/eve_forwarder.py) is standalone
— it imports nothing from `app/`, and its only dependency is `httpx`. Copy the
single file to the target box. Full flag reference and operational notes are in
[`backend/tools/EVE_FORWARDER.md`](backend/tools/EVE_FORWARDER.md).

```bash
pip install httpx
```

```bash
export FLARE_INGEST_TOKEN='<the service token from the Flare host .env>'
```

```bash
python eve_forwarder.py --eve /var/log/suricata/eve.json --url http://<flare-host>:8000/api/v1/ingest/eve --verbose
```

The token is passed by **naming an environment variable**, never in `argv` —
`ps` is readable by every user on a box you are deliberately attacking.

**Size `--batch` against both limiters.** The global limiter (120/min by
default) applies to `/ingest/eve` as well as the route's own budget, so the
effective ceiling is the *lower* of the two, and **batch size is what keeps a
forwarder under the global one** because it decides how many requests a file
becomes. A 2,075-record file is 208 requests at `--batch 10` and 42 at
`--batch 50`; the first is refused partway through, the second draws zero 429s.
Raise `--batch` before raising either limit.

### What was actually verified

The whole chain was run end to end, not asserted: Suricata 8.0.6 RELEASE
(official `jasonish/suricata` container) with ET Open rules via `suricata-update`
— 68,625 rules, 52,672 enabled, a second pull two rules newer than the
68,623 / 52,670 that produced the committed sample — against `smallFlows.pcap`
(14,261 packets), producing 2,075 EVE records of which 107 were alerts,
forwarded by `eve_forwarder.py` into a running server with replay going the
whole time.

- **107 / 107** alerts reached the pipeline and persisted with `source="live_demo"`, in a **single** forwarder pass of 42 batches, with **zero** schema rejections and **zero** 429s
- **107 / 107** carry a complete seven-node trace whose `classify` entry names the D25 reason
- **Groq answered all 107. LightGBM answered none.** That is the demo dynamic, measured rather than described
- The 1,968 non-alert records were **counted, not discarded**, and attributed by reason in `dropped_breakdown` — an `eve.json` is mostly `flow`/`dns`/`http`/`stats` records, and an operator needs to tell a normal ratio from a broken forwarder
- Replay ran throughout, produced 11 alerts in the same window, none `unknown`, and **not one replay triage slot was consumed by the live lane**

That run also found two defects a pcap-only test could never have surfaced: the
forwarder stranded 27 of 107 alerts after a single 429 because its in-memory
read offset advanced past a failed delivery (fixed with a snapshot-and-rollback,
safe because the endpoint is idempotent by alert id), and the global limiter's
interaction with the ingest budget was undocumented and not guessable.

**The chain is proven against a pcap, which proves the plumbing.** It does not
prove that `nmap`, `hydra`, `hping3` or `sqlmap` against a target box will trip
an ET rule — default ET Open rules do not necessarily fire on a low-rate toy
attack. That rehearsal is a separate, open task and is the top demo risk.

**That pcap is from 2011, and so are the sample's timestamps.**
`smallFlows.pcap` is the public tcpreplay capture, taken 2011-01-25, and
Suricata in offline mode stamps every event with the packet's own time from the
pcap header rather than wall-clock time. The committed
`backend/data/datasets/suricata_eve_sample.json` therefore spans a 4m46s window
in January 2011. The records are genuine engine output over a genuine capture —
old, not synthetic. Worth knowing alongside that: `parse_eve_record` passes the
record's own timestamp straight through, where `parse_cicids_row` takes a
caller-stamped arrival time and parks the 2017 capture time in `captured_at`, so
the EVE path has no arrival-time split and these records would render as some
fifteen years old. Nothing loads the file today — `read_eve_file` has no caller
and the live path is fed by the forwarder, not from disk — so it is a reference
artifact rather than a demo input. A sample that should render fresh has to come
from a fresh capture; restamping these would make the file a fabrication.

---

## 🔧 Configuration

93 settings, all read by real code, all documented in
[`backend/.env.example`](backend/.env.example). A CI check asserts both
directions: every setting the code reads is documented, and nothing is
documented that the code does not read.

Only `JWT_SECRET` is required. Everything below shows its default.

### Required

| Variable | Read by | What breaks without it |
|---|---|---|
| `JWT_SECRET` | `security/tokens.py` | **The app refuses to start.** No fallback, minimum 32 chars |

### Core

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `JWT_ALGORITHM` | `HS256` | `security/tokens.py` | Only accepted value |
| `ACCESS_TOKEN_TTL_MINUTES` | `30` | `security/tokens.py` | The login panel renders "jwt · 30m access"; that claim is only true at 30 |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | `security/tokens.py` | Refresh window |
| `DATABASE_URL` | `sqlite+aiosqlite:///./flare.db` | `store/session.py` | Points at another DB; WAL is set at connect time |
| `ENVIRONMENT` | `dev` | `main.py` | `prod` disables `/docs` |
| `CORS_ORIGINS` | `["http://localhost:5174"]` | `main.py` | Browser calls blocked if wrong |
| `CORS_ALLOW_CREDENTIALS` | `false` | `main.py` | `*` together with `true` is **rejected at startup** |
| `RATE_LIMIT_REQUESTS` / `_WINDOW_SECONDS` | `120` / `60` | `main.py` → `core/middleware.py` | Global inbound limiter; also caps `/ingest/eve` |
| `HEALTH_CACHE_TTL_SECONDS` / `_STALE_SECONDS` | `60` / `120` | `core/health_state.py` | STALE must exceed TTL or startup fails |
| `DEMO_SEED_ENABLED` | `false` | `main.py`, `scripts/seed_demo.py` | On: the demo account exists. Logged loudly. Never enable in prod |
| `LOG_LEVEL` | `INFO` | `core/logging.py` | Log verbosity |

### Replay and the graph

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `REPLAY_ALERTS_PER_MINUTE` | `30.0` | `ingestion/feed.py` | Demo cadence. Every quota figure above is sized from this |
| `REPLAY_AUTOSTART` | `true` | `main.py` | Off: no alerts flow until started. The suite pins it false |
| `GRAPH_BUDGET_SECONDS` | `45.0` | `agent/graph.py` | Whole-graph wall clock. Below the longest provider timeout, startup fails |
| `MAX_CONCURRENT_PIPELINES` | `8` | `agent/graph.py` | Past this an alert waits rather than the process growing |

### Tiering — two independent gates

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `ESCALATION_CONFIDENCE_THRESHOLD` | `0.99` | `agent/graph.py` → `agent/router.py` | Gate 1. Set empirically, fires on ~3/1000 |
| `REASON_SEVERITY_FLOOR` | `high` | `agent/graph.py` → `agent/router.py` | Gate 2, **policy**. `unknown` satisfies no threshold, ever |
| `REASON_CALLS_PER_MINUTE` | `10.0` | `agent/budget.py` | Gate 2's **cap**. This is what keeps the demo under Gemini's RPM |

### Providers

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `GROQ_API_KEY_DEV` / `_RESERVED` / `_SPARE` | unset | `providers/registry.py` → `providers/keypool.py` | Groq enabled with an empty pool **fails closed at startup** |
| `GEMINI_API_KEY_DEV` / `_RESERVED` / `_SPARE` | unset | `providers/registry.py` → `providers/keypool.py` | Same |
| `GROQ_MODEL_PRIMARY` | `openai/gpt-oss-120b` | `providers/registry.py` | Verified by live call, not from docs |
| `GROQ_MODEL_FALLBACK` | `qwen/qwen3.8-27b` | `providers/registry.py` | Different model family, so one provider-side issue is unlikely to hit both |
| `GROQ_REASONING_FORMAT` | `hidden` | `providers/registry.py` | Routes the final answer into `content`. The default emits a separate reasoning channel |
| `GROQ_REASONING_EFFORT` | `low` | `providers/registry.py` | Latency/quality trade |
| `GEMINI_MODEL` | `gemini-3.6-flash` | `providers/registry.py` | `gemini-2.5-flash` is listed and 404s on `generateContent` |
| `GEMINI_THINKING_LEVEL` | `low` | `providers/registry.py` | **Paired with the timeout below.** `high` with a timeout under 60 s is rejected at startup |
| `LLM_TIMEOUT_SECONDS_GEMINI` | `25.0` | `providers/registry.py` | Measured 3.1–5.0 s median with a 20.6 s tail; a 12 s ceiling failed ~1 call in 8 |
| `LLM_TIMEOUT_SECONDS_GROQ` | `15.0` | `providers/registry.py` | Per-call timeout |
| `KEY_COOLDOWN_SECONDS` | `60.0` | `providers/registry.py` → `providers/keypool.py` | How long a 429'd key cools when no `Retry-After` is sent |
| `OFFLINE_MODE` | `false` | `agent/graph.py`, `providers/registry.py` | The **declared** way to run with no keys. Every alert marked `degraded` |

### Enrichment and retrieval

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | unset | `intel/aggregator.py` | Absent: an honest traced **skip**, never a fabricated clean verdict |
| `VIRUSTOTAL_API_KEY` | unset | `intel/aggregator.py` | Same |
| `INTEL_TIMEOUT_SECONDS` | `8.0` | `intel/aggregator.py` | Per-source timeout |
| `INTEL_ESCALATION_SCORE` | `50` | `agent/graph.py` → `agent/nodes/enrich.py` | Reputation at or above this forces `high`. Intel beats the model, loses to a rule |
| `INTEL_CACHE_TTL_SECONDS` | `900.0` | `intel/aggregator.py` | Per-IP cache. This is what bounds real quota spend |
| `INTEL_CACHE_MAX_ENTRIES` | `2048` | `intel/aggregator.py` | Bounded so the cache cannot grow without limit |
| `RETRIEVAL_TOP_K` | `5` | `rag/retriever.py` | Candidates handed to the reason node |
| `RETRIEVAL_LOW_CONFIDENCE_SCORE` | `0.45` | `agent/graph.py` → `agent/nodes/retrieve.py` | Below this the match is **reported** low-confidence, not dropped |

### Product surface

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `HEALTH_DEEP_CALLS_PER_MINUTE` | `4.0` | `core/user_rate_limit.py` | A second, per-user budget on the route that spends four metered quotas per call |
| `RULE_REGEX_MAX_LENGTH` | `200` | `rules/engine.py` | Checked at rule creation |
| `RULE_REGEX_MAX_QUANTIFIERS` | `8` | `rules/engine.py` | Checked at rule creation |
| `RULE_REGEX_MATCH_TIMEOUT_SECONDS` | `0.05` | `rules/engine.py` | Checked on every match. Without it a catastrophic backtrack stalls the whole API |
| `RULE_REGEX_MAX_SUBJECT_LENGTH` | `1024` | `rules/engine.py` | Checked on every match |
| `EXPORT_MAX_ROWS` | `500` | `api/routes/export.py` | The frozen export button always sends `limit=500`; this caps it server-side |
| `CORRELATION_MIN_ALERTS` | `3` | `workers/scheduler.py`, `api/routes/alerts.py` | A **real** cluster threshold, not a client-side reduce |
| `CORRELATION_WINDOW_MINUTES` | `1440` | `workers/scheduler.py`, `api/routes/alerts.py` | Correlation window |
| `STATS_WINDOW_MINUTES` / `STATS_BUCKET_SECONDS` | `30` / `60` | `api/routes/metrics.py` | One-minute buckets, so a bucket count *is* alerts-per-minute. A bucket larger than the window is rejected at startup |
| `METRICS_SAMPLE_INTERVAL_SECONDS` | `60` | `workers/scheduler.py` | Sampling cadence for the velocity series |
| `METRICS_SAMPLE_WINDOW_MINUTES` | `60` | `api/routes/metrics.py` | How much of the sampled series the rail plots |
| `FORECAST_WINDOW_MINUTES` | `30` | `api/routes/metrics.py` | Window-over-window delta |
| `PIPELINE_ACTIVITY_SAMPLE_SIZE` | `200` | `api/routes/metrics.py` | Bounded so the panel cannot become a full-table scan |
| `SCHEDULER_ENABLED` | `true` | `workers/scheduler.py` | Off: the clusters screen serves whatever the last run stored — the honest consequence |
| `CORRELATION_REFRESH_SECONDS` | `120` | `workers/scheduler.py` | Refresh cadence |
| `PLAYBOOK_AUTOTRIGGER_ENABLED` | `true` | `ingestion/feed.py` → `playbooks/engine.py` | A matching playbook executes automatically. `unknown` severity never auto-triggers |

### The eval

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `EVAL_SAMPLE_SIZE` | `300` | `eval/harness.py` | 1/300 = 0.0033 expresses every guard threshold; 1/80 = 0.0125 cannot express 0.995 at all |
| `EVAL_SEED` | `20260904` | `eval/dataset.py` | Threaded through sampling and shuffling |
| `EVAL_LLM_PACE_SECONDS` | `2.0` | `eval/harness.py` | Sequential pacing so a run stays inside Groq's ~30 RPM |
| `EVAL_SCORE_FULL_PARTITION` | `true` | `eval/harness.py` | Off: the degenerate and absolute-ceiling guards go **inconclusive** |

### Live injection

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `LIVE_INGEST_ENABLED` | `false` | `api/router.py` | Off: the route is **not mounted at all** |
| `INGEST_SERVICE_TOKEN` | `""` | `security/service_token.py` | Enabled without ≥32 chars: **the app refuses to start** |
| `INGEST_REQUESTS_PER_MINUTE` | `60.0` | `api/routes/ingest.py` | The route's own budget |
| `INGEST_BURST` | `10` | `api/routes/ingest.py` | Burst allowance |
| `INGEST_MAX_BODY_BYTES` | `1048576` | `api/routes/ingest.py` | Checked from `Content-Length` before the body is read |
| `INGEST_MAX_EVENTS_PER_BATCH` | `200` | `api/routes/ingest.py` | Bounds the work one accepted request can create |

### Notifications

| Variable | Default | Read by | Consequence |
|---|---|---|---|
| `NOTIFICATIONS_ENABLED` | `false` | `notifications/dispatcher.py` | On **without** `SMTP_HOST` and `SMTP_FROM`: startup refuses (fail closed) |
| `PRESENCE_STALE_SECONDS` | `900.0` | `notifications/presence.py` | How long a connection's last frame counts as watching |
| `NOTIFY_SEVERITIES` | `["critical","high"]` | `notifications/dispatcher.py` | `unknown` is **rejected here**, not merely absent |
| `NOTIFICATION_DEBOUNCE_SECONDS` | `300.0` | `notifications/dispatcher.py` | One email per user per event type per window. The first is immediate |
| `NOTIFICATION_DIGEST_THRESHOLD` | `3` | `notifications/dispatcher.py` | Above this the email is presented as a digest |
| `NOTIFICATION_DIGEST_MAX_ALERTS` | `10` | `notifications/dispatcher.py` | How many a digest lists before "and N more" |
| `NOTIFICATION_PENDING_MAX` | `200` | `notifications/dispatcher.py` | Bounded, so a wedged flusher cannot grow memory |
| `NOTIFICATION_FLUSH_SECONDS` | `60` | `workers/scheduler.py` | Drain cadence, well below the debounce window |
| `NOTIFICATION_MAX_ATTEMPTS` | `3` | `notifications/dispatcher.py` | Retries only **transient** failures; a permanent 5xx is not retried |
| `NOTIFICATION_RETRY_BACKOFF_SECONDS` | `2.0` | `notifications/dispatcher.py` | Exponential base |
| `NOTIFICATION_QUEUE_SIZE` | `500` | `notifications/dispatcher.py` | Bounded hand-off, so SMTP can never stall the feed |
| `SMTP_HOST` / `SMTP_PORT` | unset / `587` | `notifications/email.py` | Required when notifications are on |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | unset | `notifications/email.py` | Must be set **together** or startup fails |
| `SMTP_FROM` / `SMTP_FROM_NAME` | unset / `Flare SOC` | `notifications/email.py` | Sender identity; `SMTP_FROM` required when on |
| `SMTP_USE_TLS` / `SMTP_START_TLS` | `false` / `true` | `notifications/email.py` | **Mutually exclusive** — both true is rejected at startup |
| `SMTP_TIMEOUT_SECONDS` | `15.0` | `notifications/email.py` | The point of the rewrite: the predecessor's blocking `smtplib` had no timeout and hung a worker forever on a black-holed host |
| `DASHBOARD_BASE_URL` | `http://localhost:5174` | `notifications/dispatcher.py` | Where the email's single link points. No tracking pixel, no external asset |

---

## 📁 Project Structure

```
Flare_V2/
├── .github/workflows/ci.yml       # quality, integrity, cold-clone, load + an aggregate gate
├── PLAN.md                        # The build plan: decisions D1-D39, invariants I1-I19
├── CONTRACT.md                    # Frozen-frontend API contract, screen by screen
├── openapi.yaml                   # The wire spec (4 known gaps — see limitations)
├── REAL_VS_SIMULATED.md           # The real/replayed boundary, stated up front
├── GAPS.md                        # Plan-vs-build sweep: what closed, what is open
├── BACKEND_SUMMARY.md             # Long-form implementation record, incl. doc/code drift
│
├── backend/                       # FastAPI + LangGraph, :8000
│   ├── app/
│   │   ├── agent/                 # THE PIPELINE
│   │   │   ├── graph.py           # StateGraph assembly, wall clock, run_pipeline (the eval's entry point)
│   │   │   ├── router.py          # Pure state -> str conditional edges. Stage skipping lives HERE
│   │   │   ├── admission.py       # Reasoning admission, decided on the path every alert takes
│   │   │   ├── budget.py          # The reason-calls-per-minute token budget
│   │   │   ├── prompts.py         # PROMPT_FEATURES (15 of 77) and the prompt builders
│   │   │   ├── trace.py           # @traced — exactly one TraceNode per node, always
│   │   │   └── nodes/             # classify, enrich, retrieve, reason, recommend, rules, finalize
│   │   ├── ml/                    # features.py (77-column ALLOWLIST), classifier.py (LightGBM + isotonic)
│   │   ├── rag/                   # embedder (ONNX), retriever (numpy cosine), chunker, loader, corpus/
│   │   ├── eval/                  # harness, dataset (SCORABLE_SOURCES), guards, scoring, pricing, cache
│   │   ├── ingestion/             # replay, feed (ONE loop per server), normalize, suricata, live, labels
│   │   ├── intel/                 # aggregator (max/any, concurrent), abuseipdb, virustotal
│   │   ├── providers/             # keypool (sticky, cooling, dead), groq, gemini, offline, registry
│   │   ├── rules/                 # engine (runs LAST), safety (ReDoS bounds), store
│   │   ├── playbooks/engine.py    # manual / approval / auto, branched for real
│   │   ├── notifications/         # dispatcher (presence, debounce, digest), email, presence
│   │   ├── analytics/             # correlation (SQL GROUP BY), metrics (zero literals)
│   │   ├── security/              # sanitize (escape + clamp), tokens, hashing, service_token
│   │   ├── api/routes/            # 38 handlers across 14 modules
│   │   ├── store/                 # models, repositories, session (WAL, schema verification)
│   │   ├── workers/               # queue (bounded, drops COUNTED), scheduler
│   │   ├── config.py              # All 93 settings. Every one read by real code
│   │   └── main.py                # Lifespan: verify schema, load artifacts, fail closed
│   ├── alembic/versions/          # 4 migrations. The ONLY schema authority
│   ├── data/
│   │   ├── splits/                # train 5,400 / eval 1,800 / replay 1,800 + MANIFEST.json
│   │   ├── eval/                  # n80, n300, n300_postadjudication, latest — all published
│   │   ├── datasets/              # suricata_eve_sample.json (107 real Suricata 8.0.6 alerts
│   │   │                          #   over smallFlows.pcap; 2011 stamps are the pcap's own.
│   │   │                          #   Reference artifact — no code loads it)
│   │   ├── retrieval_labels.json  # 18 hand-labelled retrieval pairs
│   │   └── PROVENANCE.md          # Dataset provenance, defect list, live-chain verification
│   ├── models/                    # 28 MB, COMMITTED so a cold clone needs no network
│   │   ├── classifier/            # boosters, feature schema, metrics.json, MODEL_CARD.md
│   │   ├── embeddings/            # MiniLM int8 ONNX + tokenizer, checksummed
│   │   └── index/                 # embedding matrix, chunk manifest, RETRIEVAL_REPORT.json
│   ├── scripts/                   # fetch_dataset, build_partitions, train_classifier, build_index,
│   │   │                          #   run_eval, seed_demo, verify_models, send_test_email
│   │   └── ci/                    # checks.py (8 checks), run.py, smoke.py
│   ├── tests/                     # 834 tests: unit, integration, failure, load, invariants, contract, ci
│   ├── tools/                     # eve_forwarder.py — runs on the TARGET box, imports nothing from app/
│   ├── Makefile / make.ps1        # Identical target lists, asserted by a test
│   └── pyproject.toml
│
└── frontend/                      # React 19 + Vite 8, :5174 — FROZEN
    ├── src/
    │   ├── components/            # AlertTable, AlertDetailDrawer (renders trace[]), WorkspacePanel,
    │   │   │                      #   DashboardView, FilterStrip, FlareLanding
    │   │   ├── dash/              # DashSidebar, TopBar, RightRail, CommandPalette
    │   │   ├── flare/             # AuthPanel, PipelineStages, Telemetry, EmberField
    │   │   └── landing/           # Globe, CursorField, StageCards, TriageBuffer
    │   ├── hooks/useAlertStream.js  # First-message auth handshake + presence (FE-2)
    │   ├── contexts/              # AuthContext (silent refresh on 401), ThemeContext
    │   └── pages/                 # Login, Register, Dashboard, Settings
    ├── e2e/auth.spec.js           # Playwright
    └── vite.config.js             # /api proxy with ws: true (FE-1)
```

There is no root `package.json` and no root Python project. `backend/` and
`frontend/` are installed and run separately.

---

## 🔌 API

Everything is under `/api/v1`. Responses are enveloped as
`{ok, data, meta:{latency_ms}}`; `meta.latency_ms` is **omitted** rather than
zero-filled when it was not measured.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/register`, `/auth/login`, `/auth/refresh` | — | Register, sign in, rotate |
| `GET` / `PUT` / `POST` | `/auth/me`, `/auth/profile`, `/auth/change-password` | JWT | Profile. A password change bumps `token_version` and invalidates outstanding tokens |
| `GET` | `/alerts`, `/alerts/attack-types`, `/alerts/clusters` | JWT | Alert list with filters; type facets; correlated clusters from the DB |
| `WS` | `/ws/stream` | **First-message handshake** | One complete alert per message. Inbound `pause` / `resume` / `config{speed}` / `presence` |
| `GET` | `/stats`, `/metrics/rail`, `/metrics/overview` | JWT | Velocity buckets, right-rail series, header counters computed over the whole table |
| `GET` | `/eval` | JWT | The cached eval payload the Evaluation screen renders |
| `GET` / `POST` / `DELETE` | `/rules`, `/rules/{id}` | JWT | Rule CRUD, scoped to the owner. **No update and no enable/disable call** |
| `GET` | `/rules/alerts/{id}/explain-rules` | JWT | The per-condition fire trace recorded **at triage time**, not recomputed |
| `GET` / `POST` / `PUT` / `DELETE` | `/playbooks`, `/playbooks/{id}` | JWT | Playbook CRUD |
| `POST` / `GET` | `/playbooks/{id}/execute`, `/playbooks/executions/{id}` | JWT | Execute and poll. `manual` / `approval` / `auto` are 200 / 403 / 409 distinguishable |
| `GET` / `POST` / `DELETE` | `/notifications/preferences`, `/preferences/{id}`, `/notifications/log` | JWT | Preferences upsert by `(user, channel, event_type)`; delivery log. A `slack` preference is **refused with a message**, not accepted and ignored |
| `GET` | `/export/alerts/{format}` | JWT | CSV and PDF. Formula injection escaped; headers emitted even on an empty set |
| `GET` | `/logs`, `/logs/me` | admin / JWT | Audit log |
| `GET` | `/users`, `/jobs`, `POST /jobs/{job}/run` | **admin** | User list, scheduler job receipts, manual job run |
| `GET` | `/health` | JWT | **Never probes a provider.** Serves a 60 s cache. An anonymous health endpoint in a prior codebase is why this one is authenticated |
| `GET` | `/health/deep` | JWT | The real four-provider probe. Manual refresh only, own 4/min budget |
| `POST` | `/ingest/eve` | **ServiceToken** | Live Suricata injection. **Not mounted unless enabled** |

Full request and response shapes are in [`openapi.yaml`](openapi.yaml); the
frontend's field-by-field consumption is in [`CONTRACT.md`](CONTRACT.md).

---

## 🔐 Security

| Control | Where |
|---|---|
| **No JWT in a query string.** The WebSocket authenticates on the first frame, under a timer; any frame before a successful auth is discarded | `backend/app/api/routes/stream.py` |
| **Password change or deactivation invalidates outstanding tokens** — `User.token_version`, exact integer comparison | `backend/app/security/tokens.py` |
| **Prompt injection, both halves.** JSON-escape and length-cap on input, delimiters plus an untrusted-data preamble, and enum-clamping on output. Clamping alone would leave a model that can be talked into writing anything into the narrative an analyst reads | `backend/app/security/sanitize.py` |
| **Retrieval grounding.** Every MITRE technique id the model cites is dropped unless the retriever actually returned it | `backend/app/agent/nodes/reason.py` |
| **ReDoS bounds on user-supplied regex.** `regex` rather than `re`, because only it can enforce a match deadline — a catastrophic backtrack in `re` cannot be interrupted and would stall the whole API. Length and quantifier count checked at rule creation; deadline and subject length on every match | `backend/app/rules/safety.py` |
| **CSV formula injection escaped.** A cell starting `=`, `+`, `-`, `@`, tab or CR is code execution in Excel when the analyst opens the export, and signature text is attacker-influenced | `backend/app/export/writers.py` |
| **CORS closed by default**, and `*` together with credentials is rejected at startup | `backend/app/main.py` |
| **Key material never enters a trace, a log, a payload or an error.** `__repr__` is overridden on both pool classes because the default would print the secret into any exception context | `backend/app/providers/keypool.py` |
| **RBAC enforced server-side on every route that declares a role.** The UI hiding a control is a hint, never the boundary | `backend/app/api/deps.py` |
| **Rule reads, updates and deletes are scoped to the owner** (IDOR). Enforcement is deployment-wide by design — a detection rule is a statement about the network, not a per-user preference — and every fire is attributed by rule id and name | `backend/app/api/routes/rules.py` |
| **Secret scan in CI** over every tracked file: 8 credential shapes, no committed `.env`, no committed database, no key material | `backend/scripts/ci/checks.py` |

The live-ingest endpoint's controls are in [its own
section](#-live-staged-attack-injection).

---

## 🧪 Testing and CI

**834 tests. ruff clean over the tree. mypy clean over 123 source files.** A
warning fails the run. The suite runs against a throwaway database in a temp
directory, pinned before any app import, and refuses to start if the resolved
URL looks like a runtime database.

The layers are addressable, and `--strict-markers` makes a typo a collection
error rather than a silently unselected test:

| Layer | Count | What it covers |
|---|---|---|
| `-m failure` | 40 | Provider down, 429, timeout, malformed output, empty 200, intel partial/total failure, DB locked, queue full, dead key |
| `-m load` | 11 | Bounded queues drop and count rather than growing; a 503 rather than a hang; one loop under N clients |
| `-m invariant` | 84 | One named test per PLAN §5 invariant |
| `-m contract` | 37 | The frozen-frontend response shapes, field by field |

`backend/tests/invariants/test_invariants.py` **parses PLAN §5 out of the plan
file** and fails the build on an invariant with no mapped test, so the mapping
cannot rot.

CI runs four working jobs plus an aggregate gate for branch protection, and
every step is reproducible locally by the same command the workflow uses:

| Step | Enforces |
|---|---|
| ruff | Lint. **Config-only, never `--fix`** — a job that rewrites the tree it is checking reports on code that is not the code under review |
| mypy | `disallow_untyped_defs` over `app` and `scripts` |
| pytest | The suite, warnings-as-errors. The load layer runs in its **own job**, so a slow layer never hides behind a fast one |
| `disjointness` | Partitions pairwise disjoint by row id **and** by 77-feature vector |
| `artifact_integrity` | Three checksum manifests plus the classifier's schema fingerprint against the serving code |
| `train_serve_skew` | One fixture row through both feature builders must produce byte-identical `float32` vectors |
| `label_leak` | Dumps every prompt the LLM tier would send, greps it for 20 label strings, uploads the dump as a build artifact |
| `secret_scan` + `gitignore` | No committed credentials, no committed `.env`, no committed database; and the ignore file will not let the next `git add .` commit one |
| `env_example` | Both directions: nothing undocumented, nothing documented that code does not read |
| cold-clone smoke | Fresh checkout, no pip cache: migrate from zero, load both ML artifacts **with the network blocked**, boot, hit `/health` |

`scripts.ci.run` defines an eighth check, `metric_literals` — no metric key in
`app/` is ever assigned a numeric literal. The workflow does not invoke it by
name; `make ci` runs it, and the same scan runs inside the suite as
`test_I2_no_hardcoded_metric_literals`.

**Seven of the eight data and artifact checks are proven to fail on a
deliberately broken input** — `backend/tests/ci/test_checks_fail_on_broken_input.py`
overlaps a row, shares a feature vector while keeping the ids distinct, corrupts
a checksum, diverges a schema fingerprint, plants a label string, commits a key
and plants a dead config flag, then asserts the specific check goes red each
time. A check that has never failed is a check you cannot trust.
`metric_literals` is the one with no such test; it is asserted only in the
positive direction.

The cold-clone job earns its keep. It found that `langgraph` had been installed
by hand into the development virtualenv since Phase 3 and named in no dependency
list — five phases of green local runs never saw it, and `pip install -e .` on a
fresh machine produced a package that could not import its own pipeline.

---

## 🔄 v1 → v2

### Why v2 exists

This is a **ground-up backend rewrite against a frozen frontend**, not a patch.
Two earlier codebases were audited: a teammate's, which had the frontend that
ships and a backend built on a hardcoded lookup table; and the one referred to
here as **v1**, which had a genuinely good engine and a much weaker product.
Neither was shippable alone, and the audit — not taste — is what made a rewrite
the right call.

The frontend that ships is the teammate's, frozen. Eighteen additive changes to it
were sanctioned and documented, `FE-1` through `FE-18`; everything else in it is
untouched. The backend is new.

### What v1 had that was real, and was kept or rebuilt

v1's engine was the better of the two, and a lot of it survives in shape:

- **The LangGraph pipeline itself** — pure conditional-edge functions, one trace entry per node, a decorator enforcing it, and a finalize step that synthesises a `skipped` node with a human reason for every node that never ran. v2's `agent/` is recognisably descended from this.
- **Retrieval grounding.** v1 already dropped every ATT&CK technique id the model cited that the retriever had not returned, and re-hydrated the survivors from its own objects. This is a real defence and v2 keeps it verbatim in intent.
- **Intel outranking the model.** A reputation score at or above the escalation threshold upgrades severity regardless of the classifier. v1 had it; v2 keeps it and adds a rule layer above it.
- **Bounded queues that drop and count**, a token-bucket limiter, a tiered cache, and partial-intel-failure treated as a first-class degraded result rather than an error.
- **Offline mode as a real declared path**, substituting only the four network leaves and running the genuine graph through them. v1's version was thoughtful and v2's is a slimmer descendant of it.
- **The eval calling the production graph.** v1's runner was explicit that failures stay in the denominator and that the eval must not have its own code path. That principle is v2's E3 and it is inherited, not invented.

### What did not survive the audit

Concretely, and without softening:

**The teammate's backend scored itself.** Its fast tier was a 26-entry hardcoded
dict keyed on the alert signature, and the eval's ground truth was built from the
same dict — byte-identical, 26/26 keys, 26/26 values. Every metric returned
`1.000` at `0.0 ms` with zero model calls, deterministically, forever. The
failure is not that the number was high; it is that the number was
**structurally incapable of being anything else**. Its own changelog described a
"signature lookup table for perfect F1 scores", which is a written confession.

**v1 put the answer in the prompt.** Its `ingestion/parsers/cicids.py:107` built
the alert signature as `f"CICIDS {raw_label} flow {src}:{sport} -> {dst}:{dport}"`,
and its `agent/nodes/classify.py:72` put `alert.signature` straight into the
classification prompt. **Every eval prompt therefore carried the answer in plain
text** — the audit recorded it as 450 of 450. This is the worse of the two
failures, because it looked rigorous: real API calls, real latency, a real
confusion matrix, all measuring a model reading the answer off the page.

**v1's ground truth was itself from a corrupted mirror.** Its committed
450-row `cicids2017_labeled_subset.csv` carries addresses that decode to
nonsense (`8.6.0.1`, `8.0.6.4`), with the `Protocol` and destination-port
columns zeroed. v2 evaluated that same mirror family, rejected it on exactly these
grounds, and pinned a digest-verified `GeneratedLabelledFlows.zip` instead —
then cross-checked it by cleaning the five attack days and confirming the row
counts matched an independently packaged distribution to the row.

**Cold clones did not work.** v1's `.gitignore` excluded `data/onnx/` with the
comment "downloaded on first use / at build time", and its `store/chroma.py`
imported `chromadb` at module level. A missing download or a failed import took
the whole app down at startup, on a machine that had never run it.

**Dead and stale surfaces.** A `zeek` parser wired into the normalizer's dispatch
table with nothing producing Zeek input. A three.js landing hero shipped with two
unused variants of itself. And v1's backend README was a single `.` character.

**And nothing was held out anywhere.** Neither codebase could have detected its
own defect.

### What is genuinely new in v2

| | |
|---|---|
| **A trained classifier** | LightGBM on a held-out partition, with a committed model card, confusion matrix, feature importances and calibration report. Replaces a lookup dict in one build and an LLM-call-per-alert in the other |
| **Transformer retrieval without a vector DB** | MiniLM int8 ONNX weights committed with checksums, a 313-chunk numpy index, and a measured recall report. Replaces Chroma plus a gitignored download |
| **A three-way disjoint partition** | train / eval / replay, enforced on the **feature vector** rather than the row id, partition-stamped in every row id, CI-checked. v1 had no partition at all |
| **Guard bands** | Seven of them, on the eval itself, with superseded thresholds published on every payload. One caught a real 62-row leak that id-level disjointness missed |
| **The provider key pool** | Three keys per provider with declared purposes, sticky-until-exhausted, cooling on 429, dead on 403 |
| **Presence-aware notifications** | Real SMTP with a real timeout, suppressed for an analyst who is actually watching, debounced and rolled up |
| **Live staged-attack injection** | A real Suricata feeding a real endpoint, isolated behind its own queue and worker, off by default, verified end to end |
| **Auth, RBAC and an audit log** | v1's API was entirely unauthenticated by design |
| **Rules, playbooks, correlation and export** | None of which v1 had |
| **CI** | Eight integrity checks, seven of them proven to fail on a broken input, plus a network-blocked cold-clone job. v1 listed CI under *Future Improvements* |
| **One schema authority** | Alembic only. The teammate's build ran Alembic *and* `create_all` and they collided |

### What v2 deliberately does not do

- **No live traffic capture.** No sensor on production traffic, no VPS mirroring, no paid streaming intel API. Replay is the primary path, and replay is what makes the eval possible — ground truth is what lets a number mean anything, and live traffic has none.
- **No multi-tenancy.** Single-tenant by design. The model would support it; the query filters do not exist, and it will not be called multi-tenant until they do.
- **No vector database.** A real transformer, no Chroma. At 313 chunks the index is one numpy array.
- **No Slack or webhook notifications.** Email is wired and presence-aware. Slack is **rejected at the API with a message** rather than accepted and silently ignored, so nobody can create a preference and watch nothing happen.
- **No 3D topology.** The topology view is SVG driven by real alerts. The 3D claim was stale and the component is gone — though the unused `three` dependency is still in `frontend/package.json`.
- **No seeded demo data.** The rules table is genuinely empty on a fresh boot and the demo account genuinely does not exist until you seed it. If a screen looks bare, that is the honesty policy rather than a missing feature.

---

## ⚠️ Known Limitations

Stated here rather than left for a reader to find.

**Measurement**

- **The LLM tier is not a classifier on single CICIDS flows** — 0.2333 against a 0.1667 random baseline. Measured, understood, and the reason the fast tier owns classification.
- **`PROMPT_FEATURES` sends 15 of the 77 columns** the classifier sees. `Bwd Packet Length Min` — a reverse-direction statistic that helps separate a no-reply flood from an ordinary short request — is in the model's feature set and **not** in the prompt. The fifteen were chosen for prompt size in Phase 3, *before* the LLM tier had ever been scored, and **they are not changed now**: adding columns after seeing a 0.23 is tuning toward an eval number, and the resulting figure would not be comparable to the one on record.
- **Escalation is rare by design** — ~3 in 1,000, and **0 of 300** in the published run — so the as-shipped system number *equals* LightGBM-alone. **It is reported as equality, not as a win.**
- **The capped sample is 300 rows**, where one misclassification moves the headline by 0.0033. That is why the quoted figure is the full-partition 0.9944.
- **Balanced sampling flatters `benign`.** Real traffic is ~65% benign; the eval partition is 16.7%. Precision on `benign` would be materially different under the natural prior.
- **The severity head is not independent evidence.** Severity is a deterministic function of attack type here, so it solves a strictly easier problem. Six `high` rows were called `low`, which in production means a real attack presented as low severity.
- **Nothing here generalises to another network without retraining.** One 2017 test-bed, one attacker configuration. The score says nothing about how it would do elsewhere. `Destination Port` is the highest-gain feature and will mislead on a non-standard port.
- **The model has no "none of the above."** Six classes; anything else — Heartbleed, Infiltration, FTP/SSH brute force — is forced into one of them with unknown behaviour.
- **`MODEL_CARD.md`'s "best single feature reaches 0.8783" has no producer.** Every other number in that section is recomputed on each training run; this one is a one-off manual measurement presented alongside them.

**Retrieval**

- **`webattack-brute-force` retrieves T1505.003 (Web Shell) over T1110 (Brute Force).** It is the single recall@5 miss in the report. Documented and **not hand-corrected** — hand-tuning a retrieval result to look right is how a retriever stops being a retriever.

**Throughput and quota**

- **The replay loop cannot sustain its configured rate.** `ReplayEngine.run` awaits the whole graph and *then* sleeps the interval, so the real period is `graph_time + interval`. At the shipped 30/min (2.0 s interval) and the eval's measured 1,727 ms mean system latency, real throughput is **~16 alerts/min**. Every quota figure above assumes 30/min and is therefore conservative rather than wrong — but 30 alerts/min is not a rate this loop achieves while the reasoning tier is firing.
- **VirusTotal's ~4/min cap can be exceeded on a burst.** Measured over the first 300 replay rows, the worst minute introduces 5 new distinct IPs. A 429 there yields a scoreless `rate_limited` result and a degraded-but-usable aggregate, so it degrades honestly rather than failing — but it is a real ceiling, not headroom.
- **Key-pool cooling state is in-memory and per-process.** A second process keeps its own view. Accepted, and consistent with the one-loop-per-server design.

**Surface with no producer**

- **`export.ready` is a valid notification event type that nothing fires.** Exports are synchronous — `GET /export/alerts/{format}` returns the file in the response — so there is no later "ready" moment. The enum is pinned by the frozen contract, and it becomes real the moment exports go async.
- **`Rule.is_enabled` has no toggle endpoint and no update endpoint.** The rules API is create, list, delete and explain. The field is set to `true` at creation and is honoured by the engine, but nothing can change it through the API. The frozen frontend renders it as a display-only dot and has no control that would call one.

**Timing and delivery**

- **The stale-presence window is 900 seconds**, sized for the frozen frontend's frame cadence: presence is sent on connect and on `visibilitychange`, and nothing periodic — so an analyst reading the screen without switching tabs emits no frames at all. A shorter window would mark that analyst away and email them about an alert on the screen in front of them. A periodic heartbeat would let it shrink to a minute or two; that would be another frontend change, and the frontend is frozen.
- **Deliverability has no automated test and cannot have one.** The transport, templates, debounce and presence policy are all tested against a fake transport and a monkeypatched `aiosmtplib.send`. Whether a message lands in an inbox or a spam folder is answered only by sending one. It has been run and the message reached the inbox — that is a recorded operator action, not a test result, and it is listed as one. `python -m scripts.send_test_email <address>` is the command.
- **Gemini returns 503 intermittently.** Cross-provider fallback is wired and tested; a failed call is recorded as failed, never as a silent default.

**Live injection**

- **Live-demo alerts carry no ground truth and never will.** They buy realism, not eval credibility, and are structurally barred from the eval and training partitions.
- **Suricata's default ET Open rules do not necessarily fire on a toy attack.** The chain is proven against a pcap, which proves the plumbing. The attack→rule mapping against `nmap` / `hydra` / `hping3` / `sqlmap` has not been rehearsed, and that is a rehearsal risk rather than a code defect. It is the top demo risk.

**Documentation and spec**

- **`openapi.yaml` still carries four known gaps**, all recorded in [`GAPS.md`](GAPS.md) with the code's behaviour as the truth: the ingest security scheme is documented as `bearer` while the code requires `ServiceToken`; a `403` is documented for "ingestion disabled" while the code returns `404` because the route is not mounted; a `503` is documented for a full triage queue while the code returns `202` with the drop counted; and the `202` body lists an `alert_ids` field that nothing produces.
- **Four docstrings and one comment cite things that have moved.** Two name test files that do not exist (the properties *are* asserted, elsewhere); several still explain the eval in terms of an 80-row sample when the shipped default is 300; and the enrichment skip rate is quoted as 90.5% in three places when the measured figure under the shipped routing rule is 74.1%. The behaviour is correct in every case; the pointers are stale. `BACKEND_SUMMARY.md` §16.4 carries the full list.
- **`frontend/package.json` still depends on `three`**, which no source file imports.
- **Four more doc/code disagreements found while writing this file**, none of them in §16.4, and the code is the truth in all four: the old backend README (folded into this file) and `BACKEND_SUMMARY.md` §10.3 both print the n=300 baselines in the n=80 column, where the recorded values are majority **0.175000** and 1-NN **1.000000**; `backend/.env.example` and `openapi.yaml` both still print the demo credentials in full, which `GAPS.md` §C reports as removed everywhere but `CONTRACT.md` and `PLAN.md`; `backend/.env.example` documents `LLM_TIMEOUT_SECONDS_GROQ=30` while the shipped default is `15.0`; and PLAN §21, `REAL_VS_SIMULATED.md` and `BACKEND_SUMMARY.md` §16.2 all say `Rule.is_enabled` is "set at create and at update" when there is no update path at all — `CONTRACT.md`'s endpoint inventory, which states plainly that there is no rule update and no enable/disable call, is the one that is right.

---

## 🔮 Future Improvements

- **Make the replay loop hit its configured rate** — schedule the next emit off a monotonic deadline rather than sleeping after the graph returns, so `REPLAY_ALERTS_PER_MINUTE` means what it says.
- **A periodic presence heartbeat from the frontend**, which would let the 900-second stale window shrink to a minute or two.
- **Async exports**, which would give `export.ready` a producer and retire the one enum value with no meaning behind it.
- **Reconcile `openapi.yaml` with the four spec gaps**, in the direction `GAPS.md` recommends: the code is right in all four.
- **Postgres**, which is a `DATABASE_URL` change plus a driver — and the prerequisite for multi-tenancy, since cross-process key-pool and presence state need somewhere shared to live.
- **Retrain against a second capture.** Everything measured here is one test-bed. A second dataset is the only thing that would say anything about generalisation.
