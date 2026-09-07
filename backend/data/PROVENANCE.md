# Data provenance

## Source of record

**CICIDS2017**, distribution **`GeneratedLabelledFlows.zip`** — 8 CSVs, 85
columns: 78 flow features, six identity/metadata columns and a `Label`.
<https://www.unb.ca/cic/datasets/ids-2017.html>

> **This is not the distribution Phase 2 used.** Phase 2 read
> `MachineLearningCSV.zip` (79 columns), which carries no Flow ID, no
> endpoints and no timestamp. The frozen frontend requires `src_ip` and
> `dest_ip` on every alert, so endpoints had to be derived from CICIDS2017's
> published topology and stamped as derived. `GeneratedLabelledFlows` is the
> same CICFlowMeter run over the same captures with those columns present.
> **Every endpoint in a replayed alert is now the address the capture actually
> recorded, and the synthesis code is deleted rather than switched off** —
> there is no `EndpointPolicy`, no `endpoints_synthetic` field and no
> `replay_synthesize_endpoints` setting anywhere in the tree.
> `tests/unit/test_ingestion.py::test_no_endpoint_synthesis_path_remains`
> asserts all three.

### How it was acquired

UNB gates its own download: every direct path under `cicresearch.ca` 302s to a
~108KB HTML registration form, and the Kaggle mirrors carry the
`MachineLearningCSV` variant only. `scripts/fetch_dataset.py` therefore
supports two sources and assumes neither:

| Flag | Source |
|---|---|
| `--glf-hf` | `bencorn/CICIDS2017`, file `csvs/GeneratedLabelledFlows.zip` — free, anonymous, no credentials |
| `--local PATH` | an already-downloaded `GeneratedLabelledFlows.zip` or a directory of extracted `*.pcap_ISCX.csv` files |

This build used the mirror. The archive is pinned by digest:

```
GeneratedLabelledFlows.zip
sha256  7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a
size    283.9 MB
inner   TrafficLabelling /<eight canonical files>
```

`fetch_dataset.py` verifies that digest on download and refuses to proceed on a
mismatch, so a silently re-uploaded mirror is a loud failure rather than a
quiet change of dataset underneath a committed model.

**`MachineLearningCSV` is deliberately rejected.** A file missing the six
metadata columns raises `MissingMetadataError` — accepting it would only
reintroduce derived endpoints through a side door.

### Provenance verification actually run

A mirror can be the right filename and the wrong data. `bvk/CICIDS-2017` was
evaluated and **rejected** on exactly this: its addresses decode to nonsense
(`8.6.0.1`, `8.0.6.4`), its timestamps are Excel-mangled (`59:05.7`), and its
protocol and destination-port columns are zeroed. The accepted archive was
checked the same way before anything was built on it:

| Check | Expected | Observed |
|---|---|---|
| Column count | 85 | 85, original header with leading whitespace |
| Attack source addresses | `172.16.0.1` (Kali behind NAT), `205.174.165.73` (botnet C2) | both present, and *only* on attack rows |
| Victim network | `192.168.10.0/24` | 33,407 of 40,000 sampled source addresses; DoS rows target `192.168.10.50` on port 80 |
| Timestamps | real datetimes in the capture week | `5/7/2017 8:42`, dates 5–7 July 2017, one date per file matching the documented day |
| Destination ports | non-zero, plausible | 443, 53, 80, 123, 22, 137 |
| Protocol | IANA numbers | 6 (TCP), 17 (UDP), 0 (HOPOPT) |

**Independent cross-check.** Cleaning the five attack days yields **1,564,355
rows kept and 1,959 dropped** — the same two figures the `MachineLearningCSV`
build produced, and the same per-label counts to the row. Two differently
packaged distributions cleaning to an identical row set is strong evidence
that this is the genuine capture rather than a re-derived copy.

`tests/unit/test_ingestion.py::test_replayed_endpoints_match_the_published_topology`
re-runs the topology half of this check against the committed partitions, so a
swapped mirror fails the suite rather than being noticed on a screen.

### Defects handled

Counted per file in `data/datasets/clean/FETCH_REPORT.json`:

| # | Defect | Handling |
|---|---|---|
| 1 | Leading/trailing whitespace on column names | Stripped; count recorded |
| 2 | Header row repeated mid-file | Rows whose label is the literal `"Label"` are dropped and counted |
| 3 | `Infinity` / `NaN` in rate columns | Infinity masked to NaN, then rows with any non-finite feature dropped and counted |
| 4 | Mixed dtypes | Every feature column coerced with `to_numeric`; failures become NaN and fall out with (3) |
| 5 | `Fwd Header Length` duplicated | Values compared first; dropped only when identical, so a real difference would surface |
| 6 | Severe class imbalance | Preserved in the population report; capped per class at sampling time, never resampled away |
| 7 | Label encoding damage | UTF-8 → CP-1252 → Latin-1 read fallback, plus `normalize_label` collapsing every observed separator variant |
| 8 | **GLF-only** — 288,602 wholly blank rows in Thursday-Morning | Detected on the raw column rather than its string cast, dropped, counted as `blank_rows_removed` |
| 9 | **GLF-only** — 12-hour timestamp with no AM/PM | Disambiguated from the published capture window; see below |

**Totals for the five attack-heavy days:** 1,854,916 raw rows → 1,564,355 kept.
288,602 dropped blank, 1,959 dropped as unparseable, 2,843 infinity cells,
3,918 NaN cells.

---

## What is original and what is derived

Original, straight out of the capture, nothing computed:

`Flow ID` · `Source IP` · `Source Port` · `Destination IP` ·
`Destination Port` · `Protocol` · the 77 flow features · `Label` ·
the calendar date and clock time in `Timestamp`

Derived, and each one says how:

| Field | How it is derived | Why it is not an invention |
|---|---|---|
| `captured_at` | `Timestamp` parsed to ISO 8601 | Reformatting, plus the meridiem rule below. No value is created. |
| `NormalizedAlert.timestamp` | Arrival time — the moment the alert entered the feed | See "Which timestamp the UI shows". |
| `row_id` | `<partition>-<sha256 of every identity and feature column>` | Bookkeeping for the split. Carries no information about the flow. |
| `id` (`ALT-XXXXXX`) | `sha256(row_id)[:6]` | Display identifier the frozen frontend keys on. |
| `signature` | `synthesize_signature()` over flow features only | Describes the shape of the flow. **The label is not a parameter of the function** — see "Label leak" below. |
| `severity` | `CLASS_TO_SEVERITY[canonical_class]` | The documented map, applied to the row's true class. Never inflated. |

Nothing else. There is no field whose value was chosen to look plausible.

### The meridiem rule — the one inference in the pipeline

`GeneratedLabelledFlows` writes time as a 12-hour clock with **no AM/PM
marker**: `3:16` is 03:16 or 15:16 and the row does not say which. This is
resolved from published fact, not from a guess:

- UNB captured **08:30–17:00** local on each weekday.
- The observed hour histogram contains 8, 9, 10, 11, 12, 1, 2, 3, 4, 5 and
  **never 6 or 7** — exactly what that window predicts.
- So hours 8–12 are read as morning and 1–7 as afternoon.

The rule is applied uniformly and the two branches are counted per file in
`FETCH_REPORT.json` (`timestamps_read_as_morning` / `_as_afternoon`), so its
effect is auditable. Seconds are absent from the source and are recorded as
zero, not fabricated. The date is read day-first: Wednesday's file says
`5/7/2017`, and CICIDS2017's Wednesday is 5 July 2017 — month-first would make
it a Sunday, on which nothing was captured.

**The timestamp is not a feature.** It is excluded from
`app/ml/features.py::FEATURE_COLUMNS` by allowlist, so this inference cannot
reach the classifier even in principle.

### Which timestamp the UI shows

**`NormalizedAlert.timestamp` is the ARRIVAL time** — the moment the alert
entered the replay feed. The real capture time is kept alongside it on
`captured_at`, and it is real: July 2017, from the row.

Both are true statements about different things, and the split is deliberate.
The frozen frontend renders relative age from `timestamp` and buckets event
velocity off it; a July 2017 date there would render every alert as nine years
old and flatten the velocity chart to zero. "This alert arrived now" is simply
true of a live feed replaying held-out rows. `captured_at` is not serialized —
the frozen contract has no field for it — but it travels on the record, so the
eval and any future drawer field can use it without re-deriving anything.

---

## Partitions

`scripts/build_partitions.py`, seed **20260904**, output in `data/splits/`
with `MANIFEST.json` carrying per-file SHA-256, per-class counts and the full
row-id sets.

### Day selection

Wednesday supplies every DoS variant. Thursday morning supplies the web
attacks. Friday supplies Botnet (morning), PortScan and DDoS (afternoon).
Monday is entirely BENIGN and adds no class coverage; Tuesday (FTP/SSH brute
force) and Thursday afternoon (Infiltration) carry classes this build does not
model, so they would add rows without adding coverage.

### Three-way disjoint split — PLAN D20 / I15

| Partition | Rows | Feeds | Never touches |
|---|---|---|---|
| `train` | 5,400 | LightGBM fitting (Phase 2a) | eval, replay |
| `eval` | 1,800 | the eval harness (Phase 6) | train, replay |
| `replay` | 1,800 | the live demo feed | train, eval |

900 / 300 / 300 rows per class, six classes, perfectly balanced after the
per-class cap. Every row id is partition-stamped (`replay-a1b2c3...`), so a
train row reaching the demo feed is visible in the id itself and not only in a
set comparison. `ReplayEngine` refuses any file whose ids are not `replay-`.

**Row ids are now unique within a partition, and were not before.** The id
hashes every identity and feature column. Under `MachineLearningCSV` that was
features alone, and 5,400 train rows produced only 5,234 distinct ids: two
flows with identical statistics are indistinguishable without their endpoints.
With `Flow ID` in the hash the counts are 5,400 / 1,800 / 1,800 exactly, which
is what an id has to be for a disjointness check to mean anything.
`build_partitions.py` now fails the build if any partition contains a
duplicate id.

### Canonical classes

| Class | Raw spellings | Severity |
|---|---|---|
| `benign` | BENIGN | `low` |
| `dos` | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest | `high` |
| `ddos` | DDoS | `critical` |
| `port_scan` | PortScan | `medium` |
| `botnet` | Bot | `high` |
| `web_attack` | Web Attack – Brute Force / XSS / Sql Injection | `high` |

Severity order is `low < medium < high < critical` (PLAN D27). `unknown` sits
outside the order, satisfies no threshold, and is never a ground-truth label.

**Excluded:** `heartbleed` — CICIDS2017 contains **11 Heartbleed flows in
total**, which cannot yield a meaningful share across three partitions. The
exclusion and its row count are recorded in `MANIFEST.json`, not silently
dropped.

**Six classes, not seven.** PLAN §7.3 estimated seven and has been corrected.
The DoS variants collapse to one class and the three web attacks collapse to
one, because `Web Attack – Sql Injection` has only 21 rows in the entire
capture — too few to score after a 3-way split. The random baseline is
therefore 1/6 ≈ **16.7%**.

The class list and per-class counts are **identical** under
`MachineLearningCSV` and `GeneratedLabelledFlows`. Changing distribution did
not rescue Heartbleed or the web-attack subclasses; the rows simply are not
there.

Consequence for the UI: the frozen vector filter offers `sql_injection`,
`brute_force`, `malware` and `other`, none of which any alert will ever carry,
and does not offer `benign`, `dos`, `botnet` or `web_attack`, which every
alert does. Only `port_scan` and `ddos` overlap. This is a frontend change
(**FE-11**), not a backend one — `FilterStrip.jsx:40-45` hardcodes its options
and reads no endpoint.

---

## Label leak — PLAN I4

The prior codebase built its signature as `f"CICIDS {raw_label} flow ..."` and
then put the signature in the prompt, so **450/450 eval prompts contained the
answer in plain text**.

Here `synthesize_signature()` takes flow features only. The label is **not a
parameter of the function**, so it cannot leak by accident, and a change that
wanted to leak it would have to alter the function's signature — which
`test_synthesize_signature_cannot_receive_a_label` asserts against.

The label travels separately as `NormalizedAlert.ground_truth_class`, which
`alert_to_dict()` never serializes.
`test_no_canonical_class_name_appears_in_any_signature` scans real generated
signatures for every class name and every raw spelling.

---

## Suricata EVE

`app/ingestion/suricata.py` reads real EVE JSON. **These records carry no
ground-truth label** — Suricata reports which rule fired, a static per-rule
prior, not the contextual per-instance verdict the pipeline produces. PLAN I15
(extended): a `suricata_sample` or `live_demo` row must never enter the eval or
training set.

EVE records have no CICIDS flow features, so `features` is left empty, which
forces the PLAN D25 skip: the LightGBM tier cannot score them and the alert
routes straight to the LLM with an explicit `skipped` trace entry.

### The committed sample is real

`data/datasets/suricata_eve_sample.json` — **107 alert records produced by
Suricata 8.0.6**, not hand-written.

| | |
|---|---|
| Engine | Suricata 8.0.6 RELEASE, official `jasonish/suricata` container |
| Rules | ET Open via `suricata-update`, 68,623 rules, 52,670 enabled |
| Input | `smallFlows.pcap` — the public tcpreplay sample capture, 14,261 packets |
| Command | `suricata -r smallFlows.pcap -l out -k none` |
| Output | 107 `alert` events; 40 non-alert events kept so the reader's skip path is exercised against real input |

Rules that fired include `ET CHAT Skype User-Agent detected`, `GPL CHAT MSN
user search` and Suricata's own stream and HTTP anomaly rules. The reader
parses all 107 into `NormalizedAlert`s with `features` empty and
`ground_truth_class` None, which is what forces the PLAN D25 fast-tier skip.

This closes the open item in PLAN §21 and de-risks the live-injection phase
(§4.4a): the Suricata → eve.json → parser path is now proven end to end rather
than assumed.

---

## Live-injection chain — verified end to end (Phase 4a, 2026-09-06)

**The whole chain was run, not asserted.** Suricata against a real pcap → a
live `eve.json` → the standalone forwarder → `POST /ingest/eve` → the graph →
persisted alerts, with the replay loop running throughout.

| Stage | What actually ran |
|---|---|
| Engine | **Suricata 8.0.6 RELEASE**, official `jasonish/suricata` container |
| Rules | ET Open via `suricata-update` — **68,625 rules, 52,672 enabled** |
| Input | `smallFlows.pcap`, the public tcpreplay capture — **14,261 packets, 9,216,531 bytes** |
| Command | `suricata -r smallFlows.pcap -l out -k none -S rules/suricata.rules` |
| Output | **2,075 EVE records: 107 `alert`, plus 641 flow, 577 http, 501 fileinfo, 106 anomaly, 68 dns, 57 tls, 16 snmp, 1 dhcp, 1 stats** |
| Forwarder | `tools/eve_forwarder.py`, batch 50, tailing the live file |
| Server | `LIVE_INGEST_ENABLED=true`, replay running at 12 alerts/min against real providers |

### Result

- **107 / 107 distinct alerts reached the pipeline** and persisted with
  `source = "live_demo"`. The endpoint is idempotent by alert id, so batches
  refused when the live lane was full were re-delivered without duplicating.
- **107 / 107 carry a complete seven-node trace.** No stage silently skipped (I1).
- **107 / 107 have a `classify` entry naming the D25 reason**: *"source
  'live_demo' carries no flow features, so the fast tier was skipped and the LLM
  is the only tier that can classify it (D25)"*. The fast tier answered **zero**
  of them; **groq answered all 107**. That is the demo dynamic, measured.
- **13 distinct real signatures arrived**, including `ET CHAT Skype User-Agent
  detected`, `SURICATA HTTP Response excessive header repetition`,
  `SURICATA TLS invalid record type` and `SURICATA STREAM FIN out of window`.
- **The non-alert majority was counted, not discarded.** The forwarder's own
  output shows the ratio — e.g. `accepted=3 dropped=47` on a 50-record batch —
  and the endpoint's `dropped_breakdown` attributes every dropped record.
- **I19 held in production.** Replay produced 37 alerts *during* live ingestion,
  0 of them `unknown`. Not one replay triage slot was consumed by the live lane:
  the two have separate bounded queues and separate worker tasks.

### Re-verified after the Phase 8 schema correction (A2)

The first run's endpoint already ignored unknown top-level keys; what was wrong
was `openapi.yaml` and `CONTRACT.md`, which claimed unknown fields were
rejected. Both were corrected to describe the code, and the chain was run again
from a clean database to confirm the corrected rule against the same real
output:

| | |
|---|---|
| Real alert records | **107** |
| Distinct top-level keys on them | **22** (the schema names 9) |
| Pass `EveEvent` validation | **107 / 107**, zero rejected |
| Parse to a `live_demo` alert | **107 / 107** |
| Persisted through the graph | **107 / 107**, in a SINGLE forwarder pass of 42 batches |
| Complete seven-node trace | **107 / 107** |
| `classify` entry naming the D25 reason | **107 / 107** |
| Tier that answered | **groq × 107**, LightGBM × 0 |
| Schema rejections | **0** |
| 429s | **0** |
| Forwarder accounting | `accepted=107  dropped=1968` — the 1,968 are the non-alert records, every one counted |

Replay ran throughout and produced 11 alerts in the same window, none `unknown`.

### Two defects this re-run found, both fixed

**1. The forwarder stranded everything after a failed batch.** `_read_new_lines`
advances `position.offset` to EOF as a side effect of reading. Skipping
`position.save()` on a failed delivery only left the ON-DISK offset behind — the
in-memory one had already moved — so the next poll saw `st_size == offset`,
returned nothing, and the forwarder sat in its poll loop reporting nothing
wrong. **One 429 stranded 27 of 107 alerts that way.** Fixed: the loop snapshots
`(inode, offset, carry)` before the read and rolls back to it on failure, which
is safe because the endpoint is idempotent by alert id.
`tests/unit/test_eve_forwarder.py` asserts both that the rollback works and that
the run loop performs it.

**2. The global rate limiter caps the ingest budget, and that is not obvious.**
`RateLimitMiddleware` (120 req/min by default) applies to `/ingest/eve` on top
of `INGEST_REQUESTS_PER_MINUTE`, so the effective ceiling is the LOWER of the
two. A forwarder at `--batch 10` sends 208 requests per pass over a 2,075-record
file and is refused by the global limiter long before the ingest budget. This is
defence in depth working as designed, not a bug — but the operator-facing
consequence is that **batch size, not the ingest budget, is what keeps a
forwarder under the global limit.** At `--batch 50` the same file is 42 requests
and draws zero 429s.

### What the first run surfaced

**The live lane fills, and that is the design working.** Each live alert costs a
full graph pass including a real LLM call (~1–3s), so a forwarder pushing 50 at
a time outruns the pipeline and the 200-slot lane saturates. The endpoint then
returns `202` with `live_lane_full` counted in `dropped_breakdown` — **not a
503, and not a silent drop** — because a full live lane is not a service
failure and replay is untouched. On demo day the fix is operator-side: raise
`--poll` or lower `--batch` (`tools/README.md`).

**Cross-provider fallback fired for real.** Gemini's whole pool went cooling
mid-run and the reason node fell through to Groq, with the trace saying so:
*"answered by the FALLBACK provider groq/openai/gpt-oss-120b because the primary
gemini/gemini-3.6-flash was unavailable (AllKeysCoolingError)"*. Four replay
alerts were marked `degraded` in the same window. Both are the honest behaviour,
recorded rather than hidden.
