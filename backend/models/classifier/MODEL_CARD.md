# Flare fast-tier classifier — model card

PLAN E16. A trained model with no card is an unverifiable claim.

| | |
|---|---|
| Model version | `1.0.0` |
| Task | Two heads: attack type (6-class) and severity (4-class, ordinal) |
| Algorithm | LightGBM gradient-boosted trees |
| Library | lightgbm 4.7.0, numpy 2.5.2, scikit-learn 1.9.0, Python 3.13.7 |
| Seed | `20260904`, with `deterministic=True` and `force_row_wise=True` |
| Trained by | `scripts/train_classifier.py` |
| Artifacts | `attack_type.booster.txt`, `severity_gt_{low,medium,high}.booster.txt`, `feature_schema.json`, `metrics.json` |

Reproducible: rerunning the script on the committed partitions produces the
same boosters. Calibrators are serialised as isotonic knot arrays inside
`metrics.json`, not pickled — a pickle is version-fragile and the point of
committing a model is that a cold clone works.

---

## Leak guard — ADJUDICATED and PASSING

**Held-out attack-type accuracy is 0.9944. The guard passes.** It did not always: the
original guard was a bare absolute ceiling at 0.98, it fired, and the audit it demanded is
what this section records. PLAN §7.3a carries the full adjudication; the summary is below.

**One real defect, and the guard deserves the credit for it.** The first training run
scored **0.9983**. Investigation showed 62 of 1,800 eval rows (3.44%) had a 77-feature
vector appearing *verbatim* in train — 49 of them `dos` (16.3% of that class), because DoS
Hulk emits enormous numbers of stereotyped flows. Their row ids differed (ids hash Flow ID
and the endpoints, which do differ), so id-level disjointness passed while the classifier
was in effect being tested on rows it had trained on. `build_partitions.py` now
deduplicates on the feature vector across the whole population **before** splitting — this
is part of the partition contract now, not a cleanup step (PLAN §7.3b, I15 amended).
193,859 duplicate vectors were dropped; exact eval→train overlap is **0**. The score fell
from 0.9983 to 0.9944.

**The remainder is not a leak, and the 0.98 ceiling was mis-set.** Three checks,
recomputed on every training run and stored in `metrics.json` under
`separability_diagnostics`:

| Check | Result | What it rules out |
|---|---|---|
| Exact eval→train feature duplicates | **0 / 1800** | Memorisation of identical rows |
| **1-NN accuracy, no training at all** | **0.9844** | Model cleverness. 1-NN is given no label at inference and cannot memorise; it only measures whether an eval row lands beside same-class train rows. At 0.9844 the geometry alone nearly reaches the booster's 0.9944 — the classes are simply far apart in CICFlowMeter feature space |
| Accuracy without `Destination Port` | **0.9917** | The one partly label-correlated feature carrying the result. It contributes 0.27 points |
| Partition id prefixes | all `train-` / `eval-`, 0 id overlap | Wrong-partition training |
| Identifier columns in the allowlist | none | Endpoint or timestamp leak |

The best single feature alone (`Average Packet Size`) reaches 0.8783, so no individual
column is a label proxy; many are jointly strong.

### The guard that replaced it

The 0.98 ceiling was a **proxy** for "the model knows more than it was told". It sat
*below* the 0.9844 no-training baseline for this configuration, so no honest model could
have stayed under it. Measuring the thing the proxy stood in for is strictly better:

| Guard | Test | Measured |
|---|---|---|
| **Relative** (primary) | trip if `accuracy − 1nn_baseline > 0.05` while `accuracy > 0.98` | margin **0.0100** — passes |
| **Exact overlap** (unconditional, any accuracy) | trip if any eval feature vector appears in train | **0** — passes |
| **Absolute** (backstop) | trip above **0.995** | 0.9944 — passes |
| Degenerate | trip at exactly 1.000 | 0.9944 — passes |
| Perfect diagonal | trip at 0 off-diagonal | 10 errors — passes |

The superseded 0.98 is retained in `metrics.json` under
`leak_guard.superseded_thresholds` with its reason, so the revision is auditable rather
than a threshold quietly moved to make a number pass. **Nothing was tuned to change the
score.** The score is byte-identical either side of the guard change; only the question
asked of it changed.

**The 1-NN baseline is reported as a first-class baseline**, beside random and majority,
at `attack_type_head.held_out.baselines.nearest_neighbour_1nn`. Random says what a coin
does and majority says what the class prior does; neither says what the feature space
does, and on this problem that is the number that explains the score.

---

## Training data

`data/splits/train.csv` — 5,400 rows, **the training partition only**.
`load_partition()` refuses any row whose id is not `train-` prefixed, the same
structural-guard style as `synthesize_signature` and `ReplayEngine`.

| Class | Train rows | Eval rows |
|---|---|---|
| `benign` | 900 | 300 |
| `botnet` | 900 | 300 |
| `ddos` | 900 | 300 |
| `dos` | 900 | 300 |
| `port_scan` | 900 | 300 |
| `web_attack` | 900 | 300 |

Source: CICIDS2017 `GeneratedLabelledFlows`, five attack-heavy days. Six
classes — `heartbleed` (11 flows in the entire capture) is excluded, and the
DoS and Web Attack variants collapse. See `data/README.md`.

**Partition contract — deduplication comes before splitting.** The population is
deduplicated on the 77-feature vector *before* the three-way split, not only on
the row id (PLAN §7.3b, I15 as amended). Ids hash Flow ID and the endpoints, so
two flows with byte-identical statistics get different ids and would otherwise
land in different partitions while being the same row to a model that sees
neither. 193,859 duplicate vectors were dropped. `train_classifier.py`
re-verifies zero exact eval→train overlap on every run rather than trusting the
build.

**Class weighting — attack-type head: none.** `build_partitions.py` caps every
class at the same count, so the training partition is exactly balanced at 900
rows per class. Reweighting a balanced sample only adds variance.

**Class weighting — severity head: `balanced`, per cutoff.** The class→severity
map collapses `dos`, `botnet` and `web_attack` into `high`, so severity is
900/900/2700/900 and every cumulative cutoff is imbalanced even though the
attack-type partition is not.

---

## Features

**77 numeric flow features**, selected by an explicit **allowlist** in
`app/ml/features.py` — `FEATURE_COLUMNS`. Never a denylist: an allowlist fails
closed, so a new identifier column appearing upstream is ignored rather than
silently admitted.

The serving path imports **the same module**, so train/serve skew is designed
out rather than tested for. `schema_fingerprint()` digests the column list *in
order* — the booster indexes by position, so a reordering would change what
every tree splits on while leaving the column set identical.

### Features deliberately excluded, by name

| Column | Why |
|---|---|
| `Source IP` | CICIDS2017's topology is fixed. `172.16.0.1` runs DoS, DDoS and PortScan; `205.174.165.73` is the botnet C2. A source-IP column is close to a direct copy of the label |
| `Destination IP` | Same. Attacks converge on `192.168.10.50` |
| `Source Port` | Ephemeral. A session identifier, not a flow property |
| `Flow ID` | Contains both endpoints and both ports as a string |
| `Timestamp` | Attacks were run in scheduled blocks, so capture time is close to a label. Also the one field carrying an inference (the 12-hour meridiem rule) — excluding it keeps that inference away from the model entirely |
| `Label`, `canonical_class` | The answer |
| `row_id`, `partition`, `source_file` | Partition bookkeeping; `row_id` is prefixed with its partition |

This mattered *more* after the GeneratedLabelledFlows migration, not less: the
endpoints are now real, so admitting them would have produced a near-perfect
score that meant nothing.

### Retained with a caveat

**`Destination Port` is the highest-gain feature at 14.4% and is partly
label-correlated by construction** — port 80 dominates the web attacks and DoS,
8080 the botnet C2 channel, and PortScan sprays across the range. It is a
genuine property of a flow and a real analyst would use it, so it stays; it is
flagged rather than hidden. Removing it costs 0.27 accuracy points (0.9944 →
0.9917), so it is not carrying the result.

### Top features by gain

| Gain | Feature |
|---|---|
| 14.39% | `Destination Port` |
| 13.87% | `Init_Win_bytes_backward` |
| 8.42% | `Bwd Packets/s` |
| 6.42% | `Fwd Packet Length Std` |
| 6.05% | `PSH Flag Count` |
| 5.48% | `Total Length of Bwd Packets` |
| 5.02% | `act_data_pkt_fwd` |
| 4.95% | `Bwd Packet Length Min` |
| 4.13% | `Total Backward Packets` |
| 4.08% | `Flow Duration` |

Full list in `metrics.json`.

---

## Hyperparameters and selection

Selected by **5-fold stratified cross-validation on the training partition
only**, scored by macro-F1. The eval partition was read once, at the end.

| `num_leaves` | `learning_rate` | `n_estimators` | `min_child_samples` | CV macro-F1 |
|---|---|---|---|---|
| **15** | **0.10** | **200** | **20** | **0.9957 ± 0.0016** ← selected |
| 31 | 0.05 | 300 | 20 | 0.9952 ± 0.0016 |
| 31 | 0.10 | 200 | 40 | 0.9954 ± 0.0015 |
| 63 | 0.05 | 300 | 10 | 0.9954 ± 0.0017 |

The grid is deliberately small. A large sweep on 5,400 rows overfits the CV
estimate and invites tuning toward a number. **CV spread is ±0.0016** — the
four candidates are within noise of each other, so the choice barely matters.

---

## Calibration

The router thresholds on the emitted probability, so an uncalibrated score used
as a confidence gate is a fake control.

- Booster fitted on a seeded stratified **80%** of the training partition
  (4,320 rows); **isotonic** calibrators fitted on the held-out **20%**
  (1,080 rows) the booster never saw.
- Attack type: one-vs-rest isotonic per class, renormalised at apply time.
- Severity: isotonic per cumulative cutoff.

| | ECE (10 bins) |
|---|---|
| Raw booster output | 0.0047 |
| After isotonic | 0.0053 |

### Escalation threshold — PLAN §22 item 6, set empirically here

PLAN required this to be measured on Phase 2a's data rather than guessed in
Phase 3. Measured on the eval partition, recomputed every run into
`metrics.json` under `attack_type_head.router_threshold`:

| Threshold | Escalated | Accuracy on escalated | Accuracy on kept |
|---|---|---|---|
| 0.99 | 5 / 1800 (0.28%) | 0.600 | 0.9955 |
| 0.90 | 4 / 1800 (0.22%) | 0.500 | 0.9955 |
| 0.80 | 3 / 1800 (0.17%) | 0.333 | 0.9955 |
| 0.50 | 1 / 1800 (0.06%) | 0.000 | 0.9950 |

**Recommended: 0.99.** The gate genuinely discriminates — the handful of rows
below it are where the errors concentrate (40% wrong, against 0.45% above it) —
which is exactly what E17 asks of it.

**But it fires on almost nothing, and that has a consequence for the demo.**
Confidence distribution: min 0.353, median 1.000, mean 0.999, and **99.7% of
eval rows sit at exactly 1.0**. Isotonic on a well-separated problem pushes
confident predictions to the ceiling. So on replay data the LLM tier will be
approached roughly three times in a thousand alerts. Phase 3 should not assume
escalation will be visible on screen, and the as-shipped system number (E15)
will therefore land within noise of the LightGBM-alone number rather than above
it. Better to know that now than to discover it in front of an audience.

**Isotonic did not improve ECE here, and that is reported rather than hidden.**
Raw LightGBM multiclass output was already well calibrated on this data, and
isotonic on 1,080 rows adds a little fitting noise. The calibration path stays
because the guarantee it provides is structural — the probability is a fitted
mapping to observed frequency, not an unexamined softmax — and because ECE on
an easy, balanced problem is a weak discriminator. If the eval set were harder
or imbalanced, raw scores would not stay this close.

---

## Held-out metrics — eval partition, 1,800 rows, never seen in training

### Attack type (6 classes)

**Accuracy 0.9944 · macro-F1 0.9944** · random baseline 0.1667 · majority 0.1667 · **no-training 1-NN 0.9844**

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| `benign` | 0.9900 | 0.9900 | 0.9900 | 300 |
| `botnet` | 0.9933 | 0.9933 | 0.9933 | 300 |
| `ddos` | 0.9967 | 1.0000 | 0.9983 | 300 |
| `dos` | 0.9966 | 0.9900 | 0.9933 | 300 |
| `port_scan` | 1.0000 | 0.9933 | 0.9967 | 300 |
| `web_attack` | 0.9901 | 1.0000 | 0.9950 | 300 |

Confusion matrix — rows are true, columns predicted:

| | benign | botnet | ddos | dos | port_scan | web_attack |
|---|---|---|---|---|---|---|
| **benign** | 297 | 1 | 1 | 0 | 0 | 1 |
| **botnet** | 2 | 298 | 0 | 0 | 0 | 0 |
| **ddos** | 0 | 0 | 300 | 0 | 0 | 0 |
| **dos** | 1 | 0 | 0 | 297 | 0 | 2 |
| **port_scan** | 0 | 1 | 0 | 1 | 298 | 0 |
| **web_attack** | 0 | 0 | 0 | 0 | 0 | 300 |

10 errors in 1,800 — not a perfect diagonal, and 1.00 point above what 1-NN
reaches on the same features with no training at all.

### Binary detection (attack vs benign)

**Accuracy 0.9967 · precision 0.9980 · recall 0.9980 · F1 0.9980** ·
random 0.5 · majority 0.8333

### Severity (4 classes, ordinal)

**Accuracy 0.9933 · macro-F1 0.9928** · random 0.25 · majority 0.5

| | low | medium | high | critical |
|---|---|---|---|---|
| **low** | 296 | 2 | 2 | 0 |
| **medium** | 0 | 299 | 1 | 0 |
| **high** | 6 | 1 | 893 | 0 |
| **critical** | 0 | 0 | 0 | 300 |

**This number is not independent evidence.** In this dataset severity is a
deterministic function of attack type (`CLASS_TO_SEVERITY`), not a separate
human judgement, so the severity head solves a strictly easier problem —
confusing `dos`, `botnet` and `web_attack` costs nothing because all three are
`high`. It is reported because PLAN §7.3 asks for it, and it is trained
separately as specified, but it confirms nothing the attack-type number does
not already say.

Modelled as an **ordinal** problem via the Frank & Hall decomposition: three
binary models for P(severity > low / medium / high), differenced back into
class probabilities. Multiclass would treat low-vs-critical and high-vs-critical
as equally wrong; severity has a total order (PLAN D27) and the model should
know it. Negative differences (isotonic is monotone per cutoff but nothing
forces monotonicity across cutoffs) are clamped and renormalised.

---

## Known failure modes

1. **Distribution shift is unhandled.** Trained on CICIDS2017 flows from a
   single 2017 test-bed with one attacker configuration. Nothing here
   generalises to another network without retraining, and the score above says
   nothing about how it would do.
2. **`Destination Port` will mislead on a non-standard port.** A web attack on
   8443 or a C2 on 443 has no equivalent in training.
3. **No EVE or live-demo alert can be scored.** Those carry a signature and a
   5-tuple, not the 77 numeric flow columns. They are skipped explicitly with a
   trace entry (PLAN D25), never zero-filled — a zero vector scored as a real
   prediction would be a fabricated verdict.
4. **A malformed feature row yields `unknown`** and stays in the denominator
   (PLAN I13). It is never a silent default and never a fallthrough to an LLM.
5. **Six classes only.** Anything else in the world — Heartbleed, Infiltration,
   FTP/SSH brute force — is forced into one of six buckets with unknown
   behaviour. The model has no "none of the above".
6. **Balanced sampling flatters the benign class.** Real traffic is ~65%
   BENIGN; the eval partition is 16.7%. Precision on `benign` would be
   materially different under the natural prior.
7. **The severity head inherits every attack-type error** by construction, plus
   its own — six `high` rows were called `low`, which in production means a real
   attack presented as low severity.
