# Capture runbook — generating a dated EVE sample from the attack rehearsal

**Status: not yet executed.** This describes a capture that has not happened. It
exists so the rehearsal produces a usable artifact on the first attempt instead
of a second rehearsal.

## What this is for

`data/datasets/suricata_eve_sample.json` is real Suricata 8.0.6 output over
`smallFlows.pcap`, whose packets were captured 2011-01-25 — the timestamps are
the pcap's own clock and are correct (see `data/PROVENANCE.md`). The sample is
old, not synthetic. Replacing it with something recent requires a recent
capture; there is no honest edit to the existing file that achieves this.

We are **not** downloading a malware capture. We capture our own traffic during
the team's live attack rehearsal, on our own testbed, and run Suricata over
that. Real 2026 timestamps, real ET signature hits, no malware on anyone's
workstation.

---

## Before you start

| Requirement | Why |
|---|---|
| Docker Desktop running | Suricata runs in the `jasonish/suricata` container; there is no host install |
| ~15 min of setup budget | Image pull ~250 MB if not cached, ET Open rules ~50 MB |
| A testbed you are authorised to attack | This is the rehearsal's own scope, not a new authorisation |
| Administrator shell on the capture host | Packet capture requires it on every platform below |

**Capture on the target box — the machine under attack — not the attacker.**
ET rules are written against traffic arriving at a victim, and the forwarder is
documented as running there too (`tools/EVE_FORWARDER.md`).

**A pcap records everything on the wire.** Keep this to an isolated testbed. Do
not capture on a corporate LAN or anywhere carrying real user traffic,
credentials, or session tokens — the resulting `.pcap` and the EVE records
derived from it carry whatever crossed the link, including source and
destination IPs that end up committed to the repo. Review before sharing.

---

## Step 1 — Capture

Pick the path that matches the capture host.

### 1a. Windows, no install (`pktmon`)

`pktmon` ships with Windows. Run as **Administrator**.

```powershell
pktmon filter remove
```

Scope the capture to the target host so you do not record the whole box. Replace
the IP with the testbed target:

```powershell
pktmon filter add RehearsalTarget -i 192.168.56.10
```

Start. `--pkt-size 0` is **not optional** — the default truncates every packet to
128 bytes, and ET content rules match on payload, so a truncated capture
produces almost no alerts and the whole exercise silently fails:

```powershell
pktmon start --capture --pkt-size 0 --file-name C:\rehearsal\cap.etl --file-size 512
```

Run the rehearsal. Then stop:

```powershell
pktmon stop
```

Convert. `etl2pcap` emits **pcapng**, which Suricata reads natively:

```powershell
pktmon etl2pcap C:\rehearsal\cap.etl -o C:\rehearsal\rehearsal.pcapng
```

Clear the filter afterwards so it does not affect later captures:

```powershell
pktmon filter remove
```

### 1b. Windows, with Wireshark (preferred if you can install it)

Neither Wireshark nor Npcap is currently installed on the Flare workstation. If
the capture host has them, `dumpcap` is better than `pktmon`: it writes pcap
directly, needs no conversion step, and has a proper ring buffer.

List interfaces, then capture on the right one:

```powershell
& "C:\Program Files\Wireshark\dumpcap.exe" -D
```

```powershell
& "C:\Program Files\Wireshark\dumpcap.exe" -i 4 -f "host 192.168.56.10" -s 0 -b filesize:262144 -b files:8 -w C:\rehearsal\rehearsal.pcap
```

`-s 0` = full packet (same trap as `--pkt-size 0` above). `-b filesize:262144 -b
files:8` caps the capture at 8 × 256 MB in a ring, so a forgotten capture cannot
fill the disk.

### 1c. Linux attack host (`tcpdump`)

```bash
sudo tcpdump -i eth0 -s 0 -w /tmp/rehearsal.pcap -C 256 -W 8 'host 192.168.56.10'
```

Same three properties: `-s 0` full packets, `-C`/`-W` ring buffer, host filter.

### How long, and how big

Capture **the whole rehearsal window**, start to finish. Do not try to catch
individual attacks — a gap costs another rehearsal.

Sizing, from the documented reference point: `smallFlows.pcap` is 14,261 packets
in 9,216,531 bytes, ≈646 bytes/packet. Scanning and brute-force traffic runs
smaller (many short packets), web-attack traffic larger.

| Rehearsal length | Rough expectation |
|---|---|
| 15 min, light scanning | 10–80 MB |
| 30–60 min, mixed nmap / hydra / sqlmap | 100 MB – 1 GB |

The ring buffers above cap the worst case at ~2 GB. Anything in this range is
fine for Suricata; it reads offline at well above real time.

---

## Step 2 — Run Suricata

Copy the capture to the Flare workstation, e.g. `C:\rehearsal\`.

Pull the rules **once** and keep them, so the run is reproducible. The committed
sample's two documented runs recorded 68,623/52,670 and 68,625/52,672 rules —
they differ because ET Open gains rules between pulls. Pinning the ruleset is
what stops a third run from being a third number:

```powershell
docker run --rm -v C:\rehearsal:/work jasonish/suricata:latest suricata-update --no-test -D /work/suricata-state
```

Record what that prints — the rule count and enabled count go in the provenance
note. `/work/suricata-state/rules/suricata.rules` is now on the host and is the
artifact to pin.

Run the engine. This mirrors the documented original command, with `-S` to force
the pinned ruleset (as the Phase 4a run did):

```powershell
docker run --rm -v C:\rehearsal:/work -w /work jasonish/suricata:latest suricata -r /work/rehearsal.pcapng -l /work/out -k none -S /work/suricata-state/rules/suricata.rules
```

`-k none` disables checksum validation — required, because offline captures
routinely carry bad checksums from NIC offload and Suricata would otherwise drop
those packets before any rule sees them.

Check what you got before going further:

```powershell
docker run --rm -v C:\rehearsal:/work jasonish/suricata:latest suricata --build-info | Select-String -Pattern "^This is Suricata"
```

```powershell
Get-Content C:\rehearsal\out\eve.json | ConvertFrom-Json | Group-Object event_type | Sort-Object Count -Descending | Format-Table Count, Name
```

**If the `alert` count is zero, stop.** That is the documented failure mode: no
ruleset loaded, or a truncated capture. Do not proceed — an empty sample is
worse than the 2011 one. Check `C:\rehearsal\out\suricata.log` for the rule load
count and re-read Step 1's packet-size warning. Check this first, before
anything else: an empty alert set passes almost every downstream check, because
a check over zero records is vacuously true.

Then check the engine did not quietly drop traffic:

```powershell
Select-String -Path C:\rehearsal\out\suricata.log -Pattern "rules successfully loaded|error|warning" | Select-Object -First 20
```

```powershell
Get-Content C:\rehearsal\out\stats.log | Select-String -Pattern "decoder.pkts|capture.kernel_drops|flow.memcap|tcp.reassembly_memuse" | Select-Object -Last 12
```

Two things to confirm: the rule load count is in the tens of thousands (not 0,
not a handful), and the decoded packet count is close to the pcap's own packet
count. A significant gap means Suricata dropped or failed to decode a share of
the capture, and the alert set is not what the traffic would have produced —
report it rather than shipping the sample.

---

## Step 3 — Build the sample file

Save as `C:\rehearsal\build_sample.py`:

```python
"""Filter a rehearsal eve.json into the committed sample's exact on-disk format."""

import json
import random
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else r"C:\rehearsal\out\eve.json")
DST = Path(sys.argv[2] if len(sys.argv) > 2 else r"C:\rehearsal\suricata_eve_sample.json")

MIN_ALERTS = 30      # below this, stop and report rather than ship a thin sample
OTHER_TARGET = 40    # non-alert records, kept deliberately — see below

records = []
for line in SRC.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line:
        records.append(json.loads(line))

alert_idx = [i for i, r in enumerate(records) if r.get("event_type") == "alert"]
other_idx = [i for i, r in enumerate(records) if r.get("event_type") != "alert"]
print(f"source: {len(alert_idx)} alert, {len(other_idx)} non-alert")

if not alert_idx:
    raise SystemExit(
        "ZERO alert records. Almost always means no ruleset loaded. Do NOT write "
        "a sample from this run — check out/suricata.log for the rule load count."
    )
if len(alert_idx) < MIN_ALERTS:
    raise SystemExit(
        f"only {len(alert_idx)} alerts, under the {MIN_ALERTS} floor. Too thin for "
        "a reference sample. Report the count and get a decision before proceeding."
    )

# EVERY alert is kept. The committed sample happens to hold 107; that is what
# smallFlows.pcap produced, not a target. Downsampling a new capture to land on
# 107 would make the count a decoration rather than a measurement, so the alert
# count here is whatever the rehearsal actually generated. Report the real number.
keep_idx = set(alert_idx)

# The non-alert records are a fixed-size sample only because their job is to
# exercise the reader's skip path, not to be representative — an eve.json is
# overwhelmingly non-alert and keeping all of them would bury the alerts.
rng = random.Random(20260907)  # seeded: reproducible from the same eve.json
keep_idx |= set(rng.sample(other_idx, min(OTHER_TARGET, len(other_idx))))

# Re-read in index order, which preserves Suricata's own emission order. Sorting
# on `timestamp` instead looks equivalent and is not: eve.json interleaves alert
# and protocol records for the same flow, so a timestamp sort permutes the file.
# Verified — this ordering round-trips the committed sample byte-for-byte, a
# timestamp sort does not.
keep = [records[i] for i in sorted(keep_idx)]

# Format, matched to the committed file exactly:
#   line-delimited JSON, one object per line
#   compact separators — json.dumps(r, separators=(",", ":"))
#   UTF-8, no BOM
#   trailing newline
# newline="\n" is deliberate. The repo stores this path LF (.gitattributes
# `* text=auto`; data/datasets is NOT in the -text pinned list), and Git for
# Windows checks it out CRLF, which is why the current working-tree file reads
# as CRLF. Writing LF here reproduces the committed representation. No checksum
# covers this file, so nothing breaks either way — but match it anyway.
with DST.open("w", encoding="utf-8", newline="\n") as fh:
    for record in keep:
        fh.write(json.dumps(record, separators=(",", ":")))
        fh.write("\n")

print(f"wrote {len(keep)} records to {DST}")
```

```powershell
C:\Users\Smit\Desktop\Flare_V2\backend\.venv\Scripts\python.exe C:\rehearsal\build_sample.py
```

**On keeping 40 non-alert records.** The committed file is 147 records: 107
`alert` plus 40 `http`/`fileinfo`/`anomaly`/`tls`. That is deliberate and
documented — the non-alert records exercise `parse_eve_record`'s skip path
against real input, which a pure-alert file cannot do. Filter to alerts only and
you lose that property. Keep the mix unless you have a reason not to.

**Do not sample down to 107.** The committed file holds 107 alerts because that
is what `smallFlows.pcap` produced. It is a measurement, not a target. Whatever
the rehearsal yields — 40 or 4,000 — is the number that ships, and the number
that goes in the provenance note. Never pad, duplicate, or synthesise records to
reach a count; never trim to flatter one.

The script stops below **30 alerts**. That is a judgement call, not a law: a
sample that thin is not useful as a reference and probably indicates the
rehearsal did not trip much. Report the count and get a decision rather than
shipping it quietly.

---

## Step 4 — Verify before swapping

Save as `backend/verify_sample.py` (delete it afterwards; it is a check, not a
deliverable):

```python
"""Run the REAL parser over a candidate sample. No reimplementation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.api.routes.ingest import EveEvent  # noqa: E402
from app.ingestion.suricata import read_eve_file  # noqa: E402

path = Path(sys.argv[1])
alerts = list(read_eve_file(path))

# The ingest endpoint validates through EveEvent before the parser ever sees a
# record, so a sample the parser accepts can still be one the live path would
# reject. Both layers, or the check is incomplete.
import json as _json  # noqa: E402

pydantic_failures = []
for _line in path.read_text(encoding="utf-8").splitlines():
    if not _line.strip():
        continue
    _record = _json.loads(_line)
    if _record.get("event_type") != "alert":
        continue
    try:
        EveEvent.model_validate(_record)
    except Exception as exc:  # noqa: BLE001
        pydantic_failures.append((_record.get("timestamp"), str(exc)[:120]))

raw = path.read_bytes()
text = raw.decode("utf-8")
# splitlines(), not split("\n"): Git checks this path out CRLF on Windows, so a
# naive split leaves a trailing \r on every line and the compact-separator check
# below fails against a file that is in fact correct. Verified both ways.
lines = [line for line in text.splitlines() if line.strip()]

checks = {
    "parsed at least one alert": len(alerts) > 0,
    "every source is suricata_sample": all(a.source == "suricata_sample" for a in alerts),
    "every features dict is empty (D25)": all(a.features == {} for a in alerts),
    "every ground_truth_class is None (I15)": all(a.ground_truth_class is None for a in alerts),
    "no row_id": all(a.row_id is None for a in alerts),
    "every id is ALT-XXXXXX": all(a.id.startswith("ALT-") and len(a.id) == 10 for a in alerts),
    "every alert passes EveEvent validation (ingest.py)": not pydantic_failures,
    "no BOM": not raw.startswith(b"\xef\xbb\xbf"),
    "trailing newline": raw.endswith(b"\n"),
    "compact separators on every line": all(
        __import__("json").dumps(__import__("json").loads(line), separators=(",", ":")) == line
        for line in lines
    ),
}

for name, ok in checks.items():
    print(f"{'PASS' if ok else 'FAIL'}  {name}")

for ts, err in pydantic_failures[:5]:
    print(f"      EveEvent reject @ {ts}: {err}")

print(f"\nalerts parsed: {len(alerts)}")
print(f"timestamp range: {min(a.timestamp for a in alerts).isoformat()}"
      f" .. {max(a.timestamp for a in alerts).isoformat()}")
print(f"distinct signatures: {len({a.signature for a in alerts})}")

sys.exit(0 if all(checks.values()) else 1)
```

```powershell
cd C:\Users\Smit\Desktop\Flare_V2\backend; .\.venv\Scripts\python.exe verify_sample.py C:\rehearsal\suricata_eve_sample.json
```

Every line must read `PASS`, and the timestamp range must be the rehearsal date.

Both scripts above were dry-run against the **current** committed sample on
2026-09-07: the verifier reports 10/10 `PASS`, exit 0, 107 alerts, 13 distinct
signatures; and feeding the committed file through `build_sample.py` reproduces
it byte-for-byte (LF-normalised). The whole chain was then run cold against
`smallFlows.pcap` with the pinned ruleset — Suricata → `eve.json` → build →
verify — also 10/10 `PASS`. So a `FAIL` here is a fact about your new capture,
not a bug in the check.

### Suricata output is NOT byte-reproducible — do not claim that it is

Two runs of the **same pcap** with the **same pinned ruleset** were compared on
2026-09-07. Both produced 107 alerts and an **identical signature histogram**
across all 13 signatures. But one record differed between them: signature 2012648
(`ET FILE_SHARING Dropbox Client Broadcasting`) was attributed to a packet
2.5 ms apart — `18:55:50.743462` in one run, `18:55:50.745970` in the other.

The engine runs 14 worker threads, and for a rule that matches several
near-identical broadcast packets it is a race which packet is credited. The
committed sample matches one of those two outcomes.

So the reproducible claim is **alert count and signature histogram**, not bytes
and not per-record timestamps. Phrase the provenance note accordingly — and note
that `alert_id_from` seeds on the timestamp, so that record's `ALT-` id varies
between runs too. Nothing keys on it, but do not present the id set as stable.

Then confirm the D25 routing property holds on the new records:

```powershell
cd C:\Users\Smit\Desktop\Flare_V2\backend; .\.venv\Scripts\python.exe -m pytest tests/integration/test_ingest_live.py tests/unit/test_eve_forwarder.py tests/invariants/test_invariants.py -q
```

Baseline for comparison, measured 2026-09-07 against the current file: **21
passed** (ingest integration) and **41 passed** (forwarder + invariants). Nothing
in the suite loads the sample file, so these should be unchanged — a difference
means something other than the sample moved.

**If any check fails, do not loosen the check.** Report which one and why.

---

## Step 5 — Swap and document

1. Replace `backend/data/datasets/suricata_eve_sample.json`.
2. Update `backend/data/PROVENANCE.md` — the `### The committed sample is real`
   table (engine, rules, input, command, output, on-disk) and the
   `### The sample's timestamps are from 2011…` section, which stops being true.

   **Keep the superseded entry.** Record the `smallFlows.pcap` sample beside the
   new one — its 107 alert / 40 non-alert counts, its 2011-01-25 range, the
   68,623 / 52,670 ruleset, and the reason it was replaced. This project's
   convention is that superseded values ship with their evidence rather than
   being deleted; a provenance file that quietly forgets what it used to say is
   worth less than one that shows the change. Do not delete the old section —
   demote it under a heading that marks it as superseded and dated.
3. Update `README.md` — the `datasets/` tree comment (~line 976) and the 2011
   paragraph in **What was actually verified**.
4. Record, from the actual run: rehearsal date, capture host and interface,
   pcap packet count and byte size, Suricata version from `--build-info`, the
   `suricata-update` rule and enabled counts, resulting alert and non-alert
   counts, and the timestamp range.

The reason the current docs are trustworthy is that they record what was run
rather than what was intended. Keep that.

**Still true after the swap, and worth leaving in the docs:** nothing in the
codebase loads this file. `read_eve_file` has no caller; the live path is fed by
`tools/eve_forwarder.py` posting to `POST /ingest/eve`. The sample is a reference
artifact and a fixture, not a demo input. A fresher one is more credible
evidence, not new functionality.
