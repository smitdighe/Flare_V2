# `tools/` — the EVE forwarder, and things that run somewhere else

Nothing in this directory is imported by the backend, on any code path. It is
not in `app/`, it is not a `scripts.` module, and `make check` does not run it
as part of the application. These are operator tools that live on other
machines.

## `eve_forwarder.py` — the live-injection forwarder (PLAN D23 / §4.4a)

Tails a Suricata `eve.json` on the **target box** and POSTs new records to
Flare's `POST /api/v1/ingest/eve`. Copy this single file to that machine; its
only dependency is `httpx`.

```bash
pip install httpx
export FLARE_INGEST_TOKEN='<the service token from the Flare host .env>'
python eve_forwarder.py \
  --eve /var/log/suricata/eve.json \
  --url http://<flare-host>:8000/api/v1/ingest/eve \
  --verbose
```

| Flag | Default | Notes |
|---|---|---|
| `--eve` | required | Path to the live `eve.json`. |
| `--url` | required | Full URL including `/api/v1/ingest/eve`. |
| `--token-env` | `FLARE_INGEST_TOKEN` | **Names an env var.** The token is never passed in argv — `ps` is readable by every user on a box we are deliberately attacking. |
| `--state` | `<eve.json>.flarepos` | Where the resume offset is kept. Keyed by inode, so a rotation does not seek into the middle of the new file. |
| `--batch` | 50 | Events per POST. The server caps a batch at `INGEST_MAX_EVENTS_PER_BATCH` (200). |
| `--poll` | 1.0s | Sleep when there is nothing new. |
| `--from-start` | off | Ignore the saved offset and read the whole file. Useful once, against a captured `eve.json`; **not** on demo day, where it would replay the rehearsal. |

### What it handles

- **Rotation** — inode change reopens from zero.
- **Truncation in place** — a size smaller than the current offset reopens from zero.
- **Partial lines** — a half-written trailing JSON object is buffered, not counted as malformed.
- **Backoff** — exponential with full jitter, capped at 60s, reset on the first success.
- **Resume** — the offset is written after every successful batch, so a restart does not re-send.

### Server side

The endpoint is **off by default**. On the Flare host:

```bash
LIVE_INGEST_ENABLED=true
INGEST_SERVICE_TOKEN=<32+ chars>
```

With `LIVE_INGEST_ENABLED=false` the route is **not mounted at all** — not
mounted-and-refusing — so there is nothing to reach. With it `true` and no
token, the app **refuses to start**: the one endpoint that accepts unsolicited
external input does not run unauthenticated.

Generate a token the same way as `JWT_SECRET`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### What the response means

```json
{"accepted": 3, "dropped": 997,
 "dropped_breakdown": [
   {"reason": "not_an_alert_record", "count": 997},
   {"reason": "schema_invalid", "count": 0},
   {"reason": "unparseable_alert", "count": 0},
   {"reason": "live_lane_full", "count": 0}],
 "source": "live_demo", "queue_depth": 3}
```

A high `not_an_alert_record` count is **normal** — an `eve.json` is mostly
`flow`, `dns`, `http` and `stats` records. `schema_invalid` or
`unparseable_alert` climbing means a Suricata version emitting something the
endpoint's schema does not expect. `live_lane_full` means the forwarder is
outrunning the pipeline; raise `--poll` or lower `--batch`. Replay is unaffected
by any of these (PLAN I19).

### Sizing `--batch` against BOTH limiters

**`/ingest/eve` is subject to the global limiter as well as its own**, and the
effective ceiling is the lower of the two. The global `RATE_LIMIT_REQUESTS`
defaults to 120/min; `INGEST_REQUESTS_PER_MINUTE` defaults to 60. **Batch size
is what keeps you under the global one**, because it decides how many requests a
file becomes:

| eve.json size | `--batch 10` | `--batch 50` |
|---|---|---|
| 2,075 records | 208 requests | **42 requests** |

At `--batch 10` a 2,075-record file is refused by the global limiter partway
through; at `--batch 50` the same file draws zero 429s. Raise `--batch` before
you raise either limit.

A refused batch is **replayed**, not skipped: the forwarder rolls its file
position back to the last delivered offset and re-reads that window on the next
poll. Re-sending is safe because the endpoint is idempotent by alert id.

### Rehearsal (PLAN §19 step 11, §21 item 9)

Verify the attack→rule mapping **days** before, not on the morning. Default ET
Open rules do not necessarily fire on a toy `nmap` or a low-rate `hydra` run.
For each staged attack, name the rule you expect to catch it and confirm it
appears in `eve.json` before trusting the beat.
