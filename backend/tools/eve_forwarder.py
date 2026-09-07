#!/usr/bin/env python3
"""Tail a Suricata eve.json and POST new alerts to Flare. PLAN D23 / §4.4a.

**THIS SCRIPT RUNS ON THE TARGET BOX, NOT INSIDE FLARE.** It is deliberately
standalone: it imports nothing from `app/`, it is not on any import path the
server uses, and nothing in the backend calls it. Copy this one file to the
machine running Suricata and run it there. Its only dependency is `httpx`,
which is already in the backend's stack — but the script is written so that
`pip install httpx` on a bare box is the whole setup.

    python eve_forwarder.py \
        --eve /var/log/suricata/eve.json \
        --url http://192.168.4.10:8000/api/v1/ingest/eve \
        --token-env FLARE_INGEST_TOKEN

WHAT IT HANDLES, and why each one is not optional on a live box:

  * **File rotation.** Suricata rotates eve.json under load and on SIGHUP. A
    naive tail keeps reading a deleted inode and goes silent for the rest of
    the demo with no error. This stats the path every poll and compares the
    inode (st_ino) and size; a changed inode means a new file, and a size
    SMALLER than the current offset means truncation-in-place. Either one
    reopens from zero.
  * **Resume from the last position.** The offset is persisted to a small
    state file beside the log, keyed by inode, so a restarted forwarder does
    not replay the whole file — which on demo day would be a flood of alerts
    from the rehearsal.
  * **Backoff on failure.** Exponential with a cap and full jitter. Flare being
    down, restarting, or rate-limiting must not turn into a tight retry loop
    that fills the target box's own logs.
  * **Partial lines.** A tail on a file being appended to routinely reads half a
    JSON object. Incomplete trailing content is kept in a buffer and not
    counted as malformed; the offset only advances past complete lines.

WHAT IT DELIBERATELY DOES NOT DO:

  * It does not filter to `event_type == "alert"`. The server counts non-alert
    records and reports them in `dropped_breakdown`, and the operator wants
    that ratio visible rather than hidden by the client.
  * It does not retry individual events. The endpoint is idempotent by alert id
    (`upsert_alert`), so re-POSTing a whole batch after a failure is safe and
    is simpler than tracking per-event state.
  * It does not hold the token on the command line. `--token-env` names an
    environment variable; a token in argv is visible in `ps` to every user on
    the box, and this box is the one being attacked.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sys
import time
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:  # pragma: no cover - operator-facing message
    sys.exit("eve_forwarder needs httpx:  pip install httpx")

DEFAULT_BATCH = 50
DEFAULT_POLL_SECONDS = 1.0
DEFAULT_TIMEOUT_SECONDS = 10.0
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 60.0
SCHEME = "ServiceToken"

_running = True


def _stop(_signum: int, _frame: Any) -> None:
    global _running
    _running = False


class Position:
    """Where we are in the current file, persisted across restarts.

    Keyed by inode rather than by path: after a rotation the path names a
    different file, and a path-keyed offset would seek into the middle of the
    new one.
    """

    def __init__(self, state_path: Path) -> None:
        self.path = state_path
        self.inode: int | None = None
        self.offset = 0
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        inode = raw.get("inode")
        offset = raw.get("offset")
        if isinstance(inode, int) and isinstance(offset, int) and offset >= 0:
            self.inode = inode
            self.offset = offset

    def save(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            tmp.write_text(
                json.dumps({"inode": self.inode, "offset": self.offset}),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
        except OSError as exc:
            print(f"[warn] could not persist position: {exc}", file=sys.stderr)


def _read_new_lines(eve: Path, position: Position, carry: str) -> tuple[list[str], str]:
    """Return complete lines appended since `position`, plus any partial tail.

    Rotation and truncation are BOTH detected here, and they are different
    events: a new inode is a rotation, and an inode whose size went backwards
    was truncated in place (`> eve.json`, or a log manager configured to copy
    and truncate). Both reset the offset to zero; neither is an error.
    """
    try:
        stat = eve.stat()
    except FileNotFoundError:
        # Rotation window: the old file is gone and the new one is not created
        # yet. Not an error, and not worth a backoff — just nothing this poll.
        return [], carry

    if position.inode is None:
        position.inode = stat.st_ino
    elif stat.st_ino != position.inode:
        print(f"[info] eve.json rotated (inode {position.inode} -> {stat.st_ino})")
        position.inode = stat.st_ino
        position.offset = 0
        carry = ""
    elif stat.st_size < position.offset:
        print(f"[info] eve.json truncated at {stat.st_size}; rereading from 0")
        position.offset = 0
        carry = ""

    if stat.st_size == position.offset:
        return [], carry

    with eve.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(position.offset)
        chunk = handle.read()
        position.offset = handle.tell()

    buffer = carry + chunk
    if buffer.endswith("\n"):
        lines, carry = buffer.splitlines(), ""
    else:
        # The last line is still being written. Hold it and do not count it as
        # malformed — a tail on a live file hits this constantly.
        parts = buffer.split("\n")
        lines, carry = parts[:-1], parts[-1]

    return [line for line in lines if line.strip()], carry


def _post(
    client: httpx.Client, url: str, token: str, events: list[dict[str, Any]]
) -> dict[str, Any] | None:
    response = client.post(
        url,
        json={"events": events},
        headers={"Authorization": f"{SCHEME} {token}"},
    )
    if response.status_code == 202:
        try:
            body = response.json()
        except ValueError:
            return {}
        return body.get("data", body) if isinstance(body, dict) else {}

    # 4xx that is not 429 will not fix itself by retrying: a bad token, a
    # payload the server refuses. Say so loudly and keep going rather than
    # exiting, because the operator may be mid-fix and a dead forwarder is
    # harder to notice than a noisy one.
    print(
        f"[error] ingest returned {response.status_code}: {response.text[:200]}",
        file=sys.stderr,
    )
    return None


def run(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    if not token:
        return _fail(f"{args.token_env} is not set; refusing to run without a token")

    eve = Path(args.eve)
    state = Path(args.state) if args.state else eve.with_suffix(eve.suffix + ".flarepos")
    position = Position(state)

    if args.from_start:
        position.offset = 0
        position.inode = None

    print(f"[info] tailing {eve} -> {args.url} (batch {args.batch})")
    print(f"[info] position state: {state} (offset {position.offset})")

    carry = ""
    failures = 0
    sent = 0

    with httpx.Client(timeout=args.timeout) as client:
        while _running:
            # SNAPSHOT BEFORE THE READ, and roll back to it on failure.
            #
            # `_read_new_lines` advances `position.offset` to EOF as a side
            # effect of reading. Skipping `position.save()` on a failed pass
            # only leaves the ON-DISK offset behind — the IN-MEMORY one has
            # already moved, so the next poll sees `st_size == offset`, returns
            # nothing, and every event after the failing batch is skipped until
            # the process restarts.
            #
            # This is not hypothetical: a single 429 from the endpoint's own
            # rate limiter silently stranded 27 of 107 alerts in the Phase 4a
            # re-run, and the forwarder sat in its poll loop reporting nothing
            # wrong. Re-sending is safe because the endpoint is idempotent by
            # alert id, so the correct behaviour is to replay the window.
            checkpoint = (position.inode, position.offset, carry)

            lines, carry = _read_new_lines(eve, position, carry)

            if not lines:
                time.sleep(args.poll)
                continue

            events: list[dict[str, Any]] = []
            malformed = 0
            for line in lines:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    malformed += 1
            if malformed:
                print(f"[warn] skipped {malformed} unparseable line(s)")

            ok = True
            for start in range(0, len(events), args.batch):
                result = _post(client, args.url, token, events[start : start + args.batch])
                if result is None:
                    ok = False
                    break
                sent += int(result.get("accepted", 0))
                if args.verbose:
                    print(
                        f"[info] accepted={result.get('accepted')} "
                        f"dropped={result.get('dropped')} total_sent={sent}"
                    )

            if ok:
                failures = 0
                position.save()
            else:
                # Roll the in-memory position back so the next poll re-reads
                # the window we could not deliver. Without this the offset stays
                # at EOF and the remainder of the file is lost.
                position.inode, position.offset, carry = checkpoint
                failures += 1
                # Full jitter: without it, a forwarder and a restarting server
                # synchronise and every retry lands at the same instant.
                delay = min(
                    BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * (2 ** min(failures, 6))
                )
                # Full jitter. `random` is correct here: this is a retry
                # delay, not a secret, and a CSPRNG would buy nothing.
                delay = random.uniform(0, delay)  # noqa: S311
                print(f"[warn] backing off {delay:.1f}s after {failures} failure(s)")
                time.sleep(delay)

    position.save()
    print(f"[info] stopped. {sent} event(s) accepted this run.")
    return 0


def _fail(message: str) -> int:
    print(f"[fatal] {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--eve", required=True, help="path to eve.json")
    parser.add_argument("--url", required=True, help="full URL of POST /ingest/eve")
    parser.add_argument(
        "--token-env",
        default="FLARE_INGEST_TOKEN",
        help="environment variable holding the service token (never argv)",
    )
    parser.add_argument("--state", default=None, help="position file (default: alongside eve.json)")
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--poll", type=float, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="ignore the saved position and read the whole file",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.batch < 1:
        return _fail("--batch must be at least 1")

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
