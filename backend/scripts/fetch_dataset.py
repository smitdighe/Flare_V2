"""Acquire CICIDS2017 `GeneratedLabelledFlows` and clean its known defects.

Source of record: https://www.unb.ca/cic/datasets/ids-2017.html

THE DISTRIBUTION CHANGED, AND THE REASON MATTERS. Phase 2 used
`MachineLearningCSV.zip` (79 columns: 78 flow features + Label). That
distribution carries no Flow ID, no Source IP, no Destination IP and no
Timestamp, and the frozen frontend requires `src_ip` and `dest_ip` on every
alert — so endpoints had to be derived from CICIDS2017's published topology and
stamped `endpoints_synthetic=True`. Derived endpoints were the largest honesty
caveat in the project.

`GeneratedLabelledFlows.zip` (85 columns) is the same CICFlowMeter run over the
same captures WITH those six columns present. Using it removes the caveat
entirely rather than documenting it: every endpoint is now the address the
capture actually recorded. The synthesis path is deleted, not disabled.

  --glf-hf         bencorn/CICIDS2017, file csvs/GeneratedLabelledFlows.zip —
                   free, anonymous, no credentials. UNB gates its own download
                   (every direct path under cicresearch.ca 302s to a ~108KB
                   registration form) and the Kaggle mirrors carry the
                   MachineLearningCSV variant only.
  --local PATH     an already-downloaded GeneratedLabelledFlows.zip, or a
                   directory of extracted `*.pcap_ISCX.csv` files.

`MachineLearningCSV` is deliberately NOT accepted. It cannot satisfy the
frontend contract without inventing addresses, so admitting it would only
reintroduce the caveat through a side door; a file lacking the six metadata
columns fails with a named error.

KNOWN DEFECTS, all handled explicitly and counted in the report:
  1. Column names carry leading/trailing whitespace (" Destination Port").
  2. The header row repeats mid-file in some days.
  3. Infinity and NaN appear in rate columns (Flow Bytes/s, Flow Packets/s).
  4. Mixed dtypes — numeric columns parse as object because of 1-3.
  5. "Fwd Header Length" appears TWICE with identical values.
  6. Severe class imbalance; BENIGN is the overwhelming majority.
  7. Label spellings vary and contain non-UTF8 bytes
     ("Web Attack \\x96 Brute Force" uses a CP-1252 en dash).
  8. GLF-only: Thursday-Morning-WebAttacks carries 288,602 rows that are blank
     in every column including Label, Source IP and Protocol.
  9. GLF-only: Timestamp is a 12-hour clock with NO AM/PM marker, so "3:16"
     is 03:16 or 15:16 with nothing in the row to say which. Resolved by the
     published capture window, not by guessing — see `parse_capture_timestamp`.

Nothing here fabricates a value. A row that cannot be cleaned is dropped and
counted, never repaired with a guess.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_DIR = REPO_ROOT / "data" / "datasets" / "cicids2017"
DEFAULT_ARCHIVE_DIR = REPO_ROOT / "data" / "datasets" / "raw"

GLF_HF_REPO = "bencorn/CICIDS2017"
GLF_HF_PATH = "csvs/GeneratedLabelledFlows.zip"
GLF_HF_URL = f"https://huggingface.co/datasets/{GLF_HF_REPO}/resolve/main/{GLF_HF_PATH}"

# Pinned so a silently swapped mirror is a loud failure rather than a quiet
# change of dataset underneath a committed model.
GLF_SHA256 = "7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a"

# The eight canonical files. `ATTACK_DAYS` is the subset build_partitions.py
# samples from — see its report for the justification.
CANONICAL_FILES: tuple[str, ...] = (
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)

ATTACK_DAYS: tuple[str, ...] = (
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)

LABEL_COLUMN = "Label"

# The six columns GeneratedLabelledFlows has and MachineLearningCSV does not.
# They are metadata: carried through cleaning as-is, never numeric-coerced with
# the features, and never admitted to the feature allowlist in app/ml/features.py.
METADATA_COLUMNS: tuple[str, ...] = (
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Protocol",
    "Timestamp",
)

# UNB captured 08:30-17:00 local each weekday. Hours 8-12 are therefore
# morning and 1-7 afternoon; see parse_capture_timestamp.
CAPTURE_FIRST_HOUR = 8
CAPTURE_LAST_HOUR = 7


@dataclass
class FileReport:
    filename: str
    rows_raw: int = 0
    rows_kept: int = 0
    header_rows_removed: int = 0
    blank_rows_removed: int = 0
    infinity_cells: int = 0
    nan_cells: int = 0
    rows_dropped_unparseable: int = 0
    rows_dropped_bad_timestamp: int = 0
    rows_dropped_bad_endpoint: int = 0
    timestamps_read_as_morning: int = 0
    timestamps_read_as_afternoon: int = 0
    encoding_used: str = ""
    duplicate_columns_removed: list[str] = field(default_factory=list)
    columns_whitespace_stripped: int = 0
    label_counts: dict[str, int] = field(default_factory=dict)
    sha256: str = ""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class MissingMetadataError(ValueError):
    """The file is a MachineLearningCSV variant, which cannot be used."""


# --------------------------------------------------------------------------
# the 12-hour timestamp
# --------------------------------------------------------------------------


def parse_capture_timestamp(value: object) -> datetime | None:
    """`5/7/2017 8:42` -> a real datetime, or None if it is not parseable.

    Two things are ambiguous in the raw string and both are resolved from
    published facts about the capture rather than from the row:

    DAY-FIRST. `5/7/2017` appears in Wednesday-workingHours, and CICIDS2017's
    Wednesday is 5 July 2017. Month-first would make it 7 May, a Sunday, on
    which nothing was captured.

    12-HOUR WITH NO MERIDIEM. Hours run 1-12 with no AM/PM marker anywhere in
    the file, so `3:16` is under-determined by the data alone. UNB captured
    08:30-17:00 each weekday, which the observed hour histogram matches
    exactly: 8-12 and 1-5 appear, 6 and 7 do not. Hours 8-12 are therefore
    read as morning and 1-7 as afternoon. The rule is applied uniformly and
    the split is counted per file, so its effect is auditable rather than
    invisible.

    Seconds are absent from the source and are not fabricated; they are zero.
    """
    text = str(value).strip()
    if not text:
        return None

    date_part, _, time_part = text.partition(" ")
    if not time_part:
        return None

    try:
        day_s, month_s, year_s = date_part.split("/")
        hour_s, minute_s = time_part.split(":")[:2]
        day, month, year = int(day_s), int(month_s), int(year_s)
        hour, minute = int(hour_s), int(minute_s)
    except ValueError:
        return None

    if not 1 <= hour <= 12:
        return None

    if hour <= CAPTURE_LAST_HOUR:
        hour += 12
    elif hour == 12:
        pass  # noon; 12 is already correct on a 24-hour clock
    elif hour < CAPTURE_FIRST_HOUR:
        return None

    try:
        return datetime(year, month, day, hour, minute)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# acquisition
# --------------------------------------------------------------------------


def _extract_zip(source: Path, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    print(f"Extracting {source.name} ...")
    with zipfile.ZipFile(source) as archive:
        for member in archive.namelist():
            name = Path(member).name
            # The archive nests everything under "TrafficLabelling /" — note
            # the trailing space, which is in UNB's own archive.
            if name.endswith(".csv"):
                with archive.open(member) as src, (dest / name).open("wb") as out:
                    shutil.copyfileobj(src, out)
    return sorted(dest.glob("*.csv"))


def _from_local(source: Path, dest: Path) -> list[Path]:
    if not source.exists():
        raise FileNotFoundError(f"--local path does not exist: {source}")

    if source.is_file() and source.suffix.lower() == ".zip":
        return _extract_zip(source, dest)
    if source.is_dir():
        if source.resolve() == dest.resolve():
            return sorted(dest.glob("*.csv"))
        dest.mkdir(parents=True, exist_ok=True)
        for csv_path in source.rglob("*.csv"):
            shutil.copy2(csv_path, dest / csv_path.name)
        return sorted(dest.glob("*.csv"))
    raise ValueError(f"--local must be a .zip or a directory, got: {source}")


def _from_huggingface(archive_dir: Path, dest: Path) -> list[Path]:
    """Free, anonymous mirror of UNB's own GeneratedLabelledFlows.zip."""
    import urllib.request

    archive_dir.mkdir(parents=True, exist_ok=True)
    archive = archive_dir / "GeneratedLabelledFlows.zip"

    if not (archive.exists() and archive.stat().st_size > 0):
        print(f"Downloading {GLF_HF_REPO}/{GLF_HF_PATH} (~284 MB) ...", flush=True)
        tmp = archive.with_suffix(".part")
        urllib.request.urlretrieve(GLF_HF_URL, tmp)
        tmp.replace(archive)

    digest = sha256_of(archive)
    if digest != GLF_SHA256:
        raise ValueError(
            f"{archive.name} sha256 {digest} does not match the pinned "
            f"{GLF_SHA256}. The mirror changed; verify before using it."
        )
    print(f"  sha256 verified: {digest}")

    return _extract_zip(archive, dest)


# --------------------------------------------------------------------------
# cleaning
# --------------------------------------------------------------------------


def clean_file(path: Path, out_dir: Path) -> FileReport:
    report = FileReport(filename=path.name)

    # The web-attack labels carry byte 0x96 — a CP-1252 en dash. UNB's original
    # files are CP-1252; some mirrors have already been converted to UTF-8 with
    # that byte replaced by U+FFFD. Forcing either encoding mangles the other
    # (cp1252 over UTF-8 turns U+FFFD's three bytes into "ï¿½"), so try UTF-8
    # first and fall back.
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            frame = pd.read_csv(path, encoding=encoding, low_memory=False)
            report.encoding_used = encoding
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"{path.name}: not decodable as utf-8, cp1252 or latin-1")
    report.rows_raw = len(frame)

    # Defect 1 — leading/trailing whitespace on column names.
    original_columns = list(frame.columns)
    frame.columns = [str(c).strip() for c in frame.columns]
    report.columns_whitespace_stripped = sum(
        1 for a, b in zip(original_columns, frame.columns, strict=True) if a != b
    )

    missing_metadata = [c for c in METADATA_COLUMNS if c not in frame.columns]
    if missing_metadata:
        raise MissingMetadataError(
            f"{path.name} is missing {missing_metadata}. This is the "
            "MachineLearningCSV distribution, which carries no endpoints or "
            "timestamps. Supply GeneratedLabelledFlows instead — the pipeline "
            "no longer synthesizes addresses."
        )

    # Defect 5 — "Fwd Header Length" appears twice. pandas suffixes the second
    # as ".1"; verify the values agree before dropping, so a real difference
    # would surface instead of being silently discarded.
    for column in list(frame.columns):
        if column.endswith(".1") and column[:-2] in frame.columns:
            base = column[:-2]
            if frame[base].equals(frame[column]):
                frame = frame.drop(columns=[column])
                report.duplicate_columns_removed.append(column)

    if LABEL_COLUMN not in frame.columns:
        raise ValueError(f"{path.name}: no '{LABEL_COLUMN}' column after cleaning")

    label_is_null = frame[LABEL_COLUMN].isna()
    labels = frame[LABEL_COLUMN].astype(str).str.strip()

    # Defect 2 — the header row repeats mid-file. Those rows have the literal
    # string "Label" in the label column.
    header_mask = labels == LABEL_COLUMN
    report.header_rows_removed = int(header_mask.sum())

    # Defect 8 — Thursday-Morning carries 288,602 rows blank in every column.
    # They are not partial records to repair; there is nothing in them. Tested
    # on the raw column, not on its string cast: a null renders as "nan" or
    # "<NA>" depending on the pandas backend, and matching those spellings
    # would silently stop working on an upgrade — which is how 288,602 rows
    # end up counted against the wrong defect.
    blank_mask = ~header_mask & (
        label_is_null | labels.isin(["", "nan", "<NA>", "None"])
    )
    report.blank_rows_removed = int(blank_mask.sum())

    frame = frame.loc[~(header_mask | blank_mask)]

    # Defect 9 — the 12-hour timestamp.
    parsed_times = frame["Timestamp"].astype(str).map(parse_capture_timestamp)
    raw_hours = (
        frame["Timestamp"]
        .astype(str)
        .str.extract(r"\s(\d{1,2}):", expand=False)
        .astype("Float64")
    )
    report.timestamps_read_as_afternoon = int((raw_hours <= CAPTURE_LAST_HOUR).sum())
    report.timestamps_read_as_morning = int((raw_hours >= CAPTURE_FIRST_HOUR).sum())
    time_ok = parsed_times.notna()
    report.rows_dropped_bad_timestamp = int((~time_ok).sum())

    # An endpoint that does not parse as an address cannot be rendered as one.
    endpoints_ok = frame["Source IP"].astype(str).str.count(r"\.").eq(3) & frame[
        "Destination IP"
    ].astype(str).str.count(r"\.").eq(3)
    report.rows_dropped_bad_endpoint = int((time_ok & ~endpoints_ok).sum())

    frame = frame.loc[time_ok & endpoints_ok]
    parsed_times = parsed_times.loc[frame.index]

    # Defects 3 and 4 — Infinity/NaN, and object dtype caused by them.
    feature_columns = [
        c for c in frame.columns if c != LABEL_COLUMN and c not in METADATA_COLUMNS
    ]
    numeric = frame[feature_columns].apply(pd.to_numeric, errors="coerce")

    infinite = numeric.isin([float("inf"), float("-inf")])
    report.infinity_cells = int(infinite.to_numpy().sum())
    numeric = numeric.mask(infinite)

    report.nan_cells = int(numeric.isna().to_numpy().sum())

    before = len(numeric)
    keep = numeric.notna().all(axis=1)
    report.rows_dropped_unparseable = int(before - int(keep.sum()))

    cleaned = numeric.loc[keep].copy()
    for column in METADATA_COLUMNS:
        cleaned[column] = frame.loc[keep, column].to_numpy()
    cleaned["captured_at"] = (
        parsed_times.loc[keep].map(lambda t: t.isoformat()).to_numpy()
    )
    cleaned[LABEL_COLUMN] = frame.loc[keep, LABEL_COLUMN].astype(str).str.strip().to_numpy()

    report.rows_kept = len(cleaned)
    report.label_counts = {
        str(k): int(v) for k, v in cleaned[LABEL_COLUMN].value_counts().items()
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / path.name.replace(".pcap_ISCX.csv", ".clean.csv")
    cleaned.to_csv(out_path, index=False)
    report.sha256 = sha256_of(out_path)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--local", type=Path, help="GeneratedLabelledFlows.zip or a directory"
    )
    source.add_argument(
        "--glf-hf", action="store_true", help=f"use {GLF_HF_REPO} (anonymous)"
    )
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--archive-dir", type=Path, default=DEFAULT_ARCHIVE_DIR)
    parser.add_argument(
        "--attack-days-only",
        action="store_true",
        help="Clean only the attack-heavy days build_partitions.py samples from.",
    )
    args = parser.parse_args()

    raw_dir = args.raw_dir
    clean_dir = raw_dir.parent / "clean"
    wanted = ATTACK_DAYS if args.attack_days_only else CANONICAL_FILES

    files = (
        _from_local(args.local, raw_dir)
        if args.local
        else _from_huggingface(args.archive_dir, raw_dir)
    )

    files = [f for f in files if f.name in wanted]
    if not files:
        print(
            f"No expected CSVs found in {raw_dir}. Expected any of:\n  "
            + "\n  ".join(wanted),
            file=sys.stderr,
        )
        return 2

    reports: list[FileReport] = []
    for path in sorted(files):
        print(f"Cleaning {path.name} ...", flush=True)
        report = clean_file(path, clean_dir)
        reports.append(report)
        print(
            f"  raw={report.rows_raw:,} kept={report.rows_kept:,} "
            f"headers={report.header_rows_removed} blank={report.blank_rows_removed:,} "
            f"inf={report.infinity_cells:,} nan={report.nan_cells:,} "
            f"dropped={report.rows_dropped_unparseable:,}"
        )

    manifest = {
        "source_of_record": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "distribution": "GeneratedLabelledFlows.zip (78 flow features + 6 metadata + Label)",
        "acquired_via": "local" if args.local else f"{GLF_HF_REPO}/{GLF_HF_PATH}",
        "archive_sha256": GLF_SHA256 if not args.local else "",
        "metadata_columns": list(METADATA_COLUMNS),
        "timestamp_disambiguation": (
            "The source Timestamp is a 12-hour clock with no AM/PM marker. "
            "Hours 8-12 are read as morning and 1-7 as afternoon, from UNB's "
            "published 08:30-17:00 capture window; the observed hour histogram "
            "contains 8-12 and 1-5 and never 6 or 7, which is consistent. "
            "Seconds are absent from the source and are recorded as zero, not "
            "invented. Counted per file as timestamps_read_as_morning / "
            "_as_afternoon."
        ),
        "files": [asdict(r) for r in reports],
        "totals": {
            "rows_raw": sum(r.rows_raw for r in reports),
            "rows_kept": sum(r.rows_kept for r in reports),
            "header_rows_removed": sum(r.header_rows_removed for r in reports),
            "blank_rows_removed": sum(r.blank_rows_removed for r in reports),
            "infinity_cells": sum(r.infinity_cells for r in reports),
            "nan_cells": sum(r.nan_cells for r in reports),
            "rows_dropped_unparseable": sum(r.rows_dropped_unparseable for r in reports),
            "rows_dropped_bad_timestamp": sum(
                r.rows_dropped_bad_timestamp for r in reports
            ),
            "rows_dropped_bad_endpoint": sum(
                r.rows_dropped_bad_endpoint for r in reports
            ),
        },
    }

    manifest_path = clean_dir / "FETCH_REPORT.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    totals = manifest["totals"]
    assert isinstance(totals, dict)
    print(f"\nWrote {manifest_path}")
    print(
        f"TOTAL raw={totals['rows_raw']:,} kept={totals['rows_kept']:,} "
        f"dropped={totals['rows_dropped_unparseable']:,}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
