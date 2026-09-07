"""The single feature-construction module.

PLAN §4.3 / §12 / §18: train/serve skew is a silent accuracy killer. Two
divergent feature builders produce a model that scores well offline and badly
in production, and no eval catches it because the eval uses the training
builder. So there is exactly one builder — this one — imported by
`scripts/train_classifier.py` (Phase 2a) and by the serving classifier
(Phase 3) alike.

FEATURE HYGIENE (PLAN §4.3, and the >98% memorization alarm in §7.3):
identifiers are excluded by an explicit ALLOWLIST, not a denylist. CICIDS2017's
IP topology is fixed, so a leaked address column memorises instantly and scores
near-perfectly while learning nothing transferable. An allowlist fails closed —
a new identifier column appearing upstream is ignored rather than silently
admitted.

`Destination Port` is deliberately RETAINED and is called out as a caveat in
the model card rather than hidden: it is highly predictive and partly
label-correlated by construction (port 80 traffic dominates the web attacks).
That is an honest limitation, stated, not a secret.
"""

from __future__ import annotations

from typing import Final

import numpy as np
import pandas as pd

# Columns that must NEVER become features, even if a future dataset variant
# supplies them. Listed so the intent is auditable rather than implicit in an
# omission.
EXCLUDED_IDENTIFIERS: Final[tuple[str, ...]] = (
    "Flow ID",
    "Source IP",
    "Src IP",
    "Source Port",
    "Src Port",
    "Destination IP",
    "Dst IP",
    "Timestamp",
    "Label",
    "canonical_class",
    "row_id",
    "partition",
    "source_file",
)

# The 77 numeric flow features of CICIDS2017's MachineLearningCSV, in a fixed
# order. Order is part of the contract: the booster indexes by position, so a
# reordering silently changes what every tree splits on.
FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)

FEATURE_COUNT: Final[int] = len(FEATURE_COLUMNS)


def schema_fingerprint() -> str:
    """A digest of the column list IN ORDER.

    The booster indexes features by position, so a reordering changes what
    every tree splits on while leaving the column set identical. A set
    comparison would not notice; this does. The serving loader compares it
    against the value stored beside the committed model and refuses to start on
    a mismatch.
    """
    import hashlib

    return hashlib.sha256("|".join(FEATURE_COLUMNS).encode("utf-8")).hexdigest()


class FeatureSchemaError(ValueError):
    """The incoming row does not match the pinned feature schema."""


def normalize_column_name(name: str) -> str:
    """CICIDS2017 ships column names with leading/trailing whitespace."""
    return " ".join(str(name).split())


def assert_schema(columns: list[str]) -> None:
    """Fail loudly on a schema mismatch.

    PLAN §4.3: wrong column order or a missing column fails at load rather than
    producing quiet garbage at inference time.
    """
    normalized = {normalize_column_name(c) for c in columns}
    missing = [c for c in FEATURE_COLUMNS if c not in normalized]
    if missing:
        raise FeatureSchemaError(
            f"{len(missing)} feature column(s) missing: {missing[:5]}"
            + ("..." if len(missing) > 5 else "")
        )

    leaked = [c for c in EXCLUDED_IDENTIFIERS if c in normalized and c in FEATURE_COLUMNS]
    if leaked:
        raise FeatureSchemaError(f"Identifier columns present in feature set: {leaked}")


def build_matrix(frame: pd.DataFrame) -> np.ndarray:
    """Frame -> float32 matrix, columns in FEATURE_COLUMNS order.

    The one path both training and serving use.
    """
    renamed = frame.rename(columns={c: normalize_column_name(c) for c in frame.columns})
    assert_schema(list(renamed.columns))

    # copy=True is load-bearing, not defensive. pandas can hand back a
    # read-only zero-copy view — it does so for the single-row frame the
    # SERVING path builds — and the in-place infinity mask below then raises
    # "assignment destination is read-only". That surfaced as every single-row
    # inference failing to `unknown` while batch training worked perfectly:
    # exactly the train/serve skew this module exists to prevent.
    matrix = renamed.loc[:, list(FEATURE_COLUMNS)].to_numpy(dtype=np.float64, copy=True)

    # Infinity survives a clean CSV round-trip through float parsing; a booster
    # handles NaN natively but not inf. Replaced with NaN so the model's own
    # missing-value handling applies rather than a fabricated sentinel.
    matrix[np.isinf(matrix)] = np.nan
    return matrix.astype(np.float32)


def build_vector(row: dict[str, float]) -> np.ndarray:
    """Single row -> a 1-by-N float32 matrix. Serving path.

    Delegates to build_matrix so a divergence between the two is impossible by
    construction, which is the whole point of this module.
    """
    return build_matrix(pd.DataFrame([row]))
