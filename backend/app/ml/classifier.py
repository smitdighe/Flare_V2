"""Fast-tier serving. PLAN §4.3 / D6 / D25 / I5 / I13.

Loaded ONCE at startup and held as a singleton. Inference is pure CPU and
sub-millisecond, so it is called inline; `to_thread` would cost more in
scheduling than it saves.

THE TRAINED MODEL GETS NO SPECIAL TRUST. Its output is clamped to the same
enums as an LLM's, its probability is the calibrated one and not a raw softmax,
and every verdict it produces is stamped in the trace with `provider="lightgbm"`
and the model version. An analyst can always tell which tier answered — that is
I5, and it is the difference between this and a dict pretending to be a model.

FAILURE IS LOUD OR IT IS EXPLICIT, NEVER SILENT:

  missing / corrupt artifact   startup raises ModelLoadError. It does NOT fall
                               through to an LLM and does NOT fall through to a
                               default — a pipeline that quietly loses a tier
                               reports numbers for a system nobody is running.
  schema mismatch              startup raises. Wrong column order fails as
                               loudly as a missing column, because the booster
                               indexes by position.
  malformed feature row        `unknown`, a `failed` trace entry, and it STAYS
                               IN THE DENOMINATOR (I13).
  EVE / live_demo alert        `skipped` trace entry with a reason (D25).
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import lightgbm as lgb
import numpy as np

from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
from app.ingestion.normalize import NormalizedAlert
from app.ml.features import (
    FEATURE_COLUMNS,
    FeatureSchemaError,
    build_vector,
    schema_fingerprint,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO_ROOT / "models" / "classifier"

PROVIDER: Final[str] = "lightgbm"
UNKNOWN: Final[str] = "unknown"

# The sources that carry the 77 numeric flow columns. Everything else reaches
# the pipeline as a signature plus a 5-tuple.
SCOREABLE_SOURCES: Final[frozenset[str]] = frozenset({"cicids_replay"})

SKIP_REASON: Final[str] = (
    "source carries no CICIDS flow features; the fast tier is trained on 77 "
    "numeric flow columns and a zero-filled vector would be a fabricated input "
    "scored as a real prediction (PLAN D25)"
)


class ModelLoadError(RuntimeError):
    """The committed classifier is missing, corrupt, or schema-mismatched."""


@dataclass(frozen=True)
class Prediction:
    attack_type: str
    severity: str
    probability: float | None
    model_version: str
    trace: dict[str, Any] = field(default_factory=dict)

    @property
    def scored(self) -> bool:
        """False for a skip or a failure. Both stay in the denominator (I13)."""
        return self.attack_type != UNKNOWN


def _isotonic(knots: dict[str, list[float]], scores: np.ndarray) -> np.ndarray:
    x, y = knots["x"], knots["y"]
    return np.interp(scores, x, y, left=y[0], right=y[-1])


class FastTierClassifier:
    """The committed booster pair, loaded and verified."""

    def __init__(self, model_dir: Path = MODEL_DIR) -> None:
        self._dir = model_dir
        metrics = self._read_metrics()

        self.model_version: str = str(metrics["model_version"])
        self._classes: list[str] = list(metrics["attack_type_head"]["classes"])
        self._severities: list[str] = list(metrics["severity_head"]["classes"])

        # PLAN §4.3 — the schema is asserted at LOAD, not at first inference.
        # A mismatch discovered on the first alert is a mismatch discovered in
        # front of an audience.
        stored = str(metrics["feature_schema_fingerprint"])
        if stored != schema_fingerprint():
            raise ModelLoadError(
                "feature schema fingerprint mismatch: the committed model was "
                f"trained against {stored[:16]}… and app/ml/features.py is now "
                f"{schema_fingerprint()[:16]}…. The booster indexes features by "
                "POSITION, so a reordering silently changes what every tree "
                "splits on. Retrain, or restore the column order."
            )

        self._attack_booster = self._load_booster(
            "attack_type.booster.txt", metrics["attack_type_head"]["booster_sha256"]
        )
        if self._attack_booster.num_feature() != len(FEATURE_COLUMNS):
            raise ModelLoadError(
                f"booster expects {self._attack_booster.num_feature()} features, "
                f"app/ml/features.py defines {len(FEATURE_COLUMNS)}"
            )

        self._attack_knots: list[dict[str, list[float]]] = metrics[
            "attack_type_head"
        ]["calibration"]["knots"]

        self._severity_boosters = []
        self._severity_knots = []
        for threshold in metrics["severity_head"]["thresholds"]:
            self._severity_boosters.append(
                self._load_booster(threshold["booster"], threshold["booster_sha256"])
            )
            self._severity_knots.append(threshold["knots"])

    # -- loading -----------------------------------------------------------

    def _read_metrics(self) -> dict[str, Any]:
        path = self._dir / "metrics.json"
        if not path.exists():
            raise ModelLoadError(
                f"{path} missing. The classifier is committed, not downloaded — "
                "run `python -m scripts.train_classifier` to rebuild it. The "
                "pipeline does not start without a fast tier."
            )
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ModelLoadError(f"{path} is not valid JSON: {exc}") from exc
        return data

    def _load_booster(self, name: str, expected_sha256: str) -> lgb.Booster:
        path = self._dir / name
        if not path.exists():
            raise ModelLoadError(f"{path} missing — the committed model is incomplete")

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_sha256:
            raise ModelLoadError(
                f"{name} sha256 {digest[:16]}… does not match the {expected_sha256[:16]}… "
                "recorded in metrics.json. The artifact and its metrics report "
                "disagree, so neither can be trusted."
            )
        try:
            return lgb.Booster(model_file=str(path))
        except Exception as exc:
            raise ModelLoadError(f"{name} did not load as a LightGBM booster: {exc}") from exc

    # -- inference ---------------------------------------------------------

    def predict(self, alert: NormalizedAlert) -> Prediction:
        if alert.source not in SCOREABLE_SOURCES:
            return self._skipped(alert)

        try:
            vector = build_vector(alert.features)
        except (FeatureSchemaError, ValueError, TypeError) as exc:
            return self._failed(type(exc).__name__, str(exc))

        if vector.shape != (1, len(FEATURE_COLUMNS)) or not np.isfinite(
            np.nan_to_num(vector, nan=0.0)
        ).all():
            return self._failed(
                "MalformedFeatureRow",
                f"expected a 1x{len(FEATURE_COLUMNS)} finite vector, got {vector.shape}",
            )

        raw = np.asarray(self._attack_booster.predict(vector), dtype=np.float64)
        raw = raw.reshape(1, -1)

        calibrated = np.array(
            [_isotonic(k, raw[:, i])[0] for i, k in enumerate(self._attack_knots)]
        )
        total = float(calibrated.sum())
        # Every one-vs-rest calibrator returning zero leaves nothing to
        # normalise. That is a failed classification, not a uniform guess.
        if not math.isfinite(total) or total <= 0.0:
            return self._failed(
                "DegenerateCalibration",
                "every calibrated class probability was zero for this row",
            )
        probabilities = calibrated / total

        index = int(probabilities.argmax())
        attack_type = self._clamp_attack_type(self._classes[index])
        probability = float(probabilities[index])
        severity = self._predict_severity(vector)

        return Prediction(
            attack_type=attack_type,
            severity=severity,
            probability=probability,
            model_version=self.model_version,
            trace=self._trace(
                "ok",
                attack_type=attack_type,
                severity=severity,
                probability=round(probability, 6),
            ),
        )

    def _predict_severity(self, vector: np.ndarray) -> str:
        cumulative = np.array(
            [
                _isotonic(knots, np.atleast_1d(booster.predict(vector)))[0]
                for booster, knots in zip(
                    self._severity_boosters, self._severity_knots, strict=True
                )
            ]
        )
        columns = [1.0 - cumulative[0]]
        for k in range(len(cumulative) - 1):
            columns.append(cumulative[k] - cumulative[k + 1])
        columns.append(cumulative[-1])

        probabilities = np.clip(np.array(columns), 0.0, None)
        if probabilities.sum() <= 0.0:
            return UNKNOWN
        return self._clamp_severity(self._severities[int(probabilities.argmax())])

    # -- clamping ----------------------------------------------------------

    def _clamp_attack_type(self, value: str) -> str:
        """Identical treatment to LLM output — the model earns no exemption."""
        return value if value in CANONICAL_CLASSES else UNKNOWN

    def _clamp_severity(self, value: str) -> str:
        return value if value in SEVERITY_ORDER else UNKNOWN

    # -- trace -------------------------------------------------------------

    def _trace(self, status: str, **fields: Any) -> dict[str, Any]:
        return {
            "stage": "classify",
            "status": status,
            "provider": PROVIDER,
            "model": self.model_version,
            **fields,
        }

    def _skipped(self, alert: NormalizedAlert) -> Prediction:
        """PLAN D25 — an explicit skip, never a silent bypass.

        The alert still gets a trace entry, so it stays inside I5: the drawer
        shows that the fast tier was reached and declined, with the reason,
        rather than showing a gap the reader has to interpret.
        """
        return Prediction(
            attack_type=UNKNOWN,
            severity=UNKNOWN,
            probability=None,
            model_version=self.model_version,
            trace=self._trace("skipped", reason=SKIP_REASON, source=alert.source),
        )

    def _failed(self, error: str, detail: str) -> Prediction:
        """PLAN I13 — a failure is `unknown` and stays in the denominator."""
        return Prediction(
            attack_type=UNKNOWN,
            severity=UNKNOWN,
            probability=None,
            model_version=self.model_version,
            trace=self._trace("failed", error=error, detail=detail),
        )


_classifier: FastTierClassifier | None = None


def load_classifier(model_dir: Path = MODEL_DIR) -> FastTierClassifier:
    """Build the singleton. Called at startup so a bad artifact fails there."""
    global _classifier
    _classifier = FastTierClassifier(model_dir)
    return _classifier


def get_classifier() -> FastTierClassifier:
    if _classifier is None:
        raise ModelLoadError(
            "classifier not loaded. load_classifier() runs in the app lifespan; "
            "reaching inference without it means startup was bypassed."
        )
    return _classifier


def reset_classifier() -> None:
    """Test seam. Production loads once and never resets."""
    global _classifier
    _classifier = None
