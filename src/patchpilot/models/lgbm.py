"""LightGBM challenger model wrapper.

The wrapper is intentionally small: a deterministic LightGBM binary
classifier with optional isotonic calibration applied at ``predict_proba``
time. Persisted as a single ``.pkl`` blob with both the booster and the
calibrator so loading is a single ``LgbmModel.load`` call.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import lightgbm as lgb
import numpy as np

DEFAULT_PARAMS: dict[str, Any] = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 63,
    "min_data_in_leaf": 50,
    "feature_fraction": 0.9,
    "bagging_fraction": 0.8,
    "bagging_freq": 5,
    "n_estimators": 500,
    "verbose": -1,
}


@dataclass
class LgbmModelMeta:
    """Metadata bundled into the saved artifact."""

    feature_names: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    seed: int = 42
    trained_n: int = 0
    valid_n: int = 0
    model_version: str = "lgbm@v0.1.0"


class LgbmModel:
    """LightGBM binary classifier predicting ``exploited_30d``."""

    def __init__(self, params: dict[str, Any] | None = None, seed: int = 42) -> None:
        """Initialise with LightGBM hyperparameters (deterministic for fixed seed)."""
        merged = {**DEFAULT_PARAMS, **(params or {})}
        merged.update({"random_state": seed, "deterministic": True, "verbose": -1})
        self.params: dict[str, Any] = merged
        self.seed: int = seed
        self.booster: lgb.Booster | None = None
        self.calibrator: Any | None = None
        self.meta: LgbmModelMeta = LgbmModelMeta(params=merged, seed=seed)

    def fit(
        self,
        x_train: np.ndarray,
        y_train: np.ndarray,
        x_valid: np.ndarray | None = None,
        y_valid: np.ndarray | None = None,
        feature_names: list[str] | None = None,
    ) -> None:
        """Train the booster, optionally with early stopping on the valid fold."""
        x_train = np.asarray(x_train, dtype=np.float32)
        y_train = np.asarray(y_train, dtype=np.int8)
        if y_train.sum() == 0 or y_train.sum() == len(y_train):
            raise ValueError(
                "training labels are degenerate (all zeros or all ones); "
                "cannot fit a binary classifier"
            )

        train_set = lgb.Dataset(
            x_train,
            label=y_train,
            feature_name=feature_names or "auto",
        )
        valid_sets: list[lgb.Dataset] = [train_set]
        valid_names: list[str] = ["train"]
        if x_valid is not None and y_valid is not None and len(x_valid) > 0:
            valid_set = lgb.Dataset(
                np.asarray(x_valid, dtype=np.float32),
                label=np.asarray(y_valid, dtype=np.int8),
                reference=train_set,
                feature_name=feature_names or "auto",
            )
            valid_sets.append(valid_set)
            valid_names.append("valid")

        callbacks: list[Any] = [lgb.log_evaluation(period=0)]
        if len(valid_sets) > 1:
            callbacks.append(lgb.early_stopping(stopping_rounds=50, verbose=False))

        self.booster = lgb.train(
            params=self.params,
            train_set=train_set,
            num_boost_round=int(self.params.get("n_estimators", 500)),
            valid_sets=valid_sets,
            valid_names=valid_names,
            callbacks=callbacks,
        )
        self.meta = LgbmModelMeta(
            feature_names=list(feature_names or []),
            params=self.params,
            seed=self.seed,
            trained_n=int(len(y_train)),
            valid_n=int(len(y_valid)) if y_valid is not None else 0,
        )

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Return calibrated probabilities (or raw scores if no calibrator fit)."""
        if self.booster is None:
            raise RuntimeError("model has not been fit")
        scores = np.asarray(self.booster.predict(np.asarray(x, dtype=np.float32)))
        if self.calibrator is not None:
            scores = np.asarray(self.calibrator.predict(scores))
        return np.clip(scores, 0.0, 1.0).astype(np.float32)

    def set_calibrator(self, calibrator: Any) -> None:
        """Attach a fitted calibrator with a ``.predict`` method."""
        self.calibrator = calibrator

    def feature_importance(self) -> dict[str, float]:
        """Return a name -> importance dict (gain) for the trained booster."""
        if self.booster is None:
            raise RuntimeError("model has not been fit")
        importances = self.booster.feature_importance(importance_type="gain")
        names = self.meta.feature_names or [f"f{i}" for i in range(len(importances))]
        return dict(zip(names, [float(x) for x in importances], strict=False))

    def save(self, path: Path) -> Path:
        """Persist booster + calibrator + meta to a single pickle file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.booster is None:
            raise RuntimeError("nothing to save: model has not been fit")
        payload = {
            "booster_txt": self.booster.model_to_string(),
            "calibrator": self.calibrator,
            "meta": self.meta,
            "params": self.params,
        }
        with path.open("wb") as fh:
            pickle.dump(payload, fh)
        return path

    @classmethod
    def load(cls, path: Path) -> LgbmModel:
        """Load a previously saved model from ``path``."""
        with Path(path).open("rb") as fh:
            payload = cast(dict[str, Any], pickle.load(fh))
        instance = cls(params=payload["params"], seed=payload["meta"].seed)
        instance.booster = lgb.Booster(model_str=payload["booster_txt"])
        instance.calibrator = payload.get("calibrator")
        instance.meta = payload["meta"]
        return instance
