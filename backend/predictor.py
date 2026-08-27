from typing import Any, Dict, List, Optional
from pathlib import Path

import pandas as pd


class NetworkPredictor:
    """
    API adapter for the NetworkPredictionEngine.

    Responsibilities:
    - Load the central prediction engine
    - Validate CICIDS and NSL-KDD input
    - Route predictions to the correct model
    - Normalize prediction results
    """

    def __init__(self):
        self.project_root = Path(__file__).resolve().parent.parent
        self.engine = None
        self.engine_error = None

        self._load_engine()

    # =========================================================
    # ENGINE
    # =========================================================

    def _load_engine(self) -> None:
        try:
            from src.prediction_engine import NetworkPredictionEngine

            self.engine = NetworkPredictionEngine()

        except Exception as exc:
            self.engine_error = str(exc)
            self.engine = None

    # =========================================================
    # READINESS CHECKS
    # =========================================================

    def is_ready(self) -> bool:
        return self.engine is not None

    def is_cicids_ready(self) -> bool:
        return self.engine is not None and getattr(self.engine, "cicids_model", None) is not None

    def is_nsl_kdd_ready(self) -> bool:
        return self.engine is not None and getattr(self.engine, "nsl_kdd_model", None) is not None

    # =========================================================
    # STATUS
    # =========================================================

    def get_model_status(self) -> Dict[str, Any]:
        if self.engine is None:
            return {
                "status": "error",
                "loaded": False,
                "cicids": False,
                "nsl_kdd": False,
                "error": self.engine_error,
            }

        return {
            "status": "ready",
            "loaded": True,
            "cicids": True,
            "nsl_kdd": True,
            "error": None,
        }

    # =========================================================
    # MODEL INFORMATION
    # =========================================================

    def get_model_info(self) -> Dict[str, Any]:
        if self.engine is None:
            return {
                "service": "Network Anomaly Detection",
                "engine_loaded": False,
                "engine_error": self.engine_error,
            }

        try:
            engine_info = self.engine.get_model_info()
        except Exception:
            engine_info = {}

        return {
            "service": "Network Anomaly Detection",
            "engine_loaded": True,
            "datasets": {
                "CICIDS-2017": {
                    "available": True,
                    "features": int(
                        self.engine.cicids_model.n_features_in_
                    ),
                    "endpoint": "/predict/cicids",
                },
                "NSL-KDD": {
                    "available": True,
                    "features": int(
                        self.engine.nsl_kdd_model.n_features_in_
                    ),
                    "endpoint": "/predict/nsl-kdd",
                },
            },
            "engine_info": engine_info,
            "engine_error": None,
        }

    # =========================================================
    # MAIN PREDICTION
    # =========================================================

    def predict(
        self,
        dataset: str,
        features: List[Any],
    ) -> Dict[str, Any]:

        if self.engine is None:
            raise RuntimeError(
                "Prediction engine could not be loaded. "
                f"Engine error: {self.engine_error}"
            )

        if not features:
            raise ValueError("Feature list cannot be empty.")

        dataset_name = dataset.lower().strip()

        # -----------------------------------------------------
        # CICIDS
        # -----------------------------------------------------

        if dataset_name == "cicids":
            processed_features = self._validate_cicids(features)

            try:
                result = self.engine.predict_cicids(
                    processed_features
                )
            except Exception as exc:
                raise RuntimeError(
                    f"CICIDS prediction failed: {exc}"
                ) from exc

            return self._normalize_result(
                "CICIDS-2017",
                result,
            )

        # -----------------------------------------------------
        # NSL-KDD
        # -----------------------------------------------------

        if dataset_name in {
            "nsl-kdd",
            "nsl_kdd",
            "nslkdd",
        }:
            processed_features = self._validate_nsl_kdd(
                features
            )

            try:
                result = self.engine.predict_nsl_kdd(
                    processed_features
                )
            except Exception as exc:
                raise RuntimeError(
                    f"NSL-KDD prediction failed: {exc}"
                ) from exc

            return self._normalize_result(
                "NSL-KDD",
                result,
            )

        raise ValueError(
            "Unsupported dataset. "
            "Use 'cicids' or 'nsl-kdd'."
        )

    def predict_cicids(self, features: List[Any]) -> Dict[str, Any]:
        return self.predict("cicids", features)

    def predict_nsl_kdd(self, features: List[Any]) -> Dict[str, Any]:
        return self.predict("nsl-kdd", features)

    # =========================================================
    # NSL-KDD BATCH PREDICTION
    # =========================================================

    def predict_nsl_kdd_batch(
        self,
        features: pd.DataFrame,
    ) -> List[Dict[str, Any]]:
        """
        Run NSL-KDD prediction for an entire DataFrame of rows in
        a single call.
        """

        if self.engine is None:
            raise RuntimeError(
                "Prediction engine could not be loaded. "
                f"Engine error: {self.engine_error}"
            )

        if features is None or len(features) == 0:
            raise ValueError(
                "features DataFrame cannot be empty."
            )

        expected = self.engine.nsl_kdd_model.n_features_in_

        if features.shape[1] != expected:
            raise ValueError(
                f"NSL-KDD model expects {expected} feature "
                f"columns per row, but received "
                f"{features.shape[1]}."
            )

        try:
            results = self.engine.predict_nsl_kdd(features)
        except Exception as exc:
            raise RuntimeError(
                f"NSL-KDD batch prediction failed: {exc}"
            ) from exc

        return [
            self._normalize_result("NSL-KDD", result)
            for result in results
        ]

    # =========================================================
    # CICIDS VALIDATION
    # =========================================================

    def _validate_cicids(
        self,
        features: List[Any],
    ) -> List[float]:

        expected = self.engine.cicids_model.n_features_in_

        if len(features) != expected:
            raise ValueError(
                f"CICIDS model expects {expected} features, "
                f"but received {len(features)}."
            )

        try:
            return [float(value) for value in features]

        except (ValueError, TypeError) as exc:
            raise ValueError(
                "All CICIDS features must be numerical."
            ) from exc

    # =========================================================
    # NSL-KDD VALIDATION
    # =========================================================

    def _validate_nsl_kdd(
        self,
        features: List[Any],
    ) -> List[Any]:

        expected = self.engine.nsl_kdd_model.n_features_in_

        if len(features) != expected:
            raise ValueError(
                f"NSL-KDD model expects {expected} features, "
                f"but received {len(features)}."
            )

        categorical_indices = {1, 2, 3}

        processed = []

        for index, value in enumerate(features):

            if index in categorical_indices:
                processed.append(str(value).strip())
                continue

            try:
                processed.append(float(value))

            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"NSL-KDD feature at index {index} "
                    "must be numerical."
                ) from exc

        return processed

    # =========================================================
    # RESULT NORMALIZATION
    # =========================================================

    @staticmethod
    def _normalize_result(
        dataset: str,
        result: Any,
    ) -> Dict[str, Any]:

        if (
            isinstance(result, list)
            and len(result) == 1
            and isinstance(result[0], dict)
        ):
            result = result[0]

        if isinstance(result, dict):
            output = dict(result)
            output.setdefault("dataset", dataset)
            return output

        prediction = str(result).strip().upper()

        if prediction in {
            "0",
            "NORMAL",
            "BENIGN",
        }:
            status = "NORMAL"
        else:
            status = "ATTACK"

        return {
            "dataset": dataset,
            "prediction": prediction,
            "status": status,
            "confidence": None,
            "attack_probability": None,
            "is_attack": status == "ATTACK",
            "risk_score": None,
            "severity": None,
        }
