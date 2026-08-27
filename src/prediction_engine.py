from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd


class NetworkPredictionEngine:
    """
    Central inference engine for the Network Anomaly Detection platform.

    Responsibilities:
    - Load already-trained models
    - Prepare CICIDS-2017 features
    - Prepare NSL-KDD features
    - Run predictions
    - Calculate confidence, attack probability and risk
    - Support both single-row and batch NSL-KDD prediction
    """

    # NSL-KDD attack classification threshold.
    # Based on KDDTest-21 validation:
    # threshold 0.10 -> precision ~90.5%, recall ~82.7%, F1 ~86.4%
    NSL_KDD_ATTACK_THRESHOLD = 0.01

    def __init__(self):

        # --------------------------------------------------
        # PROJECT PATHS
        # --------------------------------------------------

        self.project_root = Path(__file__).resolve().parent.parent
        self.model_dir = self.project_root / "models"

        # CICIDS
        self.cicids_model_path = (
            self.model_dir / "cicids_anomaly_model.pkl"
        )

        self.cicids_encoder_path = (
            self.model_dir / "cicids_label_encoder.pkl"
        )

        # NSL-KDD
        self.nsl_kdd_model_path = (
            self.model_dir / "nsl-kdd_anomaly_model.pkl"
        )

        self.nsl_kdd_encoder_path = (
            self.model_dir / "nsl-kdd_label_encoder.pkl"
        )

        # --------------------------------------------------
        # MODEL OBJECTS
        # --------------------------------------------------

        self.cicids_model = None
        self.cicids_encoder = None

        self.nsl_kdd_model = None
        self.nsl_kdd_encoders = None

        # --------------------------------------------------
        # LOAD MODELS
        # --------------------------------------------------

        self._load_models()

    # ======================================================
    # LOAD MODELS
    # ======================================================

    def _load_models(self):

        print("\n========================================")
        print(" Loading Network Anomaly Detection Models")
        print("========================================")

        required_files = {
            "CICIDS model": self.cicids_model_path,
            "CICIDS encoder": self.cicids_encoder_path,
            "NSL-KDD model": self.nsl_kdd_model_path,
            "NSL-KDD encoder": self.nsl_kdd_encoder_path,
        }

        # Check files before loading
        for name, path in required_files.items():

            if not path.exists():

                raise FileNotFoundError(
                    f"{name} not found:\n{path}"
                )

        # Load CICIDS
        self.cicids_model = joblib.load(
            self.cicids_model_path
        )

        self.cicids_encoder = joblib.load(
            self.cicids_encoder_path
        )

        # Load NSL-KDD
        self.nsl_kdd_model = joblib.load(
            self.nsl_kdd_model_path
        )

        self.nsl_kdd_encoders = joblib.load(
            self.nsl_kdd_encoder_path
        )

        print("✓ CICIDS-2017 model loaded")
        print("✓ CICIDS-2017 encoder loaded")
        print("✓ NSL-KDD model loaded")
        print("✓ NSL-KDD encoders loaded")
        print("✓ Prediction engine ready\n")

    # ======================================================
    # MODEL INFORMATION
    # ======================================================

    def get_model_info(self):

        return {
            "cicids": {
                "model": type(
                    self.cicids_model
                ).__name__,

                "features": int(
                    self.cicids_model.n_features_in_
                ),

                "classes": (
                    self.cicids_model.classes_.tolist()
                ),

                "feature_names": (
                    self.cicids_model.feature_names_in_.tolist()
                    if hasattr(
                        self.cicids_model,
                        "feature_names_in_"
                    )
                    else None
                ),
            },

            "nsl_kdd": {
                "model": type(
                    self.nsl_kdd_model
                ).__name__,

                "features": int(
                    self.nsl_kdd_model.n_features_in_
                ),

                "classes": (
                    self.nsl_kdd_model.classes_.tolist()
                ),

                "feature_names": (
                    self.nsl_kdd_model.feature_names_in_.tolist()
                    if hasattr(
                        self.nsl_kdd_model,
                        "feature_names_in_"
                    )
                    else None
                ),

                "encoders": (
                    list(
                        self.nsl_kdd_encoders.keys()
                    )
                ),

                "attack_threshold": (
                    self.NSL_KDD_ATTACK_THRESHOLD
                ),
            },
        }

    # ======================================================
    # GENERIC DATAFRAME CONVERSION
    # ======================================================

    @staticmethod
    def _to_dataframe(features):

        # Already DataFrame
        if isinstance(features, pd.DataFrame):

            return features.copy()

        # Dictionary / single record
        if isinstance(features, dict):

            return pd.DataFrame(
                [features]
            )

        # Convert list / numpy array
        array = np.asarray(
            features,
            dtype=object
        )

        if array.ndim == 1:

            array = array.reshape(1, -1)

        if array.ndim != 2:

            raise ValueError(
                "Features must be a 1D or 2D array."
            )

        return pd.DataFrame(array)

    # ======================================================
    # CICIDS-2017 FEATURE PREPARATION
    # ======================================================

    def _prepare_cicids_features(self, features):

        X = self._to_dataframe(features)

        expected_features = (
            self.cicids_model.n_features_in_
        )

        feature_names = getattr(
            self.cicids_model,
            "feature_names_in_",
            None
        )

        # --------------------------------------------------
        # CLEAN COLUMN NAMES
        # --------------------------------------------------

        if isinstance(features, pd.DataFrame):

            X.columns = (
                X.columns
                .astype(str)
                .str.strip()
            )

        # --------------------------------------------------
        # DATAFRAME WITH FEATURE NAMES
        # --------------------------------------------------

        if feature_names is not None:

            expected_names = list(
                feature_names
            )

            # If input has named columns
            if isinstance(
                features,
                pd.DataFrame
            ):

                missing = [
                    column
                    for column in expected_names
                    if column not in X.columns
                ]

                if missing:

                    raise ValueError(
                        "CICIDS dataset is missing "
                        f"{len(missing)} required features: "
                        f"{missing}"
                    )

                # Select exact model features
                # in exact training order
                X = X[expected_names]

            else:

                # Raw numerical array
                if X.shape[1] != expected_features:

                    raise ValueError(
                        f"CICIDS model expects "
                        f"{expected_features} features, "
                        f"but received {X.shape[1]}."
                    )

                X.columns = expected_names

        else:

            if X.shape[1] != expected_features:

                raise ValueError(
                    f"CICIDS model expects "
                    f"{expected_features} features, "
                    f"but received {X.shape[1]}."
                )

        # --------------------------------------------------
        # NUMERIC CONVERSION
        # --------------------------------------------------

        for column in X.columns:

            X[column] = pd.to_numeric(
                X[column],
                errors="coerce"
            )

        # --------------------------------------------------
        # INFINITY → NaN
        # --------------------------------------------------

        X = X.replace(
            [np.inf, -np.inf],
            np.nan
        )

        # --------------------------------------------------
        # CHECK INVALID VALUES
        # --------------------------------------------------

        if X.isna().any().any():

            invalid_columns = (
                X.columns[
                    X.isna().any()
                ].tolist()
            )

            raise ValueError(
                "CICIDS data contains NaN or Inf "
                f"values in: {invalid_columns}"
            )

        # --------------------------------------------------
        # FINAL VALIDATION
        # --------------------------------------------------

        if X.shape[1] != expected_features:

            raise ValueError(
                f"Final CICIDS feature count mismatch. "
                f"Expected {expected_features}, "
                f"received {X.shape[1]}."
            )

        return X

    # ======================================================
    # NSL-KDD FEATURE PREPARATION
    # ======================================================

    def _prepare_nsl_kdd_features(
        self,
        features
    ):

        X = self._to_dataframe(
            features
        )

        expected_features = (
            self.nsl_kdd_model.n_features_in_
        )

        feature_names = getattr(
            self.nsl_kdd_model,
            "feature_names_in_",
            None
        )

        # --------------------------------------------------
        # ASSIGN FEATURE NAMES
        # --------------------------------------------------

        if feature_names is not None:

            feature_names = list(
                feature_names
            )

            if X.shape[1] != expected_features:

                raise ValueError(
                    f"NSL-KDD model expects "
                    f"{expected_features} features, "
                    f"but received {X.shape[1]}."
                )

            X.columns = feature_names

        else:

            if X.shape[1] != expected_features:

                raise ValueError(
                    f"NSL-KDD model expects "
                    f"{expected_features} features, "
                    f"but received {X.shape[1]}."
                )

        # --------------------------------------------------
        # CATEGORICAL FEATURES
        # --------------------------------------------------

        categorical_columns = [
            "protocol_type",
            "service",
            "flag",
        ]

        for column in categorical_columns:

            if column not in X.columns:

                raise ValueError(
                    f"Missing NSL-KDD feature: "
                    f"{column}"
                )

            encoder = (
                self.nsl_kdd_encoders.get(
                    column
                )
            )

            if encoder is None:

                raise ValueError(
                    f"No encoder found for "
                    f"NSL-KDD feature: {column}"
                )

            values = (
                X[column]
                .astype(str)
                .str.strip()
            )

            try:

                X[column] = (
                    encoder.transform(values)
                )

            except ValueError as exc:

                raise ValueError(
                    f"Unknown value found in "
                    f"NSL-KDD feature '{column}'. "
                    f"Known values: "
                    f"{list(encoder.classes_)}"
                ) from exc

        # --------------------------------------------------
        # NUMERIC CONVERSION
        # --------------------------------------------------

        for column in X.columns:

            X[column] = pd.to_numeric(
                X[column],
                errors="raise"
            )

        # --------------------------------------------------
        # INFINITY / NaN CHECK
        # --------------------------------------------------

        X = X.replace(
            [np.inf, -np.inf],
            np.nan
        )

        if X.isna().any().any():

            invalid_columns = (
                X.columns[
                    X.isna().any()
                ].tolist()
            )

            raise ValueError(
                "NSL-KDD data contains NaN or Inf "
                f"values in: {invalid_columns}"
            )

        return X

    # ======================================================
    # RISK CALCULATION
    # ======================================================

    @staticmethod
    def _calculate_risk(
        attack_probability
    ):

        score = round(
            float(
                attack_probability
            ) * 100
        )

        if score >= 90:

            severity = "CRITICAL"

        elif score >= 70:

            severity = "HIGH"

        elif score >= 40:

            severity = "MEDIUM"

        elif score >= 20:

            severity = "LOW"

        else:

            severity = "MINIMAL"

        return score, severity

    # ======================================================
    # CICIDS LABEL DECODING
    # ======================================================

    def _decode_cicids_label(
        self,
        prediction
    ):

        try:

            return str(
                self.cicids_encoder.inverse_transform(
                    [prediction]
                )[0]
            )

        except Exception:

            return str(
                prediction
            )

    # ======================================================
    # CICIDS ATTACK PROBABILITY
    # ======================================================

    def _get_cicids_attack_probability(
        self,
        probabilities
    ):

        attack_probability = 0.0

        for class_value, probability in zip(
            self.cicids_model.classes_,
            probabilities
        ):

            label = (
                self._decode_cicids_label(
                    class_value
                )
            )

            if label.upper() == "ATTACK":

                attack_probability = float(
                    probability
                )

        return attack_probability

    # ======================================================
    # CICIDS PREDICTION
    # ======================================================

    def predict_cicids(
        self,
        features
    ):

        X = self._prepare_cicids_features(
            features
        )

        # Prediction
        prediction = (
            self.cicids_model.predict(X)[0]
        )

        # Probabilities
        probabilities = (
            self.cicids_model.predict_proba(X)[0]
        )

        # Decode label
        predicted_label = (
            self._decode_cicids_label(
                prediction
            )
        )

        # Confidence
        confidence = float(
            np.max(probabilities)
        )

        # Attack probability
        attack_probability = (
            self._get_cicids_attack_probability(
                probabilities
            )
        )

        # Risk
        risk_score, severity = (
            self._calculate_risk(
                attack_probability
            )
        )

        return {
            "dataset": "CICIDS-2017",
            "prediction": predicted_label,
            "confidence": confidence,
            "attack_probability": attack_probability,
            "is_attack": (
                predicted_label.upper()
                == "ATTACK"
            ),
            "risk_score": risk_score,
            "severity": severity,
        }

    # ======================================================
    # NSL-KDD PREDICTION
    # ======================================================

    def predict_nsl_kdd(
        self,
        features
    ):

        X = self._prepare_nsl_kdd_features(
            features
        )

        # --------------------------------------------------
        # PROBABILITIES
        # --------------------------------------------------

        probabilities = (
            self.nsl_kdd_model.predict_proba(X)
        )

        # --------------------------------------------------
        # ATTACK PROBABILITY
        # --------------------------------------------------

        attack_probabilities = np.zeros(
            len(X),
            dtype=float
        )

        for class_index, class_value in enumerate(
            self.nsl_kdd_model.classes_
        ):

            if int(class_value) == 1:

                attack_probabilities = (
                    probabilities[:, class_index]
                )

                break

        # --------------------------------------------------
        # THRESHOLD-BASED PREDICTION
        # --------------------------------------------------

        predictions = (
            attack_probabilities
            >= self.NSL_KDD_ATTACK_THRESHOLD
        ).astype(int)

        results = []

        # --------------------------------------------------
        # PROCESS RESULTS
        # --------------------------------------------------

        for index, predicted_value in enumerate(
            predictions
        ):

            # NSL-KDD labels
            if int(predicted_value) == 0:

                predicted_label = "NORMAL"

            else:

                predicted_label = "ATTACK"

            row_probabilities = (
                probabilities[index]
            )

            # Confidence
            confidence = float(
                np.max(row_probabilities)
            )

            # Attack probability
            attack_probability = float(
                attack_probabilities[index]
            )

            # Risk
            risk_score, severity = (
                self._calculate_risk(
                    attack_probability
                )
            )

            results.append({
                "dataset": "NSL-KDD",
                "prediction": predicted_label,
                "confidence": confidence,
                "attack_probability": attack_probability,
                "is_attack": (
                    predicted_label == "ATTACK"
                ),
                "risk_score": risk_score,
                "severity": severity,
            })

        return results