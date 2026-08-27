from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from backend.predictor import NetworkPredictor


class NSLKDDAnalyzer:
    """
    Optimized analyzer for the NSL-KDD dataset.

    NSL-KDD format:
        41 network traffic features
        + attack label
        + difficulty level

    The final two columns are NOT model features.

    The analyzer:
        - Loads NSL-KDD files efficiently
        - Validates the dataset structure
        - Removes label/difficulty columns before prediction
        - Performs batch prediction
        - Calculates useful attack statistics (including risk,
          severity, and confidence aggregates)
        - Returns a JSON-friendly dictionary
    """

    # NSL-KDD has exactly 41 model features.
    FEATURE_COUNT = 41

    # Official NSL-KDD column names.
    COLUMN_NAMES = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "hot",
        "num_failed_logins",
        "logged_in",
        "num_compromised",
        "root_shell",
        "su_attempted",
        "num_root",
        "num_file_creations",
        "num_shells",
        "num_access_files",
        "num_outbound_cmds",
        "is_host_login",
        "is_guest_login",
        "count",
        "srv_count",
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
    ]

    # Keys (after lower-casing) that may indicate normal vs
    # attack traffic, in priority order.
    _NORMAL_VALUES = {
        "normal",
        "0",
        "benign",
        "safe",
        "normal traffic",
    }

    def __init__(self, predictor: Optional[NetworkPredictor] = None):
        """
        Initialize the analyzer.

        Parameters
        ----------
        predictor:
            Existing NetworkPredictor instance. If None, a new instance is created.
        """
        if predictor is None:
            predictor = NetworkPredictor()

        self.predictor = predictor

    # ------------------------------------------------------------------
    # FILE LOADING
    # ------------------------------------------------------------------

    def load_file(self, file_path: str) -> pd.DataFrame:
        """
        Load an NSL-KDD TXT/CSV file.

        NSL-KDD files are comma-separated and normally do not contain
        a header row.
        """

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"NSL-KDD file not found: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"Provided path is not a file: {path}"
            )

        try:
            df = pd.read_csv(
                path,
                header=None,
                names=self.COLUMN_NAMES + ["label", "difficulty"],
                sep=",",
                skipinitialspace=True,
                low_memory=False,
            )
        except Exception as exc:
            raise ValueError(
                f"Failed to load NSL-KDD file '{path}': {exc}"
            ) from exc

        if df.empty:
            raise ValueError(
                f"NSL-KDD file is empty: {path}"
            )

        # Remove accidental whitespace from string columns.
        object_columns = df.select_dtypes(
            include=["object"]
        ).columns

        for column in object_columns:
            df[column] = df[column].astype(str).str.strip()

        return df

    # ------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------

    def validate_dataframe(self, df: pd.DataFrame) -> None:
        """
        Validate NSL-KDD dataframe structure.
        """

        if df is None:
            raise ValueError("DataFrame cannot be None")

        if df.empty:
            raise ValueError("NSL-KDD DataFrame is empty")

        if len(df.columns) < self.FEATURE_COUNT:
            raise ValueError(
                f"Expected at least {self.FEATURE_COUNT} columns, "
                f"but received {len(df.columns)}"
            )

        missing_features = [
            column
            for column in self.COLUMN_NAMES
            if column not in df.columns
        ]

        if missing_features:
            raise ValueError(
                "Missing NSL-KDD feature columns: "
                + ", ".join(missing_features)
            )

    # ------------------------------------------------------------------
    # FEATURE EXTRACTION
    # ------------------------------------------------------------------

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract only the 41 NSL-KDD model features.

        Label and difficulty columns are intentionally excluded.
        """

        self.validate_dataframe(df)

        features = df[self.COLUMN_NAMES].copy()

        return features

    # ------------------------------------------------------------------
    # BATCH PREDICTION
    # ------------------------------------------------------------------

    def _predict_batch(self, features: pd.DataFrame) -> Any:
        """
        Perform batch prediction through NetworkPredictor.
        """
        if hasattr(self.predictor, "predict_nsl_kdd_batch"):
            return self.predictor.predict_nsl_kdd_batch(features)

        if hasattr(self.predictor, "predict_batch"):
            try:
                return self.predictor.predict_batch(
                    features,
                    dataset="nsl_kdd",
                )
            except TypeError:
                return self.predictor.predict_batch(features)

        if hasattr(self.predictor, "predict_nsl_kdd"):
            return self.predictor.predict_nsl_kdd(features)

        if hasattr(self.predictor, "predict"):
            predictions = []

            for row in features.itertuples(
                index=False,
                name=None,
            ):
                result = self.predictor.predict(
                    dataset="nsl_kdd",
                    features=list(row),
                )
                predictions.append(result)

            return predictions

        raise AttributeError(
            "NetworkPredictor does not expose a supported prediction "
            "method. Expected one of: "
            "predict_nsl_kdd_batch(), predict_batch(), "
            "predict_nsl_kdd(), or predict()."
        )

    # ------------------------------------------------------------------
    # NORMALIZE PREDICTIONS
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_single_result(value: Any) -> Dict[str, Any]:
        """
        Normalize one row's raw prediction result into a
        consistent, lower-cased-key dictionary.
        """
        if isinstance(value, dict):
            return {
                str(key).strip().lower(): item
                for key, item in value.items()
            }

        return {"prediction": value}

    def _normalize_predictions(
        self,
        predictions: Any,
        row_count: int,
    ) -> List[Dict[str, Any]]:
        """
        Convert raw prediction output into a list of normalized dictionaries.
        """
        if isinstance(predictions, pd.DataFrame):
            records: List[Any] = predictions.to_dict(orient="records")

        elif isinstance(predictions, pd.Series):
            records = predictions.tolist()

        elif hasattr(predictions, "tolist"):
            records = predictions.tolist()

        else:
            records = list(predictions)

        normalized = [
            self._normalize_single_result(record)
            for record in records
        ]

        if len(normalized) != row_count:
            raise ValueError(
                "Prediction count does not match input row count. "
                f"Rows={row_count}, Predictions={len(normalized)}"
            )

        return normalized

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    @classmethod
    def _is_normal_prediction(cls, value: Any) -> bool:
        """
        Determine whether a bare prediction value represents normal traffic.
        """
        if value is None:
            return False

        text = str(value).strip().lower()

        return text in cls._NORMAL_VALUES

    @classmethod
    def _row_is_normal(cls, row: Dict[str, Any]) -> bool:
        """
        Determine whether a normalized prediction row represents normal traffic.
        """
        status = row.get("status")
        if status is not None:
            return str(status).strip().lower() == "normal"

        is_attack = row.get("is_attack")
        if is_attack is not None:
            return not bool(is_attack)

        return cls._is_normal_prediction(row.get("prediction"))

    def _build_statistics(
        self,
        predictions: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build summary statistics from normalized prediction rows.
        """
        total = len(predictions)

        normal_count = sum(
            self._row_is_normal(row) for row in predictions
        )
        attack_count = total - normal_count

        attack_percentage = (
            round((attack_count / total) * 100, 2) if total else 0.0
        )
        normal_percentage = (
            round((normal_count / total) * 100, 2) if total else 0.0
        )

        prediction_distribution: Dict[str, int] = {}
        severity_distribution: Dict[str, int] = {}
        risk_scores: List[float] = []
        confidences: List[float] = []

        for row in predictions:
            label = row.get("prediction", row.get("status", "UNKNOWN"))
            key = str(label)
            prediction_distribution[key] = (
                prediction_distribution.get(key, 0) + 1
            )

            severity = row.get("severity")
            if severity is not None:
                severity_key = str(severity)
                severity_distribution[severity_key] = (
                    severity_distribution.get(severity_key, 0) + 1
                )

            risk_score = row.get("risk_score")
            if isinstance(risk_score, (int, float)):
                risk_scores.append(float(risk_score))

            confidence = row.get("confidence")
            if isinstance(confidence, (int, float)):
                confidences.append(float(confidence))

        statistics: Dict[str, Any] = {
            "total_records": total,
            "normal_records": normal_count,
            "attack_records": attack_count,
            "normal_percentage": normal_percentage,
            "attack_percentage": attack_percentage,
            "prediction_distribution": prediction_distribution,
        }

        if severity_distribution:
            statistics["severity_distribution"] = severity_distribution

        if risk_scores:
            statistics["risk_score_stats"] = {
                "average": round(sum(risk_scores) / len(risk_scores), 2),
                "min": min(risk_scores),
                "max": max(risk_scores),
            }

        if confidences:
            statistics["confidence_stats"] = {
                "average": round(sum(confidences) / len(confidences), 4),
                "min": round(min(confidences), 4),
                "max": round(max(confidences), 4),
            }

        return statistics

    # ------------------------------------------------------------------
    # MAIN FILE ANALYSIS
    # ------------------------------------------------------------------

    def analyze_file(
        self,
        file_path: str,
        include_predictions: bool = True,
        max_rows: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Analyze an NSL-KDD file.
        """
        path = Path(file_path)

        df = self.load_file(path)

        if max_rows is not None:
            if max_rows <= 0:
                raise ValueError(
                    "max_rows must be greater than zero"
                )

            df = df.head(max_rows).copy()

        features = self.extract_features(df)

        raw_predictions = self._predict_batch(features)

        predictions = self._normalize_predictions(
            raw_predictions,
            len(features),
        )

        statistics = self._build_statistics(predictions)

        result: Dict[str, Any] = {
            "success": True,
            "dataset": "NSL-KDD",
            "file": str(path),
            "rows_analyzed": len(df),
            "feature_count": self.FEATURE_COUNT,
            "statistics": statistics,
        }

        if include_predictions:
            result["predictions"] = predictions

        if "label" in df.columns:
            result["actual_labels"] = (
                df["label"]
                .astype(str)
                .tolist()
            )

        return result

    # ------------------------------------------------------------------
    # DATAFRAME ANALYSIS
    # ------------------------------------------------------------------

    def analyze_dataframe(
        self,
        df: pd.DataFrame,
        include_predictions: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyze an already-loaded NSL-KDD DataFrame.
        """
        features = self.extract_features(df)

        raw_predictions = self._predict_batch(features)

        predictions = self._normalize_predictions(
            raw_predictions,
            len(features),
        )

        statistics = self._build_statistics(predictions)

        result: Dict[str, Any] = {
            "success": True,
            "dataset": "NSL-KDD",
            "rows_analyzed": len(df),
            "feature_count": self.FEATURE_COUNT,
            "statistics": statistics,
        }

        if include_predictions:
            result["predictions"] = predictions

        if "label" in df.columns:
            result["actual_labels"] = (
                df["label"]
                .astype(str)
                .tolist()
            )

        return result

    # ------------------------------------------------------------------
    # QUICK SUMMARY
    # ------------------------------------------------------------------

    def summary(
        self,
        file_path: str,
        max_rows: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Return only the statistical summary.
        """
        result = self.analyze_file(
            file_path=file_path,
            include_predictions=False,
            max_rows=max_rows,
        )

        return result["statistics"]

    # ------------------------------------------------------------------
    # STRING REPRESENTATION
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"feature_count={self.FEATURE_COUNT}"
            ")"
        )
