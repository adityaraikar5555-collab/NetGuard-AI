from pathlib import Path

import pandas as pd

from src.prediction_engine import NetworkPredictionEngine


class CICIDSAnalyzer:
    """
    Analyze real CICIDS-2017 CSV files using the trained model.

    CICIDS model encoding:
        0 = ATTACK
        1 = BENIGN
    """

    def __init__(self):
        self.engine = NetworkPredictionEngine()

        self.model = self.engine.cicids_model

        # Confirm the expected 78 features
        self.feature_names = list(
            self.model.feature_names_in_
        )

    def analyze_csv(
        self,
        csv_path: str,
        max_rows: int | None = None
    ):
        path = Path(csv_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {csv_path}"
            )

        # --------------------------------------------------
        # 1. READ CSV
        # --------------------------------------------------

        df = pd.read_csv(path)

        # CICIDS files contain leading spaces in column names
        df.columns = df.columns.str.strip()

        # --------------------------------------------------
        # 2. CHECK REQUIRED FEATURES
        # --------------------------------------------------

        missing_features = [
            feature
            for feature in self.feature_names
            if feature not in df.columns
        ]

        if missing_features:
            raise ValueError(
                "Missing CICIDS features: "
                + ", ".join(missing_features)
            )

        # --------------------------------------------------
        # 3. SELECT EXACTLY THE 78 MODEL FEATURES
        # --------------------------------------------------

        X = df[self.feature_names].copy()

        # --------------------------------------------------
        # 4. CONVERT TO NUMERIC
        # --------------------------------------------------

        X = X.apply(
            pd.to_numeric,
            errors="coerce"
        )

        # --------------------------------------------------
        # 5. CLEAN INVALID VALUES
        # --------------------------------------------------

        X = X.replace(
            [float("inf"), float("-inf")],
            0
        )

        X = X.fillna(0)

        # --------------------------------------------------
        # 6. LIMIT ROWS FOR TESTING
        # --------------------------------------------------

        if max_rows is not None:
            X = X.iloc[:max_rows]
            df = df.iloc[:max_rows]

        if len(X) == 0:
            raise ValueError(
                "The CSV contains no usable rows."
            )

        # --------------------------------------------------
        # 7. MODEL PREDICTION
        # --------------------------------------------------

        predictions = self.model.predict(X)

        # --------------------------------------------------
        # 8. PREDICTION PROBABILITIES
        # --------------------------------------------------

        probabilities = None

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X)

        # --------------------------------------------------
        # 9. MODEL CLASS MAPPING
        #
        # LabelEncoder:
        # 0 = ATTACK
        # 1 = BENIGN
        # --------------------------------------------------

        classes = list(self.model.classes_)

        if 0 not in classes or 1 not in classes:
            raise ValueError(
                f"Unexpected CICIDS model classes: {classes}"
            )

        attack_index = classes.index(0)
        benign_index = classes.index(1)

        # --------------------------------------------------
        # 10. BUILD ROW RESULTS
        # --------------------------------------------------

        results = []

        for i, prediction in enumerate(predictions):

            prediction_value = int(prediction)

            # Correct interpretation
            if prediction_value == 0:
                prediction_text = "ATTACK"
                is_attack = True
            else:
                prediction_text = "BENIGN"
                is_attack = False

            confidence = None
            attack_probability = None
            benign_probability = None

            if probabilities is not None:

                attack_probability = float(
                    probabilities[i][attack_index]
                )

                benign_probability = float(
                    probabilities[i][benign_index]
                )

                confidence = float(
                    probabilities[i].max()
                )

            results.append({
                "row": i + 1,
                "prediction": prediction_text,
                "confidence": confidence,
                "attack_probability": attack_probability,
                "benign_probability": benign_probability,
                "is_attack": is_attack
            })

        # --------------------------------------------------
        # 11. CREATE RESULTS DATAFRAME
        # --------------------------------------------------

        results_df = pd.DataFrame(results)

        # --------------------------------------------------
        # 12. SUMMARY STATISTICS
        # --------------------------------------------------

        total_flows = len(results_df)

        attack_flows = int(
            results_df["is_attack"].sum()
        )

        benign_flows = (
            total_flows - attack_flows
        )

        attack_rate = (
            attack_flows / total_flows * 100
            if total_flows > 0
            else 0.0
        )

        benign_rate = (
            benign_flows / total_flows * 100
            if total_flows > 0
            else 0.0
        )

        # --------------------------------------------------
        # 13. RETURN ANALYSIS
        # --------------------------------------------------

        return {
            "dataset": "CICIDS-2017",
            "file": path.name,
            "total_flows": total_flows,
            "benign_flows": benign_flows,
            "attack_flows": attack_flows,
            "attack_rate": attack_rate,
            "benign_rate": benign_rate,
            "results": results_df
        }