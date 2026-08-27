from io import BytesIO
from typing import Dict, Any

import pandas as pd


class DatasetAnalyzer:
    """
    Handles uploaded network datasets.

    The purpose of this service is to inspect a dataset before
    sending it to the ML prediction pipeline.
    """

    def analyze(
        self,
        contents: bytes,
        filename: str
    ) -> Dict[str, Any]:

        if not contents:

            raise ValueError(
                "Uploaded file is empty."
            )

        dataframe = self._read_dataset(
            contents,
            filename
        )

        if dataframe.empty:

            raise ValueError(
                "The uploaded dataset contains no rows."
            )

        return self._build_analysis(
            dataframe,
            filename
        )

    # ========================================================
    # READ DATASET
    # ========================================================

    def _read_dataset(
        self,
        contents: bytes,
        filename: str
    ) -> pd.DataFrame:

        buffer = BytesIO(contents)

        filename_lower = filename.lower()

        # ----------------------------------------------------
        # CSV
        # ----------------------------------------------------

        if filename_lower.endswith(".csv"):

            try:

                return pd.read_csv(
                    buffer
                )

            except Exception:

                buffer.seek(0)

                return pd.read_csv(
                    buffer,
                    encoding="latin1"
                )

        # ----------------------------------------------------
        # TXT / DATA
        # ----------------------------------------------------

        try:

            return pd.read_csv(
                buffer,
                sep=None,
                engine="python"
            )

        except Exception:

            buffer.seek(0)

            return pd.read_csv(
                buffer,
                sep=",",
                encoding="latin1"
            )

    # ========================================================
    # ANALYSIS
    # ========================================================

    def _build_analysis(
        self,
        dataframe: pd.DataFrame,
        filename: str
    ) -> Dict[str, Any]:

        rows, columns = dataframe.shape

        numeric_columns = dataframe.select_dtypes(
            include="number"
        ).columns.tolist()

        categorical_columns = dataframe.select_dtypes(
            exclude="number"
        ).columns.tolist()

        missing_values = int(
            dataframe.isna().sum().sum()
        )

        duplicate_rows = int(
            dataframe.duplicated().sum()
        )

        column_information = []

        for column in dataframe.columns:

            column_information.append(
                {
                    "name": str(column),
                    "dtype": str(
                        dataframe[column].dtype
                    ),
                    "missing": int(
                        dataframe[column].isna().sum()
                    ),
                    "unique": int(
                        dataframe[column].nunique()
                    ),
                }
            )

        # ----------------------------------------------------
        # Try to identify label column
        # ----------------------------------------------------

        label_column = self._detect_label_column(
            dataframe
        )

        label_distribution = {}

        if label_column:

            counts = (
                dataframe[label_column]
                .value_counts(dropna=False)
            )

            for key, value in counts.items():

                label_distribution[
                    str(key)
                ] = int(value)

        # ----------------------------------------------------
        # Dataset type detection
        # ----------------------------------------------------

        dataset_type = self._detect_dataset(
            dataframe
        )

        return {
            "status": "success",

            "file": {
                "filename": filename,
                "size_bytes": None,
            },

            "dataset": {
                "detected": dataset_type,
                "rows": rows,
                "columns": columns,
            },

            "statistics": {
                "numeric_columns": len(
                    numeric_columns
                ),
                "categorical_columns": len(
                    categorical_columns
                ),
                "missing_values": missing_values,
                "duplicate_rows": duplicate_rows,
            },

            "label": {
                "column": label_column,
                "distribution": label_distribution,
            },

            "columns": column_information,

            "preview": dataframe.head(10)
            .fillna("")
            .to_dict(orient="records"),
        }

    # ========================================================
    # LABEL DETECTION
    # ========================================================

    @staticmethod
    def _detect_label_column(
        dataframe: pd.DataFrame
    ):

        possible_labels = [
            "label",
            "Label",
            "LABEL",
            "class",
            "Class",
            "CLASS",
            "target",
            "Target",
            "attack",
            "Attack",
        ]

        for column in dataframe.columns:

            if str(column) in possible_labels:

                return str(column)

        return None

    # ========================================================
    # DATASET DETECTION
    # ========================================================

    @staticmethod
    def _detect_dataset(
        dataframe: pd.DataFrame
    ) -> str:

        columns = {
            str(column).lower().strip()
            for column in dataframe.columns
        }

        # NSL-KDD characteristics

        nsl_columns = {
            "duration",
            "protocol_type",
            "service",
            "flag",
            "src_bytes",
            "dst_bytes",
        }

        if len(
            nsl_columns.intersection(columns)
        ) >= 3:

            return "NSL-KDD"

        # CICIDS characteristics

        cicids_indicators = [
            "flow duration",
            "total fwd packets",
            "total backward packets",
            "flow bytes/s",
            "flow packets/s",
            "fwd packet length mean",
            "bwd packet length mean",
        ]

        matches = 0

        for indicator in cicids_indicators:

            if indicator in columns:

                matches += 1

        if matches >= 2:

            return "CICIDS-2017"

        return "Unknown"