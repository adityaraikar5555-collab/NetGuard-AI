import sys
import os

from pathlib import Path


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(
    0,
    str(SRC_DIR)
)


# ============================================================
# IMPORTS
# ============================================================

from prediction_engine import (
    NetworkPredictionEngine
)

from cicids_preprocessing import (
    load_dataset,
    clean_dataset
)

from nsl_kdd_preprocessing import (
    load_and_preprocess
)


# ============================================================
# CICIDS TEST
# ============================================================

def test_cicids(engine):

    print("\n")
    print("=" * 70)
    print("CICIDS-2017 REAL PREDICTION")
    print("=" * 70)

    data_path = (
        PROJECT_ROOT
        / "data"
        / "CICIDS-2017"
    )

    print("\nLoading CICIDS-2017...")

    df = load_dataset(
        str(data_path),
        sample_per_file=1000
    )

    X, y, encoder = clean_dataset(df)

    print(
        f"Processed shape: {X.shape}"
    )

    sample = X.iloc[[0]]

    actual_label = encoder.inverse_transform(
        [y.iloc[0]]
    )[0]

    result = engine.predict_cicids(
        sample
    )

    print("\nRESULT")
    print("-" * 70)

    print(
        f"Actual:            {actual_label}"
    )

    print(
        f"Prediction:        {result['prediction']}"
    )

    print(
        f"Confidence:        "
        f"{result['confidence']:.6f}"
    )

    print(
        f"Attack Probability:"
        f" {result['attack_probability']:.6f}"
    )

    print(
        f"Risk Score:        "
        f"{result['risk_score']}/100"
    )

    print(
        f"Severity:          "
        f"{result['severity']}"
    )

    print(
        f"Is Attack:         "
        f"{result['is_attack']}"
    )

    print("\n✓ CICIDS prediction successful")


# ============================================================
# NSL-KDD TEST
# ============================================================

def test_nsl_kdd(engine):

    print("\n")
    print("=" * 70)
    print("NSL-KDD REAL PREDICTION")
    print("=" * 70)

    data_path = (
        PROJECT_ROOT
        / "data"
        / "NSL-KDD"
        / "KDDTrain+.txt"
    )

    if not data_path.exists():

        print(
            "\nNSL-KDD dataset not found."
        )

        print(
            "Skipping NSL-KDD test."
        )

        return

    print(
        "\nLoading NSL-KDD..."
    )

    original_directory = os.getcwd()

    try:

        os.chdir(SRC_DIR)

        (
            X_train,
            X_test,
            y_train,
            y_test
        ) = load_and_preprocess(
            str(data_path)
        )

    finally:

        os.chdir(
            original_directory
        )

    sample = X_test.iloc[[0]]

    actual_label = (
        "NORMAL"
        if int(y_test.iloc[0]) == 0
        else "ATTACK"
    )

    result = engine.predict_nsl_kdd(
        sample
    )

    print("\nRESULT")
    print("-" * 70)

    print(
        f"Actual:            {actual_label}"
    )

    print(
        f"Prediction:        {result['prediction']}"
    )

    print(
        f"Confidence:        "
        f"{result['confidence']:.6f}"
    )

    print(
        f"Attack Probability:"
        f" {result['attack_probability']:.6f}"
    )

    print(
        f"Risk Score:        "
        f"{result['risk_score']}/100"
    )

    print(
        f"Severity:          "
        f"{result['severity']}"
    )

    print(
        f"Is Attack:         "
        f"{result['is_attack']}"
    )

    print("\n✓ NSL-KDD prediction successful")


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("#" * 70)
    print(" NETWORK ANOMALY DETECTION")
    print(" PHASE 1 - REAL INFERENCE ENGINE")
    print("#" * 70)

    engine = NetworkPredictionEngine()

    test_cicids(engine)

    test_nsl_kdd(engine)

    print("\n")
    print("#" * 70)
    print(" PHASE 1 INFERENCE ENGINE COMPLETE")
    print("#" * 70)


if __name__ == "__main__":
    main()