import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_DIR))

from prediction_engine import NetworkPredictionEngine


def main():

    print("\n" + "=" * 70)
    print("NETWORK ANOMALY DETECTION - ENGINE TEST")
    print("=" * 70)

    engine = NetworkPredictionEngine()

    print("\nMODEL INFORMATION")
    print("-" * 70)

    info = engine.get_model_info()

    for dataset, details in info.items():

        print(f"\n{dataset.upper()}")

        for key, value in details.items():
            print(f"{key}: {value}")

    # ---------------------------------------------------------
    # Test invalid input detection
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("INPUT VALIDATION TEST")
    print("=" * 70)

    try:

        engine.predict_cicids([1, 2, 3])

    except ValueError as error:

        print("✓ Invalid CICIDS input correctly rejected")
        print(f"  Reason: {error}")

    try:

        engine.predict_nsl_kdd([1, 2, 3])

    except ValueError as error:

        print("✓ Invalid NSL-KDD input correctly rejected")
        print(f"  Reason: {error}")

    print("\n" + "=" * 70)
    print("PREDICTION ENGINE FOUNDATION TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()