from backend.predictor import NetworkPredictor
from src.nsl_kdd_analyzer import NSLKDDAnalyzer
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import numpy as np

p = NetworkPredictor()
a = NSLKDDAnalyzer(p)

df = a.load_file("data/NSL-KDD/KDDTest-21.txt").head(5000).copy()

X = a.extract_features(df)

results = p.predict_nsl_kdd_batch(X)

probs = np.array([
    r["attack_probability"]
    for r in results
])

y = np.array([
    0 if str(x).lower() == "normal" else 1
    for x in df["label"]
])

print("Actual:", dict(zip(*np.unique(y, return_counts=True))))
print()

print("Threshold | Accuracy | Precision | Recall | F1 | TN FP FN TP")
print("-" * 75)

thresholds = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50]

for t in thresholds:

    pred = (probs >= t).astype(int)

    cm = confusion_matrix(
        y,
        pred,
        labels=[0, 1]
    ).ravel()

    print(
        f"{t:9.2f} | "
        f"{accuracy_score(y, pred):.4f} | "
        f"{precision_score(y, pred, zero_division=0):.4f} | "
        f"{recall_score(y, pred, zero_division=0):.4f} | "
        f"{f1_score(y, pred, zero_division=0):.4f} | "
        f"{' '.join(map(str, cm))}"
    )
