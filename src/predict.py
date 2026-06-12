import os
import joblib
import pandas as pd


print("=" * 50)
print("NETWORK ANOMALY DETECTION PREDICTION")
print("=" * 50)

print("\nChoose Dataset:")
print("1. NSL-KDD")
print("2. CICIDS2017")

choice = input("\nEnter choice (1 or 2): ")

if choice == "1":
    model_path = "../models/nsl-kdd_anomaly_model.pkl"
elif choice == "2":
    model_path = "../models/cicids_anomaly_model.pkl"
else:
    print("Invalid Choice!")
    exit()

csv_path = input("\nEnter CSV file path: ")

if not os.path.exists(csv_path):
    print("CSV file not found!")
    exit()

model = joblib.load(model_path)

df = pd.read_csv(csv_path)

predictions = model.predict(df)

df["Prediction"] = predictions
df["Prediction"] = df["Prediction"].map(
    {0: "Normal Traffic", 1: "Attack Detected"}
)

output_file = "predictions.csv"
df.to_csv(output_file, index=False)

print("\nPrediction Completed Successfully!")
print("Results saved as:", output_file)

print("\nFirst 10 Predictions:\n")
print(df[["Prediction"]].head(10))