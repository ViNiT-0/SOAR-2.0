import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import pickle
import os

DATA_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data.csv")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")

def train():
    print("[ML] Loading training data...")
    df = pd.read_csv(DATA_PATH)

    FEATURES = [
        "ip_reputation_score",
        "historical_alert_count",
        "is_internal_ip",
        "hour_of_day",
        "alert_frequency_spike",
        "geo_risk_score",
        "failed_login_ratio"
    ]

    X = df[FEATURES]
    y = df["is_false_positive"]

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(f"[ML] Training samples: {len(X_train)}")
    print(f"[ML] Testing samples:  {len(X_test)}")
    print("[ML] Training Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n[ML] ✅ Model Accuracy: {accuracy * 100:.2f}%")
    print("\n[ML] Classification Report:")
    print(classification_report(y_test, y_pred,
          target_names=["True Positive", "False Positive"]))

    print("[ML] Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"     True Positive  correctly identified: {cm[0][0]}")
    print(f"     False Positive correctly identified: {cm[1][1]}")
    print(f"     Missed threats:                      {cm[0][1]}")
    print(f"     False alarms:                        {cm[1][0]}")

    # Feature importance
    print("\n[ML] Feature Importance:")
    importances = model.feature_importances_
    for feat, imp in sorted(zip(FEATURES, importances), key=lambda x: -x[1]):
        bar = "█" * int(imp * 50)
        print(f"     {feat:<30} {bar} {imp:.3f}")

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "features": FEATURES}, f)

    print(f"\n[ML] Model saved to {MODEL_PATH}")
    return model

if __name__ == "__main__":
    train()
