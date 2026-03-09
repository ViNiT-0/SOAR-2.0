import pickle
import os
import pandas as pd
from datetime import datetime

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")

def load_model():
    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)
    return data["model"], data["features"]

def predict_false_positive(
    ip_reputation_score,
    historical_alert_count,
    is_internal_ip,
    hour_of_day,
    alert_frequency_spike,
    geo_risk_score,
    failed_login_ratio
):
    """
    Predicts whether an alert is a false positive.
    Returns a dict with probability and reasoning.
    """
    model, features = load_model()

    feature_vector = pd.DataFrame([[
        ip_reputation_score,
        historical_alert_count,
        is_internal_ip,
        hour_of_day,
        alert_frequency_spike,
        geo_risk_score,
        failed_login_ratio
    ]], columns=features)

    # Get probability of false positive (class 1)
    proba = model.predict_proba(feature_vector)[0]
    fp_probability = round(proba[1] * 100, 1)
    tp_probability = round(proba[0] * 100, 1)

    # Determine confidence label
    if fp_probability >= 80:
        label = "LIKELY FALSE POSITIVE"
        action = "AUTO-DISMISS"
        color  = "#36a64f"
    elif fp_probability >= 50:
        label = "UNCERTAIN"
        action = "REVIEW RECOMMENDED"
        color  = "#ff9900"
    else:
        label = "LIKELY REAL THREAT"
        action = "IMMEDIATE ACTION"
        color  = "#ff0000"

    # Build human readable reasoning
    reasons = []
    if is_internal_ip:
        reasons.append("Internal IP (+FP)")
    if ip_reputation_score > 0.5:
        reasons.append("High VT reputation (+TP)")
    if historical_alert_count > 10:
        reasons.append("Repeat alerter (+FP)")
    if geo_risk_score > 0.7:
        reasons.append("High risk country (+TP)")
    if failed_login_ratio > 0.7:
        reasons.append("High failure ratio (+TP)")
    if 9 <= hour_of_day <= 17:
        reasons.append("Business hours (+FP)")

    return {
        "fp_probability":  fp_probability,
        "tp_probability":  tp_probability,
        "label":           label,
        "action":          action,
        "color":           color,
        "reasons":         reasons
    }

def format_fp_bar(fp_probability):
    """Visual progress bar for FP probability."""
    filled = int(fp_probability / 5)
    empty  = 20 - filled
    return f"[{'█' * filled}{'░' * empty}] {fp_probability}%"

if __name__ == "__main__":
    print("=" * 55)
    print("TEST 1: Obvious real attack")
    print("=" * 55)
    result = predict_false_positive(
        ip_reputation_score    = 0.85,
        historical_alert_count = 1,
        is_internal_ip         = 0,
        hour_of_day            = 3,
        alert_frequency_spike  = 1,
        geo_risk_score         = 0.9,
        failed_login_ratio     = 0.95
    )
    print(f"FP Probability: {format_fp_bar(result['fp_probability'])}")
    print(f"Label:          {result['label']}")
    print(f"Action:         {result['action']}")
    print(f"Reasons:        {', '.join(result['reasons'])}")

    print("\n" + "=" * 55)
    print("TEST 2: Obvious false positive")
    print("=" * 55)
    result2 = predict_false_positive(
        ip_reputation_score    = 0.05,
        historical_alert_count = 30,
        is_internal_ip         = 1,
        hour_of_day            = 10,
        alert_frequency_spike  = 0,
        geo_risk_score         = 0.1,
        failed_login_ratio     = 0.1
    )
    print(f"FP Probability: {format_fp_bar(result2['fp_probability'])}")
    print(f"Label:          {result2['label']}")
    print(f"Action:         {result2['action']}")
    print(f"Reasons:        {', '.join(result2['reasons'])}")
