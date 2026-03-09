import pandas as pd
import numpy as np
import random
import os

random.seed(42)
np.random.seed(42)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data.csv")

def generate_dataset(n_samples=2000):
    data = []

    for i in range(n_samples):
        # --- TRUE POSITIVES (real attacks) label=0 ---
        if i < n_samples // 2:
            ip_reputation    = round(random.uniform(0.4, 1.0), 2)
            hist_alert_count = random.randint(0, 5)
            is_internal      = 0
            hour_of_day      = random.choice([0,1,2,3,4,22,23] + list(range(0,24)))
            freq_spike       = random.choice([1, 1, 1, 0])
            geo_risk         = round(random.uniform(0.5, 1.0), 2)
            failed_ratio     = round(random.uniform(0.7, 1.0), 2)
            label            = 0  # Real threat

        # --- FALSE POSITIVES (noise/benign) label=1 ---
        else:
            ip_reputation    = round(random.uniform(0.0, 0.4), 2)
            hist_alert_count = random.randint(5, 50)
            is_internal      = random.choice([1, 1, 1, 0])
            hour_of_day      = random.randint(8, 18)
            freq_spike       = 0
            geo_risk         = round(random.uniform(0.0, 0.4), 2)
            failed_ratio     = round(random.uniform(0.0, 0.4), 2)
            label            = 1  # False positive

        # Add some noise to make it realistic
        if random.random() < 0.1:
            label = 1 - label

        data.append({
            "ip_reputation_score":   ip_reputation,
            "historical_alert_count": hist_alert_count,
            "is_internal_ip":        is_internal,
            "hour_of_day":           hour_of_day,
            "alert_frequency_spike": freq_spike,
            "geo_risk_score":        geo_risk,
            "failed_login_ratio":    failed_ratio,
            "is_false_positive":     label
        })

    df = pd.DataFrame(data)
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"[ML] Generated {n_samples} training samples")
    print(f"[ML] Saved to {OUTPUT_PATH}")
    print(f"[ML] True Positives:  {len(df[df['is_false_positive']==0])}")
    print(f"[ML] False Positives: {len(df[df['is_false_positive']==1])}")
    print(f"\nSample rows:")
    print(df.head(5).to_string())
    return df

if __name__ == "__main__":
    generate_dataset()
