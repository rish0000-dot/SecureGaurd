"""
conformal_calibration.py — Per-CWE Conformal Threshold Calibration

Split conformal prediction method use karke har CWE category ke liye
optimized classification threshold compute karta hai.

Fixed 0.4 threshold ki jagah, ye data-driven thresholds use hote hain
jo model ki actual per-category performance ke basis pe calibrate hote hain.

Run:
    python conformal_calibration.py

Output:
    thresholds.json — har CWE ke liye calibrated threshold + default fallback
"""

import os
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Configuration ─────────────────────────────────────────────────────────────
# alpha lower = zyada conservative, kam FP suppress honge
ALPHA = 0.05  # Target error rate (95% confidence)
MIN_GROUP_SIZE = 30  # too few samples for reliable per-CWE calibration
THRESHOLD_CLIP_MIN = 0.2  # Minimum allowed threshold
THRESHOLD_CLIP_MAX = 0.7  # Maximum allowed threshold
CALIBRATION_SPLIT = 0.3   # 30% of data reserved for calibration

# ─── File paths ────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
RULE_ENCODER_PATH = os.path.join(BASE_DIR, "rule_encoder.joblib")
CWE_ENCODER_PATH = os.path.join(BASE_DIR, "cwe_encoder.joblib")
DATA_PATH = os.path.join(BASE_DIR, "sample_findings.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "thresholds.json")

# ─── Feature columns (must match train.py / predict.py) ───────────────────────
FEATURE_COLS = [
    "rule_id_enc", "cwe_id_enc", "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]


def compute_nonconformity_scores(y_true, y_proba):
    """
    Nonconformity score = 1 - predicted probability of the TRUE class.

    If true label is REAL (1):       score = 1 - p    (p = prob of class 1)
    If true label is FP (0):         score = p        (= 1 - (1-p))

    Lower score = model was more confident and correct.
    Higher score = model was uncertain or wrong.
    """
    scores = np.where(
        y_true == 1,
        1.0 - y_proba,   # REAL: score = 1 - P(REAL)
        y_proba           # FP:   score = P(REAL) = 1 - P(FP)
    )
    return scores


def compute_threshold_from_scores(scores, alpha=ALPHA):
    """
    Compute the conformal threshold from nonconformity scores.

    q_hat = (1-alpha) quantile of scores
    threshold = 1 - q_hat

    This threshold ensures that when we predict REAL (p >= threshold),
    we have (1-alpha) coverage guarantee.
    """
    if len(scores) == 0:
        return 0.4  # fallback
    q_hat = np.quantile(scores, 1.0 - alpha)
    threshold = 1.0 - q_hat
    return float(np.clip(threshold, THRESHOLD_CLIP_MIN, THRESHOLD_CLIP_MAX))


def safe_encode(encoder, value):
    """Encoder me value nahi hai toh -1 return karo (unknown fallback)."""
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return -1


def run_calibration(data_path=None, model_path=None, output_path=None):
    """
    Main calibration function.

    Returns:
        dict: {"default": float, "per_cwe": {cwe_id: float, ...}, "metadata": {...}}
    """
    data_path = data_path or DATA_PATH
    model_path = model_path or MODEL_PATH
    output_path = output_path or OUTPUT_PATH

    # ─── 1. Load model and encoders ────────────────────────────────────────
    print("[Conformal] Loading model and encoders...")
    model = joblib.load(model_path)
    rule_encoder = joblib.load(RULE_ENCODER_PATH)
    cwe_encoder = joblib.load(CWE_ENCODER_PATH)

    # ─── 2. Load and prepare data ──────────────────────────────────────────
    print(f"[Conformal] Loading data from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"[Conformal] Loaded {len(df)} samples")

    # Encode categorical features
    df["rule_id_enc"] = df["rule_id"].apply(lambda x: safe_encode(rule_encoder, x))
    df["cwe_id_enc"] = df["cwe_id"].apply(lambda x: safe_encode(cwe_encoder, x))

    # ─── 3. Split: use a held-out calibration set ──────────────────────────
    # We split the data so calibration is done on unseen data (not training data)
    _, cal_df = train_test_split(
        df, test_size=CALIBRATION_SPLIT, random_state=42, stratify=df["label"]
    )
    print(f"[Conformal] Calibration set size: {len(cal_df)}")

    X_cal = cal_df[FEATURE_COLS]
    y_cal = cal_df["label"].values
    cwe_ids_cal = cal_df["cwe_id"].values

    # ─── 4. Get model probabilities on calibration set ─────────────────────
    y_proba = model.predict_proba(X_cal)[:, 1]  # P(REAL)

    # ─── 5. Compute overall nonconformity scores ──────────────────────────
    all_scores = compute_nonconformity_scores(y_cal, y_proba)
    default_threshold = compute_threshold_from_scores(all_scores)
    print(f"[Conformal] Default (global) threshold: {default_threshold:.4f}")

    # ─── 6. Compute per-CWE thresholds ────────────────────────────────────
    per_cwe = {}
    unique_cwes = np.unique(cwe_ids_cal)

    for cwe in unique_cwes:
        mask = cwe_ids_cal == cwe
        group_size = mask.sum()

        if group_size < MIN_GROUP_SIZE:
            # too few samples for reliable per-CWE calibration
            print(f"[Conformal] {cwe}: {group_size} samples (< {MIN_GROUP_SIZE}) -> using default threshold")
            per_cwe[cwe] = default_threshold
            continue

        group_scores = all_scores[mask]
        cwe_threshold = compute_threshold_from_scores(group_scores)
        per_cwe[cwe] = round(cwe_threshold, 4)
        print(f"[Conformal] {cwe}: {group_size} samples -> threshold = {cwe_threshold:.4f}")

    # ─── 7. Build output ──────────────────────────────────────────────────
    result = {
        "default": round(default_threshold, 4),
        "per_cwe": per_cwe,
        "metadata": {
            "alpha": ALPHA,
            "confidence_level": f"{(1 - ALPHA) * 100:.0f}%",
            "calibration_samples": len(cal_df),
            "min_group_size": MIN_GROUP_SIZE,
            "threshold_range": [THRESHOLD_CLIP_MIN, THRESHOLD_CLIP_MAX],
            "cwe_groups_calibrated": len([c for c in per_cwe if per_cwe[c] != default_threshold]),
            "cwe_groups_defaulted": len([c for c in per_cwe if per_cwe[c] == default_threshold]),
        }
    }

    # ─── 8. Write to file ─────────────────────────────────────────────────
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"\n[Conformal] Thresholds saved to {output_path}")
    print(f"[Conformal] Summary: default={result['default']}, per_cwe={per_cwe}")

    return result


if __name__ == "__main__":
    run_calibration()
