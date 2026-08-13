"""
predict.py — Trained model ko use karke naye SAST findings pe prediction lena

Real project me: ye logic FastAPI microservice ke andar hai (service.py dekho),
jise aapka Node.js backend REST call karega har scan ke baad.

Run: python3 predict.py
"""

import joblib
import pandas as pd

model = joblib.load("/home/claude/fp_classifier/model.joblib")
rule_encoder = joblib.load("/home/claude/fp_classifier/rule_encoder.joblib")
cwe_encoder = joblib.load("/home/claude/fp_classifier/cwe_encoder.joblib")

# NOTE: ye list generate_sample_data.py / train.py ke feature_cols se exactly match honi chahiye
feature_cols = [
    "rule_id_enc", "cwe_id_enc", "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]

# Unseen rule_id/cwe_id encoder me na ho to crash na ho, isliye safe fallback
def safe_encode(encoder, value):
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return -1  # unknown category ke liye fallback code


def predict_finding(finding: dict) -> dict:
    """
    finding: SAST scan se aaya raw finding (dict), jisme upar wale saare
    feature_cols (rule_id, cwe_id ke alawa) ke raw values hone chahiye.

    Example finding dict neeche __main__ block me hai.
    """
    row = finding.copy()
    row["rule_id_enc"] = safe_encode(rule_encoder, row["rule_id"])
    row["cwe_id_enc"] = safe_encode(cwe_encoder, row["cwe_id"])

    X = pd.DataFrame([row])[feature_cols]
    proba = model.predict_proba(X)[0][1]  # probability of being REAL

    # Security-conservative threshold: 0.4 (0.5 ki jagah), taaki real vuln miss na ho
    THRESHOLD = 0.4
    label = "REAL" if proba >= THRESHOLD else "FALSE_POSITIVE"

    return {
        "prediction": label,
        "confidence": round(float(proba), 3),
        "threshold_used": THRESHOLD,
    }


if __name__ == "__main__":
    # Example 1: likely REAL vulnerability
    example_1 = {
        "rule_id": "sqli-concat", "cwe_id": "CWE-89",
        "is_string_concat": 1, "is_parameterized_query": 0,
        "has_sanitizer_nearby": 0, "in_test_file": 0,
        "is_in_vendor_or_generated_dir": 0, "taint_source_distance": 2,
        "function_complexity": 14, "code_snippet_length": 90,
        "variable_name_entropy": 2.0, "is_user_input_direct": 1,
        "has_type_validation": 0, "is_third_party_lib_call": 0,
        "same_finding_seen_before_count": 1, "developer_dismissed_similar_before": 0,
        "file_change_frequency": 22, "is_authenticated_endpoint": 0,
    }

    # Example 2: likely FALSE POSITIVE
    example_2 = {
        "rule_id": "sqli-concat", "cwe_id": "CWE-89",
        "is_string_concat": 0, "is_parameterized_query": 1,
        "has_sanitizer_nearby": 1, "in_test_file": 1,
        "is_in_vendor_or_generated_dir": 0, "taint_source_distance": 15,
        "function_complexity": 3, "code_snippet_length": 40,
        "variable_name_entropy": 2.5, "is_user_input_direct": 0,
        "has_type_validation": 1, "is_third_party_lib_call": 1,
        "same_finding_seen_before_count": 8, "developer_dismissed_similar_before": 1,
        "file_change_frequency": 2, "is_authenticated_endpoint": 1,
    }

    print("Example 1 (expected REAL):", predict_finding(example_1))
    print("Example 2 (expected FALSE_POSITIVE):", predict_finding(example_2))
