"""
explainer.py — SHAP Explainability Engine (Lazy Load Version)

Uses SHAP (TreeExplainer) to compute feature contributions for XGBoost
predictions to provide transparent reasonings (XAI) for developers.
"""

import os
import joblib
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")

_model = None
_explainer = None

# Friendly UI feature display names
FEATURE_DISPLAY_NAMES = {
    "rule_id_enc": "Rule type match pattern",
    "cwe_id_enc": "CWE category match pattern",
    "is_string_concat": "Direct string concatenation",
    "is_parameterized_query": "Parameterized query usage",
    "has_sanitizer_nearby": "Nearby sanitization functions",
    "in_test_file": "Test/Mock file context",
    "is_in_vendor_or_generated_dir": "Vendor/Generated directory path",
    "taint_source_distance": "Taint flow distance (source-to-sink)",
    "function_complexity": "Function complexity",
    "code_snippet_length": "Code snippet length",
    "variable_name_entropy": "Variable name entropy",
    "is_user_input_direct": "Direct user input source",
    "has_type_validation": "Type validation checks",
    "is_third_party_lib_call": "Third-party library invocation",
    "same_finding_seen_before_count": "Historical finding count",
    "developer_dismissed_similar_before": "Past developer dismissals",
    "file_change_frequency": "Git file modification frequency",
    "is_authenticated_endpoint": "Authenticated endpoint",
}


def get_explainer():
    """Lazily load model and initialize TreeExplainer."""
    global _model, _explainer
    if _explainer is None:
        import shap
        _model = joblib.load(MODEL_PATH)
        _explainer = shap.TreeExplainer(_model)
    return _explainer


def explain_prediction_shap(X_row: pd.DataFrame) -> list:
    """
    Computes top-5 SHAP explanations for a single feature vector row.

    Args:
        X_row (pd.DataFrame): 1-row DataFrame containing all feature_cols.

    Returns:
        list of dict: [{"feature": str, "shap_value": float, "direction": "REAL" | "FALSE_POSITIVE"}]
    """
    expl = get_explainer()
    shap_values = expl.shap_values(X_row)

    # Resolve class-1 (REAL) values
    if isinstance(shap_values, list):
        values = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
    elif len(shap_values.shape) == 3:  # (n_samples, n_features, n_classes)
        values = shap_values[0, :, 1]
    elif len(shap_values.shape) == 2:  # (n_samples, n_features)
        values = shap_values[0]
    else:
        values = shap_values

    feature_names = X_row.columns.tolist()
    explanation = []

    for name, val in zip(feature_names, values):
        val = float(val)
        if abs(val) < 1e-5:
            continue
        display_name = FEATURE_DISPLAY_NAMES.get(name, name)
        direction = "REAL" if val > 0 else "FALSE_POSITIVE"
        explanation.append({
            "feature": display_name,
            "shap_value": round(val, 4),
            "direction": direction
        })

    # Sort by absolute SHAP value descending, take top 5
    explanation.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
    return explanation[:5]
