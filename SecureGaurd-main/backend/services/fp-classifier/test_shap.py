"""
test_shap.py — Unit tests for SHAP Explainability Engine.

Run:
    python -m unittest test_shap -v
"""

import os
import sys
import unittest
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from explainer import explain_prediction_shap
from predict import predict_finding


class TestShapExplainability(unittest.TestCase):
    """Test the SHAP TreeExplainer feature explanation logic."""

    def setUp(self):
        # Create a sample valid finding
        self.finding = {
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

    def test_explain_prediction_shap_structure(self):
        """Should return a list of top-5 sorted SHAP explanations with correct keys."""
        X_row = pd.DataFrame([self.finding.copy()])
        # Fill rule_id_enc and cwe_id_enc just like in predict_finding
        X_row["rule_id_enc"] = 0
        X_row["cwe_id_enc"] = 0
        
        # Ensure only the 18 expected feature columns are present
        from predict import feature_cols
        X_row = X_row[feature_cols]

        explanation = explain_prediction_shap(X_row)

        self.assertIsInstance(explanation, list)
        self.assertLessEqual(len(explanation), 5)

        for item in explanation:
            self.assertIn("feature", item)
            self.assertIn("shap_value", item)
            self.assertIn("direction", item)
            self.assertIn(item["direction"], ["REAL", "FALSE_POSITIVE"])
            self.assertIsInstance(item["shap_value"], float)

        # Check sorting: absolute shap values should be descending
        for i in range(len(explanation) - 1):
            self.assertGreaterEqual(
                abs(explanation[i]["shap_value"]),
                abs(explanation[i+1]["shap_value"]),
                "SHAP explanations are not sorted by absolute contribution descending"
            )

    def test_predict_finding_with_explanation(self):
        """predict_finding should include explanation list when include_explanation=True."""
        result = predict_finding(self.finding, include_explanation=True)
        self.assertIn("explanation", result)
        self.assertIsInstance(result["explanation"], list)
        self.assertGreater(len(result["explanation"]), 0)

        # Check that top features are present
        features_in_exp = [item["feature"] for item in result["explanation"]]
        self.assertLessEqual(len(features_in_exp), 5)

    def test_predict_finding_without_explanation(self):
        """predict_finding should NOT include explanation list when include_explanation=False."""
        result = predict_finding(self.finding, include_explanation=False)
        self.assertNotIn("explanation", result)


if __name__ == "__main__":
    unittest.main()
