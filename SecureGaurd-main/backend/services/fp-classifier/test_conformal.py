"""
test_conformal.py — Unit tests for conformal calibration and threshold integration.

Run:
    python -m pytest test_conformal.py -v
    OR
    python -m unittest test_conformal -v
"""

import os
import sys
import json
import unittest
import tempfile
import numpy as np

# Ensure the classifier directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conformal_calibration import (
    compute_nonconformity_scores,
    compute_threshold_from_scores,
)


class TestNonconformityScores(unittest.TestCase):
    """Test the nonconformity score computation logic."""

    def test_perfect_real_prediction(self):
        """If model predicts REAL with prob=0.95 and true label is REAL(1),
        nonconformity score should be 1 - 0.95 = 0.05 (low = correct)."""
        y_true = np.array([1])
        y_proba = np.array([0.95])
        scores = compute_nonconformity_scores(y_true, y_proba)
        self.assertAlmostEqual(scores[0], 0.05, places=5)

    def test_perfect_fp_prediction(self):
        """If model predicts FP with prob=0.1 (low REAL prob) and true label is FP(0),
        nonconformity score should be 0.1 (low = correct)."""
        y_true = np.array([0])
        y_proba = np.array([0.1])
        scores = compute_nonconformity_scores(y_true, y_proba)
        self.assertAlmostEqual(scores[0], 0.1, places=5)

    def test_wrong_real_prediction(self):
        """If model predicts REAL with prob=0.2 and true label is REAL(1),
        nonconformity score should be 1 - 0.2 = 0.8 (high = wrong)."""
        y_true = np.array([1])
        y_proba = np.array([0.2])
        scores = compute_nonconformity_scores(y_true, y_proba)
        self.assertAlmostEqual(scores[0], 0.8, places=5)

    def test_wrong_fp_prediction(self):
        """If model predicts REAL with prob=0.9 and true label is FP(0),
        nonconformity score should be 0.9 (high = wrong)."""
        y_true = np.array([0])
        y_proba = np.array([0.9])
        scores = compute_nonconformity_scores(y_true, y_proba)
        self.assertAlmostEqual(scores[0], 0.9, places=5)

    def test_batch_scores(self):
        """Test batch computation with mixed labels."""
        y_true = np.array([1, 0, 1, 0])
        y_proba = np.array([0.9, 0.1, 0.3, 0.8])
        scores = compute_nonconformity_scores(y_true, y_proba)
        expected = np.array([0.1, 0.1, 0.7, 0.8])
        np.testing.assert_array_almost_equal(scores, expected, decimal=5)


class TestThresholdComputation(unittest.TestCase):
    """Test threshold computation from nonconformity scores."""

    def test_basic_threshold(self):
        """Threshold from a simple set of scores."""
        # Scores: [0.1, 0.2, 0.3, 0.4, 0.5]
        # 95th percentile (alpha=0.05): q_hat = np.quantile([0.1,...,0.5], 0.95)
        # For 5 values, 0.95 quantile is approximately 0.48
        # threshold = 1 - 0.48 = 0.52
        scores = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
        threshold = compute_threshold_from_scores(scores, alpha=0.05)
        # Should be in the valid range [0.2, 0.7]
        self.assertGreaterEqual(threshold, 0.2)
        self.assertLessEqual(threshold, 0.7)

    def test_empty_scores_fallback(self):
        """Empty score array should return default threshold 0.4."""
        scores = np.array([])
        threshold = compute_threshold_from_scores(scores)
        self.assertEqual(threshold, 0.4)

    def test_threshold_clipping_low(self):
        """If computed threshold is below 0.2, it should be clipped to 0.2."""
        # All scores very high -> q_hat close to 1 -> threshold close to 0
        scores = np.array([0.95, 0.96, 0.97, 0.98, 0.99])
        threshold = compute_threshold_from_scores(scores, alpha=0.05)
        self.assertEqual(threshold, 0.2)  # Clipped to minimum

    def test_threshold_clipping_high(self):
        """If computed threshold is above 0.7, it should be clipped to 0.7."""
        # All scores very low -> q_hat close to 0 -> threshold close to 1
        scores = np.array([0.01, 0.02, 0.03, 0.04, 0.05])
        threshold = compute_threshold_from_scores(scores, alpha=0.05)
        self.assertEqual(threshold, 0.7)  # Clipped to maximum

    def test_threshold_range(self):
        """Threshold should always be in [0.2, 0.7] range regardless of input."""
        for _ in range(100):
            scores = np.random.uniform(0, 1, size=50)
            threshold = compute_threshold_from_scores(scores, alpha=0.05)
            self.assertGreaterEqual(threshold, 0.2)
            self.assertLessEqual(threshold, 0.7)


class TestGetThresholdForCWE(unittest.TestCase):
    """Test the per-CWE threshold lookup in predict.py."""

    def test_known_cwe_returns_specific_threshold(self):
        """A known CWE should return its specific threshold."""
        from predict import get_threshold_for_cwe, USE_CONFORMAL, CONFORMAL_PER_CWE
        if not USE_CONFORMAL:
            self.skipTest("Conformal thresholds not loaded (thresholds.json missing)")

        # Pick the first available CWE
        if CONFORMAL_PER_CWE:
            cwe = list(CONFORMAL_PER_CWE.keys())[0]
            threshold = get_threshold_for_cwe(cwe)
            self.assertEqual(threshold, CONFORMAL_PER_CWE[cwe])

    def test_unknown_cwe_returns_default(self):
        """An unseen CWE should return the default conformal threshold."""
        from predict import get_threshold_for_cwe, USE_CONFORMAL, CONFORMAL_DEFAULT
        if not USE_CONFORMAL:
            self.skipTest("Conformal thresholds not loaded (thresholds.json missing)")

        threshold = get_threshold_for_cwe("CWE-99999")
        self.assertEqual(threshold, CONFORMAL_DEFAULT)

    def test_empty_cwe_returns_default(self):
        """Empty string CWE should return default threshold."""
        from predict import get_threshold_for_cwe, USE_CONFORMAL, CONFORMAL_DEFAULT, FIXED_THRESHOLD
        threshold = get_threshold_for_cwe("")
        if USE_CONFORMAL:
            self.assertEqual(threshold, CONFORMAL_DEFAULT)
        else:
            self.assertEqual(threshold, FIXED_THRESHOLD)


class TestPredictFindingIntegration(unittest.TestCase):
    """Integration test: predict_finding uses conformal thresholds correctly."""

    def test_predict_returns_required_fields(self):
        """predict_finding output must contain all required fields for backward compatibility."""
        from predict import predict_finding

        finding = {
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
        result = predict_finding(finding)

        # All required fields must exist (backward compatibility)
        self.assertIn("prediction", result)
        self.assertIn("confidence", result)
        self.assertIn("threshold_used", result)
        self.assertIn("explanations", result)
        self.assertIn("conformal_calibrated", result)

        # prediction must be one of two values
        self.assertIn(result["prediction"], ["REAL", "FALSE_POSITIVE"])

        # confidence must be between 0 and 1
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

        # threshold_used must be in valid range
        self.assertGreaterEqual(result["threshold_used"], 0.2)
        self.assertLessEqual(result["threshold_used"], 0.7)

    def test_cwe_89_uses_cwe_specific_threshold(self):
        """CWE-89 should use its specific threshold, not the fixed 0.4."""
        from predict import predict_finding, USE_CONFORMAL, CONFORMAL_PER_CWE

        if not USE_CONFORMAL:
            self.skipTest("Conformal thresholds not loaded")

        finding = {
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
        result = predict_finding(finding)

        expected_threshold = CONFORMAL_PER_CWE.get("CWE-89")
        if expected_threshold:
            self.assertAlmostEqual(result["threshold_used"], expected_threshold, places=3)


class TestCalibrationEndToEnd(unittest.TestCase):
    """End-to-end test: run calibration and verify output format."""

    def test_thresholds_json_exists_and_valid(self):
        """thresholds.json should exist and have the correct structure."""
        thresholds_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "thresholds.json"
        )
        self.assertTrue(os.path.exists(thresholds_path),
                        f"thresholds.json not found at {thresholds_path}")

        with open(thresholds_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Required keys
        self.assertIn("default", data)
        self.assertIn("per_cwe", data)
        self.assertIn("metadata", data)

        # Default threshold in valid range
        self.assertGreaterEqual(data["default"], 0.2)
        self.assertLessEqual(data["default"], 0.7)

        # All per-CWE thresholds in valid range
        for cwe, threshold in data["per_cwe"].items():
            self.assertGreaterEqual(threshold, 0.2,
                                    f"{cwe} threshold {threshold} below minimum 0.2")
            self.assertLessEqual(threshold, 0.7,
                                 f"{cwe} threshold {threshold} above maximum 0.7")

        # Metadata validation
        self.assertEqual(data["metadata"]["alpha"], 0.05)
        self.assertEqual(data["metadata"]["confidence_level"], "95%")
        self.assertGreater(data["metadata"]["calibration_samples"], 0)


if __name__ == "__main__":
    unittest.main()
