import pandas as pd
from explainer import explain_prediction_shap

X = pd.DataFrame([[0]*18], columns=[
    "rule_id_enc", "cwe_id_enc", "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint"
])

print("DataFrame constructed.")
print("Calling explain_prediction_shap...")
res = explain_prediction_shap(X)
print("Returned from explain_prediction_shap")
print(res)
