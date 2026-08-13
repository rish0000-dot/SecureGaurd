"""
service.py — FastAPI microservice jo trained classifier ko HTTP API se serve karta hai

Ye wahi cheez hai jo aapka Node.js/Express backend call karega har SAST scan ke baad.

Run:
    pip install fastapi uvicorn
    uvicorn service:app --host 0.0.0.0 --port 8001

Test:
    curl -X POST http://localhost:8001/classify -H "Content-Type: application/json" -d '{
        "rule_id": "sqli-concat", "cwe_id": "CWE-89",
        "is_string_concat": 1, "is_parameterized_query": 0,
        "has_sanitizer_nearby": 0, "in_test_file": 0,
        "is_in_vendor_or_generated_dir": 0, "taint_source_distance": 2,
        "function_complexity": 14, "code_snippet_length": 90,
        "variable_name_entropy": 2.0, "is_user_input_direct": 1,
        "has_type_validation": 0, "is_third_party_lib_call": 0,
        "same_finding_seen_before_count": 1, "developer_dismissed_similar_before": 0,
        "file_change_frequency": 22, "is_authenticated_endpoint": 0
    }'
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from predict import predict_finding

app = FastAPI(title="SecureGuard FP Suppression Classifier")


class Finding(BaseModel):
    rule_id: str
    cwe_id: str
    is_string_concat: int
    is_parameterized_query: int
    has_sanitizer_nearby: int
    in_test_file: int
    is_in_vendor_or_generated_dir: int
    taint_source_distance: int
    function_complexity: int
    code_snippet_length: int
    variable_name_entropy: float
    is_user_input_direct: int
    has_type_validation: int
    is_third_party_lib_call: int
    same_finding_seen_before_count: int
    developer_dismissed_similar_before: int
    file_change_frequency: int
    is_authenticated_endpoint: int


class BatchRequest(BaseModel):
    findings: list[Finding]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/classify")
def classify(finding: Finding):
    """Ek single finding classify karo"""
    try:
        result = predict_finding(finding.model_dump())
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/classify/batch")
def classify_batch(request: BatchRequest):
    """Ek scan ke saare findings ek saath classify karo (recommended - kam network calls)"""
    results = []
    for finding in request.findings:
        try:
            results.append(predict_finding(finding.model_dump()))
        except Exception as e:
            results.append({"error": str(e)})
    return {"results": results}
