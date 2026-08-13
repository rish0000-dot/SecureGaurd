# SecureGuard FP Classifier — On-Call Troubleshooting Guide

This document is for engineers who need to diagnose and fix issues with the FP Classifier service in production. Follow these steps in order.

---

## Quick Reference

| Problem | First Step |
|---|---|
| Classifier service is down | See [Section 1](#1-classifier-service-is-down) |
| All findings showing as REAL (no filtering) | See [Section 2](#2-no-false-positive-filtering-happening) |
| Scan is slow / timing out | See [Section 3](#3-scan-is-slow-or-timing-out) |
| Model predicting poorly / wrong results | See [Section 4](#4-model-predictions-seem-wrong) |
| Need to roll back to an older model | See [Section 5](#5-rollback-to-a-previous-model) |
| Need to retrain the model | See [Section 6](#6-retraining-the-model) |

---

## 1. Classifier Service Is Down

### Symptoms
- Backend logs show: `[ML Service Error] Failed to reach FP classifier`
- Dashboard scans complete, but all findings remain as REAL (no suppression)

### Step-by-step

**Step 1 — Confirm service is down:**
```bash
curl http://localhost:8001/health
# Expected: {"status": "ok"}
# If connection refused → service is not running
```

**Step 2 — Start the service:**
```bash
cd backend/services/fp-classifier
uvicorn service:app --host 0.0.0.0 --port 8001 --workers 4
```

**Step 3 — If service crashes on start, check for model file errors:**
```bash
# In the fp-classifier directory, verify model files exist
ls -lh model.joblib rule_encoder.joblib cwe_encoder.joblib

# If any are missing, restore from archive
ls models_archive/
cp models_archive/model_<latest_timestamp>.joblib model.joblib
cp models_archive/rule_encoder_<latest_timestamp>.joblib rule_encoder.joblib
cp models_archive/cwe_encoder_<latest_timestamp>.joblib cwe_encoder.joblib
```

**Step 4 — Check Python environment:**
```bash
pip install -r requirements.txt
python -c "import xgboost, fastapi, sklearn; print('All deps OK')"
```

> [!NOTE]
> The backend will continue operating in fail-open mode even while the classifier is down — all findings default to REAL. No data is lost. Fix the classifier and re-trigger a scan to get filtered results.

---

## 2. No False-Positive Filtering Happening

### Symptoms
- Classifier service is running (`/health` returns OK)
- But scans still return all findings as REAL

### Step-by-step

**Step 1 — Verify the API Key is correctly configured:**
```bash
# In backend/.env — confirm this key exists
grep CLASSIFIER_API_KEY backend/.env

# Test the endpoint manually with the key
curl -X POST http://localhost:8001/classify/batch \
  -H "Content-Type: application/json" \
  -H "X-SecureGuard-Key: sg-internal-fp-classifier-key-change-me" \
  -d '{"findings":[{"rule_id":"sqli-concat","cwe_id":"CWE-89","is_string_concat":1,"is_parameterized_query":0,"has_sanitizer_nearby":0,"in_test_file":0,"is_in_vendor_or_generated_dir":0,"taint_source_distance":2,"function_complexity":5,"code_snippet_length":80,"variable_name_entropy":2.5,"is_user_input_direct":1,"has_type_validation":0,"is_third_party_lib_call":0,"same_finding_seen_before_count":0,"developer_dismissed_similar_before":0,"file_change_frequency":0,"is_authenticated_endpoint":0}]}'
```

Expected response:
```json
{"results": [{"prediction": "REAL", "confidence": 0.85}]}
```

If you get `401 Unauthorized` — the API key in `.env` and the key in the curl request don't match.

**Step 2 — Check if scanned files are actually SAST rules (not SEC-*):**
> [!IMPORTANT]
> `SEC-001`, `SEC-002`, `SEC-003` (hardcoded secrets) are **intentionally never filtered**. They always show as REAL. This is correct behavior, not a bug.

**Step 3 — Check backend logs for ML errors:**
```bash
# In the terminal running the Node.js backend, look for:
# [ML Service Error] Classifier returned status XXX
# [ML Service Error] Failed to reach FP classifier
```

---

## 3. Scan Is Slow or Timing Out

### Symptoms
- Scans take > 30 seconds
- Backend logs show timeout warnings

### Step-by-step

**Step 1 — Check current timeout setting:**
The timeout per 50-finding batch is **5 seconds** (hardcoded in `backend/routes/scans.js`).

**Step 2 — Check classifier load:**
```bash
curl -H "X-SecureGuard-Key: sg-internal-fp-classifier-key-change-me" \
  http://localhost:8001/metrics
```

**Step 3 — Scale up workers for better throughput:**
```bash
# Restart service with more workers
uvicorn service:app --host 0.0.0.0 --port 8001 --workers 8
```

**Step 4 — If a single large repo causes persistent timeouts:**
The scan will still complete — timed-out batches default to REAL. Investigate if the model itself is slow (could indicate a model file corruption — re-deploy from archive).

---

## 4. Model Predictions Seem Wrong

### Symptoms
- Real vulnerabilities are being suppressed (false negatives)
- Too many false alerts that should be filtered

### Step-by-step

**Step 1 — Check current model metadata:**
```bash
cat backend/services/fp-classifier/model_metadata.json
```

**Step 2 — Review recent prediction logs:**
```bash
tail -50 backend/services/fp-classifier/predictions.log
```

**Step 3 — Check metrics endpoint for drift:**
```bash
curl -H "X-SecureGuard-Key: sg-internal-fp-classifier-key-change-me" \
  http://localhost:8001/metrics
```

If `average_confidence` drops below 0.65 or `real_percentage` is wildly off-baseline — the model may have degraded. Consider retraining (see Section 6).

**Step 4 — For immediate stabilization, roll back (see Section 5).**

---

## 5. Rollback to a Previous Model

### When to roll back
- New model was deployed but `real_percentage` or confidence metrics look wrong
- A recently deployed model is producing unexpected predictions

### Step-by-step

```bash
cd backend/services/fp-classifier

# List available archived model versions
ls models_archive/

# Example output:
# model_20260710_183000.joblib
# model_20260715_120000.joblib  ← this is the one to roll back to

# Roll back (replace active files with archived version)
$VERSION = "20260710_183000"  # ← change this timestamp
copy models_archive\model_$VERSION.joblib model.joblib
copy models_archive\rule_encoder_$VERSION.joblib rule_encoder.joblib
copy models_archive\cwe_encoder_$VERSION.joblib cwe_encoder.joblib
```

**Restart the service after rollback:**
```bash
# Stop current service (Ctrl+C or kill the process)
# Then restart:
uvicorn service:app --host 0.0.0.0 --port 8001 --workers 4
```

**Verify rollback worked:**
```bash
curl http://localhost:8001/health
# Then trigger a test scan from the dashboard
```

---

## 6. Retraining the Model

### When to retrain
- Accumulated 500+ new developer feedback labels (Ignore/Confirm/Apply Fix)
- Model drift detected in prediction logs
- Added a new SAST rule type to `securityScanner.js`

### Step-by-step

```bash
cd backend/services/fp-classifier

# Step 1: Collect labeled feedback from the database and mix with synthetic base
python collect_training_data.py
# Expected output: "Successfully wrote XXXX total samples to sample_findings.csv!"

# Step 2: Run retraining (with 500-sample threshold check)
python retrain.py

# If you want to force training with fewer than 500 new samples (testing):
python retrain.py --force

# Step 3: Verify the output
cat model_metadata.json
# Check: metrics.recall should be >= 0.82 and metrics.accuracy >= 0.88

# Step 4: Restart the service to load the new model
# The model files (model.joblib etc.) are already updated by retrain.py
# Just restart uvicorn to pick up the changes:
uvicorn service:app --host 0.0.0.0 --port 8001 --workers 4
```

> [!CAUTION]
> If `retrain.py` outputs `🚨 [ROLLBACK TRIGGERED]` — the new model performed worse than the current one. The old model is still active. Investigate the training data quality (check for label noise in feedback, or run with `--force` on a cleaned subset).

---

## 7. Adding a New SAST Rule Type

When a new rule is added to `securityScanner.js`:

1. **Add to `RULE_MAP`** in `backend/routes/scans.js`:
   ```js
   'NEW-001': 'new-rule-category-name',
   ```

2. **Add training samples** for the new rule in `sample_findings.csv` (or generate via `generate_sample_data.py`).

3. **Retrain the model** following Section 6 above.

4. **Verify** the new rule is correctly classified by the model in a test scan.

---

## 8. Checking All System Logs

```bash
# Node.js backend logs (look for [ML Service Error])
# These appear in the terminal where you ran: node index.js / npm run dev

# Python classifier logs (live request logs)
tail -f backend/services/fp-classifier/predictions.log

# Model training/retraining output is printed to console
```
