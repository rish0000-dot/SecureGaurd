# SecureGuard — False Positive Suppression Classifier

Working end-to-end classifier jo SAST findings ko REAL vs FALSE_POSITIVE classify karta hai.
Current version: 8000 synthetic samples pe trained, 18 features, GridSearch-tuned.

**Current performance (synthetic data pe):** Accuracy 90.5% | Precision 86.3% | Recall 83.6%

## Files

| File | Kaam |
|---|---|
| `generate_sample_data.py` | Demo/synthetic labeled data banata hai (8000 findings, 18 features) |
| `train.py` | Model train + hyperparameter tune + evaluate karta hai (XGBoost + GridSearch) |
| `predict.py` | Trained model se ek finding pe prediction leta hai |
| `service.py` | **FastAPI microservice** — HTTP API se model serve karta hai |
| `node_integration_example.js` | Aapke Node.js backend me kaise call karna hai, uska example |
| `data/sample_findings.csv` | Generated synthetic dataset |
| `model.joblib`, `rule_encoder.joblib`, `cwe_encoder.joblib` | Trained model + encoders |

## Setup & Run

```bash
pip install pandas scikit-learn xgboost joblib fastapi uvicorn

# 1. Data generate karo
python3 generate_sample_data.py

# 2. Model train karo (metrics print honge)
python3 train.py

# 3. Quick test (terminal me)
python3 predict.py

# 4. API service start karo (production integration ke liye)
uvicorn service:app --host 0.0.0.0 --port 8001
```

## Apne Project Me Integrate Karne Ke Steps

1. `service.py` ko apne backend infra pe deploy karo (Docker container ya separate Python service ke roop me), port 8001 pe expose karo
2. `node_integration_example.js` ko dekho — apne Express/Fastify scan-pipeline code me `filterFalsePositives()` function jaisa kuch call karo
3. Environment variable `FP_CLASSIFIER_URL` set karo agar service kisi alag host/container pe chal rahi ho
4. `/classify/batch` endpoint use karo (ek scan ke saare findings ek saath bhejo) — `/classify` single-finding ke liye hai, latency zyada lagegi bulk ke liye

## Real Data Pe Switch Karne Ke Steps (accuracy production-grade banane ke liye)

Synthetic data sirf demo/pipeline dikhane ke liye hai. Real accuracy in steps se aayegi:

### 1. Real labeled data collect karo
- **OWASP Benchmark** / **Juliet Test Suite (NIST)** / **SARD** — pre-labeled public datasets
- Apne test repos pe Semgrep chalao, findings ko manually label karo (kam se kam 1000-2000 se shuru karo)
- Production launch ke baad: developer ke "Ignore"/"Confirm" clicks ko automatically label bana lo (best long-term source — PRD ka "allowlist" feature isi se connect karo)

### 2. Real feature extraction banao
Abhi features synthetic hain. Real me code se ye nikalne honge:
- **Semgrep JSON output** se `rule_id`, `cwe_id`, `file_path`, line numbers milte hain seedhe
- **tree-sitter** (AST parser) se: string concatenation detect karna, sanitizer function nearby hai ya nahi, taint distance
- `radon` (Python) ya `lizard` (multi-language) se cyclomatic complexity
- Git history se `file_change_frequency` aur `same_finding_seen_before_count` nikal sakte ho

### 3. Class imbalance handle karo
Agar real data me REAL vulnerabilities kam % hon (jo aksar hota hai), to `train.py` me XGBClassifier ko
`scale_pos_weight` parameter do:
```python
scale_pos_weight = (negative_class_count / positive_class_count)
```

### 4. Retraining loop set karo
Har hafte/mahine naya feedback data collect karke `train.py` dobara chalao — model behtar hota jayega time ke saath.

### 5. Threshold monitor karo
`predict.py` me `THRESHOLD = 0.4` set hai (0.5 se conservative — recall priority). Production data
aane ke baad ROC curve dekh ke isko fine-tune karo apne risk-tolerance ke hisaab se.
