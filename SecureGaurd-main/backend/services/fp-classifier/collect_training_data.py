import os
import csv
import json
import urllib.request
import urllib.error

# Setup directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(os.path.dirname(BASE_DIR))
ENV_PATH = os.path.join(BACKEND_DIR, ".env")

# Define CSV files
SAMPLE_FINDINGS_CSV = os.path.join(BASE_DIR, "sample_findings.csv")
SYNTHETIC_FINDINGS_CSV = os.path.join(BASE_DIR, "synthetic_findings.csv")

def load_env(path):
    env = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    parts = line.split("=", 1)
                    k = parts[0].strip()
                    v = parts[1].strip().strip("'").strip('"')
                    env[k] = v
    return env

def main():
    print("[Data Collection] Loading configuration...")
    env = load_env(ENV_PATH)
    
    port = env.get("PORT", "5000")
    backend_url = f"http://localhost:{port}"
    api_key = env.get("CLASSIFIER_API_KEY", "")
    
    # 1. Back up sample_findings.csv to synthetic_findings.csv if not exists
    if os.path.exists(SAMPLE_FINDINGS_CSV) and not os.path.exists(SYNTHETIC_FINDINGS_CSV):
        print(f"[Data Collection] Backing up base findings to {SYNTHETIC_FINDINGS_CSV}...")
        os.rename(SAMPLE_FINDINGS_CSV, SYNTHETIC_FINDINGS_CSV)
    
    # Ensure synthetic seed exists
    if not os.path.exists(SYNTHETIC_FINDINGS_CSV):
        print(f"[Data Collection ERROR] Base dataset {SYNTHETIC_FINDINGS_CSV} not found!")
        return

    # 2. Fetch feedback from backend API
    url = f"{backend_url}/api/scans/export-feedback"
    headers = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["X-SecureGuard-Key"] = api_key

    print(f"[Data Collection] Fetching labeled findings from {url}...")
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            feedback_data = json.loads(response.read().decode("utf-8"))
            print(f"[Data Collection] Successfully retrieved {len(feedback_data)} feedback entries.")
    except urllib.error.URLError as e:
        print(f"[Data Collection ERROR] Failed to connect to backend: {e}")
        print("[Data Collection] Defaulting to synthetic findings only.")
        feedback_data = []

    # 3. Read base synthetic findings
    synthetic_rows = []
    with open(SYNTHETIC_FINDINGS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            synthetic_rows.append(row)

    # 4. Combine findings
    print(f"[Data Collection] Combining {len(synthetic_rows)} synthetic samples with {len(feedback_data)} feedback samples...")
    
    combined_rows = list(synthetic_rows)
    for entry in feedback_data:
        # Construct clean row matching CSV headers
        row = {}
        for field in fieldnames:
            row[field] = str(entry.get(field, ""))
        combined_rows.append(row)

    # 5. Overwrite sample_findings.csv
    with open(SAMPLE_FINDINGS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(combined_rows)

    print(f"[Data Collection] Successfully wrote {len(combined_rows)} total samples to {SAMPLE_FINDINGS_CSV}!")

if __name__ == "__main__":
    main()
