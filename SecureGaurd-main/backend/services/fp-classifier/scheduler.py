"""
scheduler.py - Automated Retrain Loop for SecureGuard FP Classifier

Ye script background me chal ke:
  1. Har N ghante me collect_training_data.py chalata hai (naya feedback fetch karta hai)
  2. Phir retrain.py chalata hai (safety gate ke saath)
  3. Sab kuch scheduler.log me log hota hai

Run karo:
    python scheduler.py
"""

import os
import sys
import time
import subprocess
import schedule
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH  = os.path.abspath(os.path.join(BASE_DIR, "..", "..", ".env"))
LOG_FILE = os.path.join(BASE_DIR, "scheduler.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SCHEDULER] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("scheduler")

def load_env(path):
    env = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip().strip("'").strip('"')
    return env

env = load_env(ENV_PATH)
RETRAIN_HOURS = int(env.get("RETRAIN_SCHEDULE_HOURS", "24"))
MIN_FEEDBACK  = int(env.get("MIN_FEEDBACK_TO_RETRAIN", "100"))

def run_retrain_job():
    log.info("=" * 50)
    log.info("[RETRAIN] Starting scheduled retrain cycle...")

    # Step 1: Collect feedback data
    log.info("Step 1/2 -- Collecting training data from backend API...")
    collect_script = os.path.join(BASE_DIR, "collect_training_data.py")
    result = subprocess.run(
        [sys.executable, collect_script],
        capture_output=True, text=True, cwd=BASE_DIR
    )
    if result.returncode != 0:
        log.error(f"collect_training_data.py FAILED:\n{result.stderr}")
        log.warning("Retrain step skipped due to data collection failure.")
        return

    log.info(result.stdout.strip())

    # Step 2: Retrain
    log.info(f"Step 2/2 -- Running retrain.py (min threshold: {MIN_FEEDBACK})...")
    retrain_script = os.path.join(BASE_DIR, "retrain.py")
    result = subprocess.run(
        [sys.executable, retrain_script, "--threshold", str(MIN_FEEDBACK)],
        capture_output=True, text=True, cwd=BASE_DIR
    )
    log.info(result.stdout.strip())

    if result.returncode == 0:
        log.info("[OK] Retrain completed -- new model deployed!")
    elif result.returncode == 2:
        log.warning("[ROLLBACK] Safety gate triggered -- keeping previous model.")
    else:
        log.info(f"[SKIP] Retrain skipped (not enough new feedback). code={result.returncode}")

    log.info("=" * 50)

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("[SCHEDULER] SecureGuard Retrain Scheduler STARTING")
    log.info(f"   Config: Every {RETRAIN_HOURS}h | Min feedback items: {MIN_FEEDBACK}")
    log.info(f"   Log: {LOG_FILE}")
    log.info("=" * 60)

    log.info("Running initial retrain check on startup...")
    run_retrain_job()

    schedule.every(RETRAIN_HOURS).hours.do(run_retrain_job)
    log.info(f"[SCHEDULED] Next retrain check in {RETRAIN_HOURS} hours.")

    while True:
        schedule.run_pending()
        time.sleep(60)
