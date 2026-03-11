"""
Centralised settings loader using pydantic-settings pattern with python-dotenv.
All config is sourced from .env — never hardcode secrets.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Environment
    ENV: str = os.getenv("ENV", "development")

    # Capture
    CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "eth0")
    CAPTURE_MODE: str = os.getenv("CAPTURE_MODE", "pcap")
    PCAP_FILE: str = os.getenv("PCAP_FILE", "data/pcap/test.pcap")

    # Detection thresholds
    ANOMALY_THRESHOLD: float = float(os.getenv("ANOMALY_THRESHOLD", "0.7"))
    RF_CONFIDENCE_THRESHOLD: float = float(os.getenv("RF_CONFIDENCE_THRESHOLD", "0.8"))
    AUTOENCODER_THRESHOLD: float = float(os.getenv("AUTOENCODER_THRESHOLD", "0.85"))
    ENSEMBLE_VOTE_THRESHOLD: int = int(os.getenv("ENSEMBLE_VOTE_THRESHOLD", "2"))

    # HIDS
    HIDS_LOG_PATHS: list = os.getenv("HIDS_LOG_PATHS", "/var/log/auth.log").split(",")
    HIDS_WATCH_DIRS: list = os.getenv("HIDS_WATCH_DIRS", "/etc").split(",")
    BASELINE_FILE: str = os.getenv("BASELINE_FILE", "data/baselines/file_hashes.json")
    HIDS_POLL_INTERVAL: int = int(os.getenv("HIDS_POLL_INTERVAL", "30"))

    # Alerts
    ALERT_DEDUP_WINDOW: int = int(os.getenv("ALERT_DEDUP_WINDOW", "60"))
    ALERT_RATE_LIMIT: int = int(os.getenv("ALERT_RATE_LIMIT", "100"))
    DB_PATH: str = os.getenv("DB_PATH", "db/ids.sqlite")

    # Email
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")
    EMAIL_MIN_SEVERITY: str = os.getenv("EMAIL_MIN_SEVERITY", "HIGH")

    # Slack
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    SLACK_MIN_SEVERITY: str = os.getenv("SLACK_MIN_SEVERITY", "MEDIUM")

    # ML Models
    MODEL_DIR: str = os.getenv("MODEL_DIR", "src/ml/models")
    IF_MODEL_PATH: str = os.getenv("IF_MODEL_PATH", "src/ml/models/isolation_forest.joblib")
    RF_MODEL_PATH: str = os.getenv("RF_MODEL_PATH", "src/ml/models/random_forest.joblib")
    AE_MODEL_PATH: str = os.getenv("AE_MODEL_PATH", "src/ml/models/autoencoder.pt")
    SCALER_PATH: str = os.getenv("SCALER_PATH", "src/ml/models/scaler.joblib")

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/ids.log")

    @classmethod
    def ensure_dirs(cls):
        """Create required directories if missing."""
        dirs = [
            "data/raw", "data/processed", "data/pcap", "data/baselines",
            "db", "logs", "src/ml/models"
        ]
        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)

config = Config()
