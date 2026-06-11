"""
Centralised settings loader using python-dotenv.
All secrets are sourced from .env or the host environment - never hardcoded.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _split_csv(value: str) -> list:
    """Split a comma-separated env value, dropping empty entries."""
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


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
    # Autoencoder uses a percentile of training reconstruction errors as the
    # raw-MSE threshold. The legacy AUTOENCODER_THRESHOLD env var (a normalised-
    # score cutoff) is no longer consulted - it was dead code.
    AUTOENCODER_THRESHOLD_PERCENTILE: float = float(
        os.getenv("AUTOENCODER_THRESHOLD_PERCENTILE", "95.0")
    )
    ENSEMBLE_VOTE_THRESHOLD: int = int(os.getenv("ENSEMBLE_VOTE_THRESHOLD", "2"))

    # HIDS
    # Log paths default empty so the engine doesn't try to tail Linux paths on
    # Windows (or vice versa). Set explicitly per host. Watch dirs ditto: the
    # previous default of `data,src` made the IDS alert on its own source edits
    # and self-DoS via the alert rate-limit.
    HIDS_LOG_PATHS: list = _split_csv(os.getenv("HIDS_LOG_PATHS", ""))
    HIDS_WATCH_DIRS: list = _split_csv(os.getenv("HIDS_WATCH_DIRS", ""))
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

    # Dashboard
    # Password gate for the dashboard; blank disables the login.
    DASHBOARD_PASSWORD: str = os.getenv("DASHBOARD_PASSWORD", "")
    DASHBOARD_DEMO_MODE: bool = os.getenv("DASHBOARD_DEMO_MODE", "false").lower() in (
        "1", "true", "yes", "on",
    )

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
