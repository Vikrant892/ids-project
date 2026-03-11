"""
Alert Notifiers.
Three channels:
  1. Console (always active — structured log)
  2. Email (SMTP, configurable min severity)
  3. Slack webhook (configurable min severity)

Each notifier is a callable: notifier(alert_dict) -> None
"""
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import requests
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_COLORS = {
    "LOW":      "#36a64f",   # green
    "MEDIUM":   "#f4bf00",   # yellow
    "HIGH":     "#d9534f",   # red
    "CRITICAL": "#7b1a1a",   # dark red
}


def _severity_meets_threshold(alert_severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(alert_severity, 0) >= SEVERITY_RANK.get(threshold, 0)


def console_notifier(alert: dict):
    """Always-active: pretty-print to stdout."""
    sev = alert.get("severity", "LOW")
    desc = alert.get("description", "")[:120]
    src = alert.get("src_ip", "-")
    dst = alert.get("dst_ip", "-")
    ts  = alert.get("timestamp", "-")
    print(
        f"[ALERT][{sev}] {ts} | {src} → {dst} | {desc}"
    )


def email_notifier(alert: dict):
    """Send email for alerts at or above EMAIL_MIN_SEVERITY."""
    if not config.SMTP_USER or not config.SMTP_PASSWORD:
        return
    if not _severity_meets_threshold(alert.get("severity", "LOW"), config.EMAIL_MIN_SEVERITY):
        return

    sev = alert.get("severity", "LOW")
    subject = f"[IDS {sev}] {alert.get('description', '')[:60]}"
    body = f"""
    <html><body>
    <h2 style="color:{SEVERITY_COLORS.get(sev,'#333')}">IDS Alert — {sev}</h2>
    <table>
      <tr><td><b>Timestamp:</b></td><td>{alert.get('timestamp','')}</td></tr>
      <tr><td><b>Type:</b></td><td>{alert.get('alert_type','')}</td></tr>
      <tr><td><b>Source IP:</b></td><td>{alert.get('src_ip','')}</td></tr>
      <tr><td><b>Destination IP:</b></td><td>{alert.get('dst_ip','')}</td></tr>
      <tr><td><b>Port:</b></td><td>{alert.get('dst_port','')}</td></tr>
      <tr><td><b>Description:</b></td><td>{alert.get('description','')}</td></tr>
      <tr><td><b>MITRE Tactic:</b></td><td>{alert.get('mitre_tactic','')}</td></tr>
      <tr><td><b>Confidence:</b></td><td>{alert.get('confidence','')}</td></tr>
    </table>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = config.SMTP_USER
    msg["To"]      = config.ALERT_EMAIL_TO
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.sendmail(config.SMTP_USER, config.ALERT_EMAIL_TO, msg.as_string())
        logger.info("email_alert_sent", to=config.ALERT_EMAIL_TO, severity=sev)
    except Exception as e:
        logger.error("email_send_failed", error=str(e))


def slack_notifier(alert: dict):
    """Post to Slack webhook for alerts at or above SLACK_MIN_SEVERITY."""
    if not config.SLACK_WEBHOOK_URL:
        return
    if not _severity_meets_threshold(alert.get("severity", "LOW"), config.SLACK_MIN_SEVERITY):
        return

    sev   = alert.get("severity", "LOW")
    color = SEVERITY_COLORS.get(sev, "#333333")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"IDS Alert — {sev}",
            "fields": [
                {"title": "Type",        "value": alert.get("alert_type", ""),   "short": True},
                {"title": "Source IP",   "value": alert.get("src_ip", "-"),       "short": True},
                {"title": "Dest IP",     "value": alert.get("dst_ip", "-"),       "short": True},
                {"title": "Port",        "value": str(alert.get("dst_port", "")), "short": True},
                {"title": "Description", "value": alert.get("description", "")[:200], "short": False},
                {"title": "MITRE",       "value": alert.get("mitre_tactic", ""),  "short": True},
                {"title": "Confidence",  "value": str(alert.get("confidence", "")), "short": True},
            ],
            "footer": "Hybrid IDS",
            "ts": "",
        }]
    }

    try:
        resp = requests.post(config.SLACK_WEBHOOK_URL, json=payload, timeout=5)
        if resp.status_code != 200:
            logger.warning("slack_post_failed", status=resp.status_code)
        else:
            logger.info("slack_alert_sent", severity=sev)
    except Exception as e:
        logger.error("slack_request_failed", error=str(e))


def get_all_notifiers() -> list:
    """Return list of all configured notifiers."""
    return [console_notifier, email_notifier, slack_notifier]
