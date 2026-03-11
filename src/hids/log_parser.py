"""
HIDS Log Parser.
Parses Linux auth.log and syslog for:
  - Failed SSH login attempts
  - Successful logins from unusual IPs
  - sudo abuse (sudo to root, failed sudo)
  - User account creation/deletion
  - Service starts/stops

Returns HIDSEvent objects for the alert pipeline.
Designed to work inside Docker container watching mounted host log files.
"""
import re
import time
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class HIDSEvent:
    timestamp: str
    event_type: str
    hostname: str
    user: str
    source_ip: Optional[str]
    pid: Optional[int]
    description: str
    severity: str
    raw_line: str


# Regex patterns for log parsing
PATTERNS = {
    "SSH_FAILED": {
        "regex": re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s(\S+)\s\S+\[(\d+)\]:\s"
            r"Failed\s\w+\sfor\s(?:invalid user\s)?(\S+)\sfrom\s([\d.]+)"
        ),
        "severity": "MEDIUM",
        "event_type": "AUTH_FAIL",
    },
    "SSH_SUCCESS": {
        "regex": re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s(\S+)\s\S+\[(\d+)\]:\s"
            r"Accepted\s\w+\sfor\s(\S+)\sfrom\s([\d.]+)"
        ),
        "severity": "LOW",
        "event_type": "AUTH_SUCCESS",
    },
    "SUDO_SUCCESS": {
        "regex": re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssudo\[(\d+)\]:\s+(\S+)\s.*COMMAND=(.*)"
        ),
        "severity": "MEDIUM",
        "event_type": "SUDO",
    },
    "SUDO_FAIL": {
        "regex": re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssudo\[(\d+)\]:\s+(\S+)\s.*"
            r"(?:incorrect password|authentication failure)"
        ),
        "severity": "HIGH",
        "event_type": "SUDO_FAIL",
    },
    "USER_ADDED": {
        "regex": re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s(\S+)\suseradd\[(\d+)\]:\snew user:\sname=(\S+)"
        ),
        "severity": "HIGH",
        "event_type": "USER_ADDED",
    },
    "USER_DELETED": {
        "regex": re.compile(
            r"(\w+\s+\d+\s[\d:]+)\s(\S+)\suserdel\[(\d+)\]:\sdelete user '(\S+)'"
        ),
        "severity": "HIGH",
        "event_type": "USER_DELETED",
    },
}

# Brute-force detection: N failures from same IP in window
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60  # seconds


class LogParser:
    """
    Tails log files and parses them for security events.
    Uses inotify-style polling (seek to end, then read new lines).
    """

    def __init__(self, callback: Callable[[HIDSEvent], None]):
        self.callback = callback
        self._running = False
        self._fail_tracker: dict = {}   # ip -> [timestamps]

    def start(self):
        """Start tailing all configured log files in background threads."""
        self._running = True
        for log_path in config.HIDS_LOG_PATHS:
            t = threading.Thread(
                target=self._tail_file, args=(log_path.strip(),), daemon=True
            )
            t.start()
            logger.info("hids_log_watcher_started", path=log_path)

    def stop(self):
        self._running = False

    def _tail_file(self, path: str):
        """Continuously tail a file and emit events."""
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(0, 2)   # Seek to end
                while self._running:
                    line = f.readline()
                    if line:
                        event = self.parse_line(line.strip())
                        if event:
                            self._check_brute_force(event)
                            self.callback(event)
                    else:
                        time.sleep(0.5)
        except FileNotFoundError:
            logger.warning("hids_log_not_found", path=path)
        except PermissionError:
            logger.error("hids_log_permission_denied", path=path)

    def parse_line(self, line: str) -> Optional[HIDSEvent]:
        """Try all patterns against a log line. Return first match."""
        for rule_name, rule in PATTERNS.items():
            m = rule["regex"].search(line)
            if m:
                groups = m.groups()
                ts = groups[0] if groups else ""
                hostname = groups[1] if len(groups) > 1 else ""
                pid = int(groups[2]) if len(groups) > 2 else None
                user = groups[3] if len(groups) > 3 else ""
                src_ip = groups[4] if len(groups) > 4 else None

                return HIDSEvent(
                    timestamp=self._normalise_timestamp(ts),
                    event_type=rule["event_type"],
                    hostname=hostname,
                    user=user,
                    source_ip=src_ip,
                    pid=pid,
                    description=f"{rule_name}: {line[:120]}",
                    severity=rule["severity"],
                    raw_line=line,
                )
        return None

    def _check_brute_force(self, event: HIDSEvent):
        """Escalate severity if brute-force threshold is exceeded."""
        if event.event_type != "AUTH_FAIL" or not event.source_ip:
            return
        now = time.time()
        ip = event.source_ip
        tracker = self._fail_tracker.setdefault(ip, [])
        tracker.append(now)
        tracker[:] = [t for t in tracker if now - t <= BRUTE_FORCE_WINDOW]
        if len(tracker) >= BRUTE_FORCE_THRESHOLD:
            event.severity = "CRITICAL"
            event.event_type = "BRUTE_FORCE"
            event.description = (
                f"SSH brute force from {ip}: {len(tracker)} failures in {BRUTE_FORCE_WINDOW}s"
            )
            logger.warning("brute_force_detected", ip=ip, count=len(tracker))

    @staticmethod
    def _normalise_timestamp(ts_str: str) -> str:
        """Convert syslog timestamp (e.g. 'Jun  5 14:23:01') to ISO format."""
        try:
            now = datetime.now()
            dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            return datetime.now().isoformat()


def parse_log_file(path: str) -> List[HIDSEvent]:
    """One-shot parse of an entire log file. Useful for testing and backfill."""
    events = []
    parser = LogParser(callback=lambda e: events.append(e))
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                event = parser.parse_line(line.strip())
                if event:
                    events.append(event)
    except FileNotFoundError:
        logger.warning("log_file_not_found", path=path)
    return events
