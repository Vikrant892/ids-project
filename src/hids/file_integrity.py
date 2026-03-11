"""
HIDS File Integrity Monitor (FIM).
Establishes a SHA-256 hash baseline for monitored directories.
Detects: file creation, deletion, modification.
Baseline is persisted to disk as JSON so it survives restarts.
"""
import hashlib
import json
import os
import time
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

CHUNK_SIZE = 65536  # 64KB read chunks for hashing


@dataclass
class FIMEvent:
    timestamp: str
    event_type: str          # CREATED | MODIFIED | DELETED
    file_path: str
    old_hash: Optional[str]
    new_hash: Optional[str]
    severity: str

    def to_dict(self) -> dict:
        return {
            "timestamp":  self.timestamp,
            "event_type": self.event_type,
            "file_path":  self.file_path,
            "old_hash":   self.old_hash,
            "new_hash":   self.new_hash,
            "severity":   self.severity,
        }


def sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 hex digest of a file. Returns None on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def build_baseline(watch_dirs: List[str]) -> Dict[str, str]:
    """
    Recursively scan directories and build {filepath: sha256} baseline.
    Skips unreadable files — logs a warning for each.
    """
    baseline = {}
    for d in watch_dirs:
        if not os.path.exists(d):
            logger.warning("fim_watch_dir_missing", path=d)
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                fpath = os.path.join(root, fname)
                digest = sha256_file(fpath)
                if digest:
                    baseline[fpath] = digest
                else:
                    logger.warning("fim_file_unreadable", path=fpath)
    logger.info("fim_baseline_built", file_count=len(baseline))
    return baseline


class FileIntegrityMonitor:
    """
    Polls monitored directories on a configurable interval.
    Compares current hashes to stored baseline and emits FIMEvents.
    """

    def __init__(self, callback: Callable[[FIMEvent], None]):
        self.callback = callback
        self.baseline_path = config.BASELINE_FILE
        self.watch_dirs = config.HIDS_WATCH_DIRS
        self.poll_interval = config.HIDS_POLL_INTERVAL
        self._baseline: Dict[str, str] = {}
        self._running = False

    def initialise_baseline(self):
        """Build baseline from scratch and persist it."""
        self._baseline = build_baseline(self.watch_dirs)
        self._save_baseline()

    def load_baseline(self):
        """Load existing baseline from disk. Rebuild if missing."""
        if os.path.exists(self.baseline_path):
            with open(self.baseline_path, "r") as f:
                self._baseline = json.load(f)
            logger.info("fim_baseline_loaded", file_count=len(self._baseline))
        else:
            logger.info("fim_baseline_not_found_rebuilding")
            self.initialise_baseline()

    def _save_baseline(self):
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        with open(self.baseline_path, "w") as f:
            json.dump(self._baseline, f, indent=2)
        logger.info("fim_baseline_saved", path=self.baseline_path)

    def start(self):
        """Start polling in background thread."""
        self._running = True
        self.load_baseline()
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()
        logger.info("fim_monitor_started", dirs=self.watch_dirs,
                    interval=self.poll_interval)

    def stop(self):
        self._running = False

    def _poll_loop(self):
        while self._running:
            self._scan_once()
            time.sleep(self.poll_interval)

    def _scan_once(self):
        """Compare current filesystem state to baseline."""
        current: Dict[str, str] = {}
        for d in self.watch_dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    digest = sha256_file(fpath)
                    if digest:
                        current[fpath] = digest

        ts = datetime.now().isoformat()

        # Detect modifications and deletions
        for fpath, old_hash in self._baseline.items():
            if fpath not in current:
                self.callback(FIMEvent(
                    timestamp=ts, event_type="DELETED",
                    file_path=fpath, old_hash=old_hash, new_hash=None,
                    severity="HIGH",
                ))
            elif current[fpath] != old_hash:
                self.callback(FIMEvent(
                    timestamp=ts, event_type="MODIFIED",
                    file_path=fpath, old_hash=old_hash, new_hash=current[fpath],
                    severity="HIGH" if self._is_critical_path(fpath) else "MEDIUM",
                ))

        # Detect new files
        for fpath, new_hash in current.items():
            if fpath not in self._baseline:
                self.callback(FIMEvent(
                    timestamp=ts, event_type="CREATED",
                    file_path=fpath, old_hash=None, new_hash=new_hash,
                    severity="MEDIUM",
                ))

        # Update baseline to current state
        self._baseline = current
        self._save_baseline()

    @staticmethod
    def _is_critical_path(path: str) -> bool:
        """Flag modifications to sensitive system files as HIGH."""
        critical_dirs = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                         "/etc/hosts", "/bin/", "/usr/bin/", "/sbin/"]
        return any(path.startswith(c) for c in critical_dirs)
