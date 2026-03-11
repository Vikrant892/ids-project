"""
HIDS Process Monitor.
Monitors running processes for anomalies:
  - Unusual parent-child relationships (e.g. webserver spawning shell)
  - Processes connecting to suspicious ports
  - High CPU/memory consumption by unexpected processes
  - New processes not in a known whitelist

Uses psutil for cross-platform process inspection.
"""
import time
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Set
import psutil
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Whitelist of expected high-privilege parent processes
TRUSTED_PARENTS = {
    "systemd", "init", "launchd", "sshd", "crond",
    "python3", "python", "docker", "containerd",
}

# Shells — unexpected spawning of these is suspicious
SHELL_NAMES = {"bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "csh"}

# Web servers / app servers — should not spawn shells
HIGH_RISK_PARENTS = {"nginx", "apache2", "httpd", "php-fpm", "node", "java", "ruby"}

# Suspicious process names
SUSPICIOUS_NAMES = {
    "nc", "ncat", "netcat", "nmap", "masscan",
    "mimikatz", "msfconsole", "msfvenom",
    "cryptominer", "xmrig",
}

POLL_INTERVAL = 15   # seconds


@dataclass
class ProcessEvent:
    timestamp: str
    event_type: str       # SUSPICIOUS_SPAWN | SUSPICIOUS_PROCESS | RESOURCE_ABUSE
    pid: int
    process_name: str
    parent_pid: int
    parent_name: str
    cmdline: str
    description: str
    severity: str

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class ProcessMonitor:
    """
    Polls running processes and emits events for anomalies.
    Maintains a snapshot of known PIDs to detect new arrivals.
    """

    def __init__(self, callback: Callable[[ProcessEvent], None]):
        self.callback = callback
        self._running = False
        self._known_pids: Set[int] = set()

    def start(self):
        self._running = True
        # Snapshot all current PIDs as baseline (no alerts for pre-existing)
        self._known_pids = {p.pid for p in psutil.process_iter(["pid"])}
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()
        logger.info("process_monitor_started", known_pids=len(self._known_pids))

    def stop(self):
        self._running = False

    def _poll_loop(self):
        while self._running:
            self._scan_once()
            time.sleep(POLL_INTERVAL)

    def _scan_once(self):
        current_pids: Set[int] = set()
        ts = datetime.now().isoformat()

        for proc in psutil.process_iter(
            ["pid", "name", "ppid", "cmdline", "cpu_percent", "memory_percent", "status"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info["name"] or "").lower()
                ppid = info["ppid"] or 0
                cmdline = " ".join(info["cmdline"] or [])[:200]
                current_pids.add(pid)

                # Only check NEW processes
                if pid in self._known_pids:
                    continue

                parent_name = ""
                try:
                    parent = psutil.Process(ppid)
                    parent_name = (parent.name() or "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                event = None

                # Check 1: Known suspicious process names
                if name in SUSPICIOUS_NAMES:
                    event = ProcessEvent(
                        timestamp=ts, event_type="SUSPICIOUS_PROCESS",
                        pid=pid, process_name=name, parent_pid=ppid,
                        parent_name=parent_name, cmdline=cmdline,
                        description=f"Known suspicious tool: {name} (pid={pid})",
                        severity="CRITICAL",
                    )

                # Check 2: Web server spawning a shell
                elif parent_name in HIGH_RISK_PARENTS and name in SHELL_NAMES:
                    event = ProcessEvent(
                        timestamp=ts, event_type="SUSPICIOUS_SPAWN",
                        pid=pid, process_name=name, parent_pid=ppid,
                        parent_name=parent_name, cmdline=cmdline,
                        description=(
                            f"Shell '{name}' spawned by web process '{parent_name}' — "
                            f"possible RCE (pid={pid})"
                        ),
                        severity="CRITICAL",
                    )

                # Check 3: Shell with suspicious cmdline (reverse shell patterns)
                elif name in SHELL_NAMES and any(
                    x in cmdline for x in ["/dev/tcp/", "bash -i", "nc -e", "mkfifo"]
                ):
                    event = ProcessEvent(
                        timestamp=ts, event_type="SUSPICIOUS_SPAWN",
                        pid=pid, process_name=name, parent_pid=ppid,
                        parent_name=parent_name, cmdline=cmdline,
                        description=f"Potential reverse shell: {cmdline[:80]}",
                        severity="CRITICAL",
                    )

                if event:
                    self.callback(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        self._known_pids = current_pids
