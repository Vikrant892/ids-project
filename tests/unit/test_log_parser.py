"""Unit tests — HIDS Log Parser"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from src.hids.log_parser import LogParser


SAMPLE_LINES = {
    "ssh_fail": (
        "Jun  5 14:23:01 server sshd[1234]: "
        "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
    ),
    "ssh_success": (
        "Jun  5 14:25:00 server sshd[1235]: "
        "Accepted password for ubuntu from 10.0.0.5 port 22 ssh2"
    ),
    "sudo": (
        "Jun  5 14:26:00 server sudo[1236]:   ubuntu : TTY=pts/0 ; "
        "PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"
    ),
    "user_added": (
        "Jun  5 14:30:00 server useradd[1237]: new user: name=hacker, "
        "UID=1001, GID=1001, home=/home/hacker, shell=/bin/bash"
    ),
    "noise": "Jun  5 14:31:00 server kernel: eth0: renamed from veth123",
}

@pytest.fixture
def parser():
    events = []
    p = LogParser(callback=lambda e: events.append(e))
    p._events = events
    return p

class TestLogParser:
    def test_ssh_fail_detected(self, parser):
        event = parser.parse_line(SAMPLE_LINES["ssh_fail"])
        assert event is not None
        assert event.event_type == "AUTH_FAIL"
        assert event.source_ip == "192.168.1.100"

    def test_ssh_success_detected(self, parser):
        event = parser.parse_line(SAMPLE_LINES["ssh_success"])
        assert event is not None
        assert event.event_type == "AUTH_SUCCESS"
        assert event.user == "ubuntu"

    def test_sudo_detected(self, parser):
        event = parser.parse_line(SAMPLE_LINES["sudo"])
        assert event is not None
        assert event.event_type == "SUDO"

    def test_user_added_detected(self, parser):
        event = parser.parse_line(SAMPLE_LINES["user_added"])
        assert event is not None
        assert event.event_type == "USER_ADDED"

    def test_noise_returns_none(self, parser):
        event = parser.parse_line(SAMPLE_LINES["noise"])
        assert event is None

    def test_brute_force_escalation(self, parser):
        """5 failures from same IP within window should trigger BRUTE_FORCE."""
        for _ in range(6):
            event = parser.parse_line(SAMPLE_LINES["ssh_fail"])
            parser._check_brute_force(event)
        # After 6 failures, severity should escalate
        event = parser.parse_line(SAMPLE_LINES["ssh_fail"])
        parser._check_brute_force(event)
        assert event.severity == "CRITICAL"
        assert event.event_type == "BRUTE_FORCE"

    def test_empty_line_no_crash(self, parser):
        assert parser.parse_line("") is None

    def test_malformed_line_no_crash(self, parser):
        assert parser.parse_line("random garbage 12345 !@#$") is None
