from collections import Counter
from dataclasses import dataclass

from backend.log_ingestion.parser import SecurityEvent


@dataclass
class SecurityAlert:
    rule: str
    source_ip: str
    attempts: int
    severity: str
    message: str


FAILED_LOGIN_THRESHOLD = 3


def detect_brute_force(events: list[SecurityEvent]) -> list[SecurityAlert]:
    """
    Detect multiple failed login attempts from the same IP.
    """

    failed_logins = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILED"
    ]

    attempts_by_ip = Counter(
        event.source_ip
        for event in failed_logins
    )

    alerts = []

    for source_ip, attempts in attempts_by_ip.items():
        if attempts >= FAILED_LOGIN_THRESHOLD:
            alerts.append(
                SecurityAlert(
                    rule="Multiple Failed Logins",
                    source_ip=source_ip,
                    attempts=attempts,
                    severity="HIGH",
                    message=(
                        f"Possible brute-force attack detected from "
                        f"{source_ip}"
                    ),
                )
            )

    return alerts
if __name__ == "__main__":
    from datetime import datetime

    events = [
        SecurityEvent(
            timestamp=datetime(2026, 8, 19, 18, 0, 1),
            event_type="LOGIN_FAILED",
            username="admin",
            source_ip="192.168.1.10",
        ),
        SecurityEvent(
            timestamp=datetime(2026, 8, 19, 18, 1, 10),
            event_type="LOGIN_FAILED",
            username="admin",
            source_ip="192.168.1.10",
        ),
        SecurityEvent(
            timestamp=datetime(2026, 8, 19, 18, 1, 15),
            event_type="LOGIN_FAILED",
            username="admin",
            source_ip="192.168.1.10",
        ),
        SecurityEvent(
            timestamp=datetime(2026, 8, 19, 18, 2, 0),
            event_type="LOGIN_SUCCESS",
            username="shourya",
            source_ip="192.168.1.20",
        ),
    ]

    alerts = detect_brute_force(events)

    for alert in alerts:
        print("ALERT")
        print("Rule:", alert.rule)
        print("Source IP:", alert.source_ip)
        print("Attempts:", alert.attempts)
        print("Severity:", alert.severity)
        print("Message:", alert.message)