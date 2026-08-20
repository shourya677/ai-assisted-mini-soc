from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    username: str
    source_ip: str


def parse_log_line(line: str) -> SecurityEvent:
    """
    Convert a raw security log line into a structured SecurityEvent.
    """

    parts = line.split()

    if len(parts) < 5:
        raise ValueError(f"Invalid log format: {line}")

    timestamp = datetime.strptime(
        f"{parts[0]} {parts[1]}",
        "%Y-%m-%d %H:%M:%S",
    )

    event_type = parts[2]

    username = parts[3].split("=", 1)[1]
    source_ip = parts[4].split("=", 1)[1]

    return SecurityEvent(
        timestamp=timestamp,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
    )
if __name__ == "__main__":
    sample = (
        "2026-08-19 18:00:01 "
        "LOGIN_FAILED user=admin ip=192.168.1.10"
    )

    event = parse_log_line(sample)

    print("Timestamp:", event.timestamp)
    print("Event type:", event.event_type)
    print("Username:", event.username)
    print("Source IP:", event.source_ip)