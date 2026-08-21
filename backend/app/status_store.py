import json
from pathlib import Path


STATUS_FILE = Path("backend/app/alert_status.json")


ALLOWED_STATUSES = {
    "OPEN",
    "ACKNOWLEDGED",
    "RESOLVED",
}


ALLOWED_TRANSITIONS = {
    "OPEN": {
        "OPEN",
        "ACKNOWLEDGED",
        "RESOLVED",
    },
    "ACKNOWLEDGED": {
        "ACKNOWLEDGED",
        "RESOLVED",
    },
    "RESOLVED": {
        "RESOLVED",
    },
}


def load_alert_statuses() -> dict[int, str]:
    """
    Load alert statuses from the JSON status file.
    """

    if not STATUS_FILE.exists():
        return {}

    with STATUS_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    return {
        int(key): value
        for key, value in data.items()
    }


def save_alert_statuses(
    statuses: dict[int, str],
) -> None:
    """
    Save alert statuses to the JSON status file.
    """

    STATUS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with STATUS_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            statuses,
            file,
            indent=2,
        )


def get_alert_status(
    alert_id: int,
    statuses: dict[int, str],
) -> str:
    """
    Return the current status of an alert.
    """

    return statuses.get(
        alert_id,
        "OPEN",
    )


def set_alert_status(
    alert_id: int,
    status: str,
    statuses: dict[int, str],
) -> dict[int, str]:
    """
    Update an alert status while enforcing
    valid alert lifecycle transitions.
    """

    status = status.upper()

    if status not in ALLOWED_STATUSES:
        raise ValueError(
            f"Invalid alert status: {status}"
        )

    current_status = get_alert_status(
        alert_id,
        statuses,
    )

    allowed_next_statuses = ALLOWED_TRANSITIONS[
        current_status
    ]

    if status not in allowed_next_statuses:
        raise ValueError(
            f"Invalid status transition: "
            f"{current_status} -> {status}"
        )

    statuses[alert_id] = status

    return statuses
