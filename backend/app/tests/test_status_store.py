from backend.app.status_store import (
    get_alert_status,
    set_alert_status,
)


def test_default_alert_status():
    statuses = {}

    status = get_alert_status(
        1,
        statuses,
    )

    assert status == "OPEN"


def test_set_acknowledged_status():
    statuses = {}

    set_alert_status(
        1,
        "ACKNOWLEDGED",
        statuses,
    )

    assert statuses[1] == "ACKNOWLEDGED"


def test_set_resolved_status():
    statuses = {}

    set_alert_status(
        1,
        "RESOLVED",
        statuses,
    )

    assert statuses[1] == "RESOLVED"


def test_status_is_case_insensitive():
    statuses = {}

    set_alert_status(
        1,
        "acknowledged",
        statuses,
    )

    assert statuses[1] == "ACKNOWLEDGED"


def test_invalid_status():
    statuses = {}

    try:
        set_alert_status(
            1,
            "INVALID",
            statuses,
        )
    except ValueError as error:
        assert "Invalid alert status" in str(error)
    else:
        raise AssertionError(
            "Expected ValueError for invalid status"
        )


def test_open_to_acknowledged():
    statuses = {
        1: "OPEN",
    }

    set_alert_status(
        1,
        "ACKNOWLEDGED",
        statuses,
    )

    assert statuses[1] == "ACKNOWLEDGED"


def test_acknowledged_to_resolved():
    statuses = {
        1: "ACKNOWLEDGED",
    }

    set_alert_status(
        1,
        "RESOLVED",
        statuses,
    )

    assert statuses[1] == "RESOLVED"


def test_open_to_resolved():
    statuses = {
        1: "OPEN",
    }

    set_alert_status(
        1,
        "RESOLVED",
        statuses,
    )

    assert statuses[1] == "RESOLVED"


def test_resolved_cannot_be_reopened():
    statuses = {
        1: "RESOLVED",
    }

    try:
        set_alert_status(
            1,
            "OPEN",
            statuses,
        )
    except ValueError as error:
        assert "Invalid status transition" in str(error)
    else:
        raise AssertionError(
            "Expected ValueError for reopening a resolved alert"
        )


def test_resolved_cannot_be_acknowledged():
    statuses = {
        1: "RESOLVED",
    }

    try:
        set_alert_status(
            1,
            "ACKNOWLEDGED",
            statuses,
        )
    except ValueError as error:
        assert "Invalid status transition" in str(error)
    else:
        raise AssertionError(
            "Expected ValueError for acknowledging a resolved alert"
        )