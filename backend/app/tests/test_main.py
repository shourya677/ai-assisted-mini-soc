from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "online"


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"


def test_get_alerts():
    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "alerts" in data


def test_get_alert_by_id():
    response = client.get("/alerts/1")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == 1
    assert "rule" in data
    assert "source_ip" in data
    assert "severity" in data
    assert "status" in data


def test_alert_not_found():
    response = client.get("/alerts/999")

    assert response.status_code == 404


def test_alert_stats():
    response = client.get("/alerts/stats")

    assert response.status_code == 200

    data = response.json()

    assert "total" in data
    assert "open" in data
    assert "acknowledged" in data
    assert "resolved" in data
    assert "high" in data
    assert "medium" in data
    assert "low" in data


def test_alert_filter_by_severity():
    response = client.get("/alerts?severity=HIGH")

    assert response.status_code == 200

    data = response.json()

    for alert in data["alerts"]:
        assert alert["severity"] == "HIGH"


def test_alert_filter_by_source_ip():
    response = client.get(
        "/alerts?source_ip=192.168.1.10"
    )

    assert response.status_code == 200

    data = response.json()

    for alert in data["alerts"]:
        assert alert["source_ip"] == "192.168.1.10"


def test_upload_valid_log():
    with open(
        "backend/log_ingestion/sample_security.log",
        "rb",
    ) as log_file:
        response = client.post(
            "/logs/upload",
            files={
                "file": (
                    "sample_security.log",
                    log_file,
                    "text/plain",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["filename"] == "sample_security.log"
    assert "count" in data
    assert "alerts" in data


def test_upload_invalid_file_type():
    response = client.post(
        "/logs/upload",
        files={
            "file": (
                "test.txt",
                b"some test content",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400

    data = response.json()

    assert data["detail"] == "Only .log files are allowed"


def test_upload_empty_log():
    response = client.post(
        "/logs/upload",
        files={
            "file": (
                "empty.log",
                b"",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400

    data = response.json()

    assert data["detail"] == "Uploaded log file is empty"