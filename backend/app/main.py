from fastapi import FastAPI, HTTPException
import json
from pathlib import Path

from backend.log_ingestion.pipeline import process_log_file
app = FastAPI(
    title="AI-Assisted Mini SOC",
    description="Automated Threat Detection and Incident Response Platform",
    version="0.1.0",
)

STATUS_FILE = Path("backend/app/alert_status.json")


def load_alert_statuses():
    if not STATUS_FILE.exists():
        return {}

    with open(STATUS_FILE, "r") as file:
        data = json.load(file)

    return {int(key): value for key, value in data.items()}


def save_alert_statuses(statuses):
    with open(STATUS_FILE, "w") as file:
        json.dump(statuses, file, indent=2)


alert_statuses = load_alert_statuses()


@app.get("/")
def root():
    return {
        "message": "AI-Assisted Mini SOC is running!",
        "status": "online",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }


@app.get("/alerts")
def get_alerts():
    log_file = "backend/log_ingestion/sample_security.log"

    alerts = process_log_file(log_file)

    return {
        "count": len(alerts),
        "alerts": [
            {
                "id": index,
                "rule": alert.rule,
                "source_ip": alert.source_ip,
                "attempts": alert.attempts,
                "severity": alert.severity,
                "message": alert.message,
                "status": alert_statuses.get(index, "OPEN"),
            }
            for index, alert in enumerate(alerts, start=1)
        ],
    }


@app.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    log_file = "backend/log_ingestion/sample_security.log"
    alerts = process_log_file(log_file)

    if alert_id < 1 or alert_id > len(alerts):
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found",
        )

    alert_statuses[alert_id] = "RESOLVED"
    save_alert_statuses(alert_statuses)

    return {
        "alert_id": alert_id,
        "status": "RESOLVED",
    }