from fastapi import FastAPI
from backend.log_ingestion.pipeline import process_log_file

app = FastAPI(
    title="AI-Assisted Mini SOC",
    description="Automated Threat Detection and Incident Response Platform",
    version="0.1.0",
)

alert_statuses = {}


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
    alert_statuses[alert_id] = "RESOLVED"

    return {
        "alert_id": alert_id,
        "status": "RESOLVED",
    }