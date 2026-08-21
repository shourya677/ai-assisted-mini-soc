from fastapi import FastAPI, HTTPException, Query, UploadFile, File
from pathlib import Path

from backend.log_ingestion.pipeline import process_log_file
from backend.app.status_store import (
    load_alert_statuses,
    save_alert_statuses,
    get_alert_status,
    set_alert_status,
)


app = FastAPI(
    title="AI-Assisted Mini SOC",
    description="Automated Threat Detection and Incident Response Platform",
    version="0.1.0",
)


UPLOAD_DIR = Path("backend/app/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


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


@app.post("/logs/upload")
async def upload_log(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected",
        )

    if not file.filename.lower().endswith(".log"):
        raise HTTPException(
            status_code=400,
            detail="Only .log files are allowed",
        )

    file_path = UPLOAD_DIR / Path(file.filename).name

    try:
        contents = await file.read()

        if not contents:
            raise HTTPException(
                status_code=400,
                detail="Uploaded log file is empty",
            )

        file_path.write_bytes(contents)

        alerts = process_log_file(str(file_path))

        return {
            "filename": file.filename,
            "count": len(alerts),
            "alerts": [
                {
                    "rule": alert.rule,
                    "source_ip": alert.source_ip,
                    "attempts": alert.attempts,
                    "severity": alert.severity,
                    "message": alert.message,
                }
                for alert in alerts
            ],
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process log file: {error}",
        )


@app.get("/alerts")
def get_alerts(
    severity: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    status: str | None = Query(default=None),
):
    log_file = "backend/log_ingestion/sample_security.log"

    all_alerts = process_log_file(log_file)

    filtered_alerts = all_alerts

    if severity:
        severity = severity.upper()

        filtered_alerts = [
            alert
            for alert in filtered_alerts
            if alert.severity.upper() == severity
        ]

    if source_ip:
        filtered_alerts = [
            alert
            for alert in filtered_alerts
            if alert.source_ip == source_ip
        ]

    if status:
        status = status.upper()

        filtered_alerts = [
            alert
            for alert in filtered_alerts
            if get_alert_status(
                all_alerts.index(alert) + 1,
                alert_statuses,
            ) == status
        ]

    return {
        "count": len(filtered_alerts),
        "alerts": [
            {
                "id": all_alerts.index(alert) + 1,
                "rule": alert.rule,
                "source_ip": alert.source_ip,
                "attempts": alert.attempts,
                "severity": alert.severity,
                "message": alert.message,
                "status": get_alert_status(
                    all_alerts.index(alert) + 1,
                    alert_statuses,
                ),
            }
            for alert in filtered_alerts
        ],
    }


@app.get("/alerts/stats")
def get_alert_stats():
    log_file = "backend/log_ingestion/sample_security.log"

    alerts = process_log_file(log_file)

    total = len(alerts)

    open_count = 0
    acknowledged_count = 0
    resolved_count = 0

    high_count = 0
    medium_count = 0
    low_count = 0

    for index, alert in enumerate(alerts, start=1):
        status = get_alert_status(
            index,
            alert_statuses,
        )

        if status == "OPEN":
            open_count += 1
        elif status == "ACKNOWLEDGED":
            acknowledged_count += 1
        elif status == "RESOLVED":
            resolved_count += 1

        severity = alert.severity.upper()

        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1

    return {
        "total": total,
        "open": open_count,
        "acknowledged": acknowledged_count,
        "resolved": resolved_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    log_file = "backend/log_ingestion/sample_security.log"

    alerts = process_log_file(log_file)

    if alert_id < 1 or alert_id > len(alerts):
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found",
        )

    alert = alerts[alert_id - 1]

    return {
        "id": alert_id,
        "rule": alert.rule,
        "source_ip": alert.source_ip,
        "attempts": alert.attempts,
        "severity": alert.severity,
        "message": alert.message,
        "status": get_alert_status(
            alert_id,
            alert_statuses,
        ),
    }


@app.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    log_file = "backend/log_ingestion/sample_security.log"

    alerts = process_log_file(log_file)

    if alert_id < 1 or alert_id > len(alerts):
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found",
        )

    set_alert_status(
        alert_id,
        "ACKNOWLEDGED",
        alert_statuses,
    )

    save_alert_statuses(alert_statuses)

    return {
        "alert_id": alert_id,
        "status": "ACKNOWLEDGED",
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

    set_alert_status(
        alert_id,
        "RESOLVED",
        alert_statuses,
    )

    save_alert_statuses(alert_statuses)

    return {
        "alert_id": alert_id,
        "status": "RESOLVED",
    }