from fastapi import FastAPI

app = FastAPI(
    title="AI-Assisted Mini SOC",
    description="Automated Threat Detection and Incident Response Platform",
    version="0.1.0",
)


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