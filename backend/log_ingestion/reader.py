from pathlib import Path


def read_log_file(file_path: str) -> list[str]:
    """
    Read a security log file and return its lines.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    with path.open("r", encoding="utf-8") as log_file:
        lines = [line.strip() for line in log_file if line.strip()]

    return lines
if __name__ == "__main__":
    log_file = "backend/log_ingestion/sample_security.log"

    logs = read_log_file(log_file)

    print("Total logs:", len(logs))

    for log in logs:
        print(log)