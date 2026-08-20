from backend.log_ingestion.reader import read_log_file
from backend.log_ingestion.parser import parse_log_line
from backend.log_ingestion.detector import detect_brute_force


def process_log_file(file_path: str):
    """
    Read, parse, and analyze a security log file.
    """

    raw_logs = read_log_file(file_path)

    events = []

    for line in raw_logs:
        try:
            event = parse_log_line(line)
            events.append(event)
        except ValueError as error:
            print(f"Skipping invalid log: {error}")

    alerts = detect_brute_force(events)

    return alerts


if __name__ == "__main__":
    log_file = "backend/log_ingestion/sample_security.log"

    alerts = process_log_file(log_file)

    if not alerts:
        print("No security alerts detected.")
    else:
        for alert in alerts:
            print("\n🚨 SECURITY ALERT")
            print("Rule:", alert.rule)
            print("Source IP:", alert.source_ip)
            print("Attempts:", alert.attempts)
            print("Severity:", alert.severity)
            print("Message:", alert.message)