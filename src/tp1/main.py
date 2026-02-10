from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report
import time


def main():
    logger.info("Starting TP1")

    capture = Capture("eth0")
    capture.capture_traffic()
    capture.get_all_protocols()
    print(capture.sort_network_protocols())
    capture.analyse("HTTP")
    summary = capture.get_summary()

    print(summary)
    filename = "report.md"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save()


if __name__ == "__main__":
    main()
