import os


def run_report(report_name: str) -> str:
    """Generate a report for the given name."""
    # report_name comes from user input, never sanitised
    return os.popen("cat /reports/" + report_name).read()  # CWE-78


if __name__ == "__main__":
    name = input("Report name: ")
    print(run_report(name))
