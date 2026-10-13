"""Post a report to the configured reporting API."""
import os
import sys
import urllib.request


def main(report_path):
    token = os.environ["REPORT_API_TOKEN"]
    url = os.environ["REPORT_API_URL"]
    with open(report_path, "rb") as handle:
        body = handle.read()
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(request) as response:
        print(response.status)


if __name__ == "__main__":
    main(sys.argv[1])
