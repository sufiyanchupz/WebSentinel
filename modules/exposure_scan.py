import requests
from urllib.parse import urljoin


SENSITIVE_PATHS = [
    "robots.txt",
    ".env",
    ".git/",
    "config.php",
    "backup.zip",
    "database/",
    "reports/",
    "evidence/",
    "requirements.txt",
]


def scan_exposure(url):
    url = url.rstrip("/")

    print(f"\n[*] Checking for exposed resources: {url}\n")

    findings = []

    for path in SENSITIVE_PATHS:
        target = urljoin(url + "/", path)

        try:
            response = requests.get(
                target,
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "WebSentinel/1.0"}
            )

            if response.status_code == 200:
                print(f"[!] FOUND    {path}  -> HTTP {response.status_code}")

                findings.append({
                    "path": path,
                    "status_code": response.status_code,
                    "severity": "MEDIUM"
                })

            elif response.status_code in [301, 302, 307, 308]:
                print(f"[+] REDIRECT {path}  -> HTTP {response.status_code}")

            else:
                print(f"[-] Not found {path}  -> HTTP {response.status_code}")

        except requests.RequestException as error:
            print(f"[-] Error checking {path}: {error}")

    print(f"\n[+] Potential exposures found: {len(findings)}")

    return findings


if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()

    scan_exposure(target)
