import requests
from urllib.parse import urlparse


def check_misconfigurations(url):
    print(f"\n[*] Checking security misconfigurations: {url}\n")

    findings = []

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "WebSentinel/1.0"}
        )

    except requests.RequestException as error:
        print(f"[-] Request failed: {error}")
        return findings

    parsed = urlparse(url)

    # 1. HTTPS check
    if parsed.scheme.lower() == "http":
        print("[!] HTTP is being used instead of HTTPS")

        findings.append({
            "type": "Security Misconfiguration",
            "name": "HTTP instead of HTTPS",
            "severity": "MEDIUM"
        })
    else:
        print("[+] HTTPS is being used")

    # 2. Server banner disclosure
    server = response.headers.get("Server")

    if server:
        print(f"[!] Server banner disclosed: {server}")

        findings.append({
            "type": "Information Disclosure",
            "name": "Server banner disclosure",
            "severity": "LOW"
        })
    else:
        print("[+] Server banner not disclosed")

    # 3. Directory listing indicator
    body = response.text.lower()

    directory_listing_indicators = [
        "<title>directory listing for",
        "directory listing for"
    ]

    if any(indicator in body for indicator in directory_listing_indicators):
        print("[!] Possible directory listing detected")

        findings.append({
            "type": "Security Misconfiguration",
            "name": "Possible directory listing",
            "severity": "MEDIUM"
        })
    else:
        print("[+] No directory listing detected on the target page")

    print(f"\n[+] Misconfiguration observations: {len(findings)}")

    return findings


if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()

    try:
        check_misconfigurations(target)

    except ValueError as error:
        print(f"[-] Error: {error}")
