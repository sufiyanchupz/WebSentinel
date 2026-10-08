import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS and content injection",
    "X-Frame-Options": "Helps prevent clickjacking",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features"
}


def analyze_headers(url):
    print(f"\n[*] Analyzing security headers: {url}\n")

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "WebSentinel/1.0"}
        )
    except requests.RequestException as error:
        print(f"[-] Request failed: {error}")
        return {}

    results = {}

    for header, description in SECURITY_HEADERS.items():
        if header in response.headers:
            print(f"[+] {header}: PRESENT")
            results[header] = {
                "status": "present",
                "value": response.headers[header]
            }
        else:
            print(f"[-] {header}: MISSING")
            results[header] = {
                "status": "missing",
                "description": description
            }

    return results


if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()

    analyze_headers(target)
