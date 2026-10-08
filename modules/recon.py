import requests
from urllib.parse import urlparse


def validate_url(url):
    """Validate and normalize the target URL."""

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("URL must start with http:// or https://")

    if not parsed.netloc:
        raise ValueError("Invalid URL")

    return url.rstrip("/")


def perform_recon(url):
    """Collect basic information from an authorized web target."""

    url = validate_url(url)

    print(f"\n[*] Target: {url}")
    print("[*] Starting reconnaissance...\n")

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "WebSentinel/1.0"
            }
        )

        print(f"[+] Status Code : {response.status_code}")
        print(f"[+] Final URL   : {response.url}")
        print(f"[+] Server      : {response.headers.get('Server', 'Not disclosed')}")
        print(f"[+] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        print(f"[+] Page Size   : {len(response.content)} bytes")

        print("\n[+] Response Headers:")
        for header, value in response.headers.items():
            print(f"    {header}: {value}")

        return {
            "target": url,
            "status_code": response.status_code,
            "final_url": response.url,
            "server": response.headers.get("Server"),
            "content_type": response.headers.get("Content-Type"),
            "size": len(response.content),
            "headers": dict(response.headers)
        }

    except requests.RequestException as error:
        print(f"[-] Connection failed: {error}")
        return None


if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()

    try:
        perform_recon(target)
    except ValueError as error:
        print(f"[-] Error: {error}")
