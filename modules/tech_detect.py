import requests


def detect_technology(url):
    print(f"\n[*] Detecting technologies: {url}\n")

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "WebSentinel/1.0"}
        )

    except requests.RequestException as error:
        print(f"[-] Request failed: {error}")
        return {}

    technologies = {}

    server = response.headers.get("Server")
    powered_by = response.headers.get("X-Powered-By")

    if server:
        technologies["Server"] = server

    if powered_by:
        technologies["X-Powered-By"] = powered_by

    print("[+] Detected Technologies:")

    if technologies:
        for name, value in technologies.items():
            print(f"    {name}: {value}")
    else:
        print("    No technology information disclosed.")

    return technologies


if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()

    detect_technology(target)
