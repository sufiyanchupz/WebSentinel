import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl(url):
    print(f"\n[*] Crawling: {url}\n")

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "WebSentinel/1.0"}
        )

        response.raise_for_status()

    except requests.RequestException as error:
        print(f"[-] Request failed: {error}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")

    base_domain = urlparse(url).netloc
    discovered = set()

    for link in soup.find_all("a", href=True):
        full_url = urljoin(url, link["href"])
        parsed = urlparse(full_url)

        # Only collect links from the same domain
        if parsed.netloc == base_domain:
            discovered.add(full_url)

    print(f"[+] URLs discovered: {len(discovered)}\n")

    for found_url in sorted(discovered):
        print(f"    {found_url}")

    return sorted(discovered)


if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()

    crawl(target)
