# WebSentinel v1.0

## Automated Web Security Assessment Framework

WebSentinel is a Python-based web security assessment framework designed
to automate basic reconnaissance, URL discovery, technology detection,
security header analysis, sensitive resource detection, input analysis,
security misconfiguration checks, risk scoring, evidence collection,
database storage, HTML report generation, and dashboard visualization.

> Testing should be performed only against systems you own or are
> explicitly authorized to assess.

---

## Project Objectives

The main objectives of WebSentinel are:

- Automate basic web security assessment tasks
- Identify security configuration weaknesses
- Discover application URLs and forms
- Detect exposed resources
- Collect assessment evidence
- Calculate a security risk score
- Store scan history in SQLite
- Generate HTML security reports
- Provide a web-based dashboard

---

## Technology Stack

- Python 3
- Requests
- BeautifulSoup
- SQLite
- Flask
- HTML
- CSS
- Linux / Kali Linux

---

## Project Architecture

```text
                     WebSentinel
                          |
                          v
                      Target URL
                          |
        +-----------------+------------------+
        |                 |                  |
        v                 v                  v
      Recon            Crawler          Tech Detection
        |                 |                  |
        +-----------------+------------------+
                          |
                          v
                 Security Header Analysis
                          |
                          v
                Sensitive Resource Scan
                          |
                          v
                 Input / Parameter Analysis
                          |
                          v
                Security Misconfiguration
                          |
                          v
                     Risk Engine
                      /       \
                     v         v
                Evidence     SQLite
                     \         /
                      \       /
                       v     v
                    HTML Report
                         |
                         v
                     Dashboard
                         |
                         v
                    Scan Details
