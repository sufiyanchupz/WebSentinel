# 🌌 WebSentinel v1.0


### Beyond the Attack Surface.

**Automated Web Security Assessment Framework**

WebSentinel is a Python-based web security assessment framework developed for authorized testing and controlled lab environments.

It automates multiple stages of a basic web security assessment, including reconnaissance, URL discovery, technology detection, security header analysis, sensitive resource detection, input and parameter analysis, security misconfiguration checks, risk scoring, evidence collection, scan history, HTML report generation, and dashboard visualization.

> ⚠️ **Authorized Testing Only**
>
> WebSentinel should only be used against systems you own or have explicit permission to assess.

---

## 🚀 Features

- 🔎 **Reconnaissance** — Collects basic information about the target
- 🕷️ **URL Discovery** — Discovers accessible URLs and endpoints
- 🧩 **Technology Detection** — Identifies server and technology information
- 🛡️ **Security Header Analysis** — Checks important HTTP security headers
- 📂 **Sensitive Resource Detection** — Checks for potentially exposed resources
- 📝 **Input & Parameter Analysis** — Identifies forms and URL parameters
- ⚙️ **Security Misconfiguration Detection** — Identifies selected configuration weaknesses
- 📊 **Risk Scoring** — Calculates an overall security risk score
- 📁 **Evidence Collection** — Stores assessment evidence
- 🗄️ **Scan History** — Stores scan information using SQLite
- 📄 **HTML Reports** — Generates security assessment reports
- 🖥️ **Dashboard** — Provides a web-based interface for viewing scan results

---

## 🎯 Project Objectives

The main objectives of WebSentinel are:

- Automate basic web security assessment tasks
- Identify common security configuration weaknesses
- Discover application URLs and forms
- Detect potentially exposed resources
- Analyze application inputs and parameters
- Collect assessment evidence
- Calculate a security risk score
- Store scan history
- Generate HTML security reports
- Provide dashboard-based result visualization

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core development |
| Requests | HTTP communication |
| BeautifulSoup | HTML parsing and URL discovery |
| SQLite | Scan history and data storage |
| Flask | Web dashboard |
| HTML / CSS | Web interface and reports |
| Linux / Kali Linux | Development and testing environment |

---

## 🔄 Assessment Workflow

```text
                    WebSentinel
                         |
                         v
                    Target URL
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
        Recon         Crawler      Tech Detection
          |              |              |
          +--------------+--------------+
                         |
                         v
                Security Headers
                         |
                         v
              Sensitive Resources
                         |
                         v
              Input / Parameters
                         |
                         v
             Misconfiguration Checks
                         |
                         v
                    Risk Engine
                    /         \
                   v           v
              Evidence       SQLite
                   \           /
                    \         /
                     v       v
                   HTML Report
                        |
                        v
                    Dashboard
                        |
                        v
                   Scan Details
