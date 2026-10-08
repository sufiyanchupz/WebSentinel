# WebSentinel v1.0

## Automated Web Security Assessment Framework

---

# 1. Abstract

WebSentinel is a Python-based automated web security assessment
framework developed for authorized and educational testing
environments.

The framework automates several basic web security assessment
activities including reconnaissance, URL discovery, technology
detection, security header analysis, sensitive resource exposure
checks, input and parameter analysis, security misconfiguration
checks, risk scoring, evidence collection, database storage, HTML
report generation, and dashboard visualization.

The system stores scan information and findings in an SQLite
database and provides a Flask-based dashboard for reviewing scan
history and individual scan details.

---

# 2. Introduction

Web applications are frequently exposed to security risks caused by
misconfiguration, information disclosure, weak security controls,
and insecure application design.

Manual assessment of basic security properties can be repetitive and
time-consuming. WebSentinel was developed to automate common initial
assessment activities and provide a structured output containing
findings, evidence, risk scores, and reports.

The project is designed as an educational cybersecurity framework
and is intended to be used only against authorized targets.

---

# 3. Problem Statement

Security assessment of web applications often requires multiple
manual checks for response information, URLs, security headers,
exposed resources, input fields, and configuration issues.

A lightweight automated framework can reduce repetitive work by
combining these checks into a single assessment workflow.

---

# 4. Objectives

The objectives of WebSentinel are:

- Automate basic web security assessment tasks
- Discover URLs and application inputs
- Detect disclosed technology information
- Identify missing security headers
- Detect potentially exposed resources
- Identify basic security misconfiguration observations
- Calculate a project-defined security risk score
- Collect supporting evidence
- Store scan history in SQLite
- Generate HTML security reports
- Provide a web dashboard for reviewing scan results

---

# 5. Scope

WebSentinel focuses on basic web application assessment activities.

The current scope includes:

- HTTP reconnaissance
- Same-domain URL discovery
- Server technology detection
- Security header analysis
- Sensitive resource exposure checks
- HTML form and parameter analysis
- Basic security misconfiguration checks
- Risk scoring
- Evidence collection
- Database storage
- HTML reporting
- Dashboard visualization

The framework does not replace a full professional penetration
test or comprehensive vulnerability assessment.

---

# 6. System Architecture

The overall system follows this workflow:

```text
                    WebSentinel
                         |
                         v
                    Target URL
                         |
       +-----------------+-----------------+
       |                 |                 |
       v                 v                 v
     Recon            Crawler        Tech Detection
       |                 |                 |
       +-----------------+-----------------+
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
