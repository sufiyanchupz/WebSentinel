from urllib.parse import urlparse


HEADER_WEIGHTS = {
    "Content-Security-Policy": 15,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 5,
    "Strict-Transport-Security": 10,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5
}


EXPOSURE_WEIGHTS = {
    "database/": 15,
    "reports/": 10,
    "evidence/": 10,
    "requirements.txt": 5
}


MISCONFIG_WEIGHTS = {
    "HTTP instead of HTTPS": 10,
    "Server banner disclosure": 5,
    "Possible directory listing": 15
}


def get_severity(weight):
    if weight >= 15:
        return "MEDIUM"
    elif weight >= 5:
        return "LOW"
    return "INFO"


def calculate_risk(
    header_results,
    exposure_findings,
    target_url=None,
    misconfig_findings=None
):
    score = 100
    findings = []

    misconfig_findings = misconfig_findings or []

    # Check HTTPS
    is_https = False

    if target_url:
        parsed = urlparse(target_url)
        is_https = parsed.scheme.lower() == "https"

    # Security header findings
    for header, weight in HEADER_WEIGHTS.items():

        # HSTS applies to HTTPS
        if header == "Strict-Transport-Security" and not is_https:
            continue

        result = header_results.get(header, {})

        if result.get("status") == "missing":
            score -= weight

            findings.append({
                "type": "Security Header",
                "name": header,
                "severity": get_severity(weight),
                "deduction": weight
            })

    # Sensitive resource exposure
    for finding in exposure_findings:

        path = finding.get("path")
        weight = EXPOSURE_WEIGHTS.get(path, 5)

        score -= weight

        findings.append({
            "type": "Information Exposure",
            "name": path,
            "severity": get_severity(weight),
            "deduction": weight
        })

    # Security misconfiguration
    for finding in misconfig_findings:

        name = finding.get("name")
        weight = MISCONFIG_WEIGHTS.get(name, 5)

        score -= weight

        findings.append({
            "type": finding.get(
                "type",
                "Security Misconfiguration"
            ),
            "name": name,
            "severity": get_severity(weight),
            "deduction": weight
        })

    # Keep score between 0 and 100
    score = max(0, min(score, 100))

    # Risk classification
    if score >= 80:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk, findings
