from datetime import datetime
from html import escape


def generate_report(
    target,
    recon_result,
    discovered_urls,
    technologies,
    header_results,
    exposure_findings,
    input_results,
    score,
    risk,
    findings,
    output_file="reports/report.html"
):
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    forms = input_results.get("forms", [])
    parameters = input_results.get("parameters", [])
    input_observations = input_results.get("findings", [])

    with open(output_file, "w", encoding="utf-8") as report:

        report.write(f"""<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>WebSentinel Security Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f6f8;
            color: #222;
        }}

        .header {{
            background: #111827;
            color: white;
            padding: 25px;
            border-radius: 10px;
        }}

        .summary {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin: 25px 0;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            min-width: 180px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}

        .card h3 {{
            margin-top: 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-bottom: 30px;
        }}

        th, td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }}

        th {{
            background: #e5e7eb;
        }}

        ul {{
            background: white;
            padding: 20px 40px;
            border-radius: 10px;
        }}
    </style>
</head>

<body>

<div class="header">
    <h1>WebSentinel v1.0</h1>
    <p>Automated Web Security Assessment Report</p>
    <p><strong>Scan Time:</strong> {escape(scan_time)}</p>
</div>

<h2>Target Information</h2>

<table>
    <tr>
        <th>Target</th>
        <td>{escape(target)}</td>
    </tr>

    <tr>
        <th>Status Code</th>
        <td>{recon_result["status_code"]}</td>
    </tr>

    <tr>
        <th>Final URL</th>
        <td>{escape(recon_result["final_url"])}</td>
    </tr>

    <tr>
        <th>Server</th>
        <td>{escape(str(recon_result.get("server") or "Not disclosed"))}</td>
    </tr>

    <tr>
        <th>Content Type</th>
        <td>{escape(str(recon_result.get("content_type") or "Unknown"))}</td>
    </tr>

    <tr>
        <th>Page Size</th>
        <td>{recon_result["size"]} bytes</td>
    </tr>
</table>


<h2>Security Summary</h2>

<div class="summary">

    <div class="card">
        <h3>URLs</h3>
        <p>{len(discovered_urls)}</p>
    </div>

    <div class="card">
        <h3>Technologies</h3>
        <p>{len(technologies)}</p>
    </div>

    <div class="card">
        <h3>Forms</h3>
        <p>{len(forms)}</p>
    </div>

    <div class="card">
        <h3>Parameters</h3>
        <p>{len(parameters)}</p>
    </div>

    <div class="card">
        <h3>Exposures</h3>
        <p>{len(exposure_findings)}</p>
    </div>

    <div class="card">
        <h3>Security Score</h3>
        <p>{score}/100</p>
    </div>

    <div class="card">
        <h3>Risk Level</h3>
        <p>{escape(risk)}</p>
    </div>

</div>


<h2>Discovered URLs</h2>

<ul>
""")

        for url in discovered_urls:
            report.write(f"<li>{escape(url)}</li>\n")

        report.write("""
</ul>


<h2>Detected Technologies</h2>

<table>
    <tr>
        <th>Technology</th>
        <th>Value</th>
    </tr>
""")

        if technologies:

            for name, value in technologies.items():
                report.write(
                    f"<tr>"
                    f"<td>{escape(name)}</td>"
                    f"<td>{escape(str(value))}</td>"
                    f"</tr>\n"
                )

        else:

            report.write(
                "<tr><td colspan='2'>"
                "No technology information disclosed."
                "</td></tr>"
            )

        report.write("""
</table>


<h2>Security Headers</h2>

<table>
    <tr>
        <th>Header</th>
        <th>Status</th>
        <th>Value / Description</th>
    </tr>
""")

        for header, result in header_results.items():

            status = result.get("status", "unknown")

            if status == "present":
                details = result.get("value", "")
            else:
                details = result.get("description", "")

            report.write(
                f"<tr>"
                f"<td>{escape(header)}</td>"
                f"<td>{escape(status.upper())}</td>"
                f"<td>{escape(str(details))}</td>"
                f"</tr>\n"
            )

        report.write("""
</table>


<h2>Potential Exposures</h2>

<table>
    <tr>
        <th>Path</th>
        <th>HTTP Status</th>
        <th>Severity</th>
    </tr>
""")

        if exposure_findings:

            for finding in exposure_findings:

                report.write(
                    f"<tr>"
                    f"<td>{escape(finding['path'])}</td>"
                    f"<td>{finding['status_code']}</td>"
                    f"<td>{escape(finding['severity'])}</td>"
                    f"</tr>\n"
                )

        else:

            report.write(
                "<tr><td colspan='3'>"
                "No potential exposures detected."
                "</td></tr>"
            )

        report.write("""
</table>


<h2>Input & Parameter Analysis</h2>

<table>
    <tr>
        <th>Metric</th>
        <th>Value</th>
    </tr>

    <tr>
        <td>Forms Discovered</td>
        <td>""" + str(len(forms)) + """</td>
    </tr>

    <tr>
        <td>URL Parameters</td>
        <td>""" + str(len(parameters)) + """</td>
    </tr>
</table>
""")

        if forms:

            report.write("""
<h3>Forms</h3>

<table>
    <tr>
        <th>Form</th>
        <th>Action</th>
        <th>Method</th>
        <th>Inputs</th>
    </tr>
""")

            for form in forms:

                input_names = []

                for field in form.get("inputs", []):
                    name = field.get("name") or "(unnamed)"
                    field_type = field.get("type", "unknown")

                    input_names.append(
                        f"{escape(name)} [{escape(field_type)}]"
                    )

                inputs_html = "<br>".join(input_names)

                report.write(
                    f"<tr>"
                    f"<td>Form {form['form_id']}</td>"
                    f"<td>{escape(form['action'])}</td>"
                    f"<td>{escape(form['method'])}</td>"
                    f"<td>{inputs_html or 'None'}</td>"
                    f"</tr>\n"
                )

            report.write("""
</table>
""")

        if parameters:

            report.write("""
<h3>URL Parameters</h3>

<ul>
""")

            for parameter in parameters:
                report.write(
                    f"<li>{escape(parameter)}</li>\n"
                )

            report.write("""
</ul>
""")

        report.write("""
<h3>Input Security Observations</h3>
""")

        if input_observations:

            report.write("""
<table>
    <tr>
        <th>Type</th>
        <th>Finding</th>
        <th>Severity</th>
    </tr>
""")

            for observation in input_observations:

                report.write(
                    f"<tr>"
                    f"<td>{escape(observation.get('type', 'Unknown'))}</td>"
                    f"<td>{escape(observation.get('name', 'Unknown'))}</td>"
                    f"<td>{escape(observation.get('severity', 'Unknown'))}</td>"
                    f"</tr>\n"
                )

            report.write("""
</table>
""")

        else:

            report.write(
                "<p>No basic input security observations detected.</p>"
            )


        report.write("""
<h2>Risk Findings</h2>

<table>
    <tr>
        <th>Type</th>
        <th>Finding</th>
        <th>Severity</th>
        <th>Score Deduction</th>
    </tr>
""")

        if findings:

            for finding in findings:

                report.write(
                    f"<tr>"
                    f"<td>{escape(finding['type'])}</td>"
                    f"<td>{escape(finding['name'])}</td>"
                    f"<td>{escape(finding['severity'])}</td>"
                    f"<td>-{finding['deduction']}</td>"
                    f"</tr>\n"
                )

        else:

            report.write(
                "<tr><td colspan='4'>"
                "No risk findings detected."
                "</td></tr>"
            )

        report.write("""
</table>

<hr>

<p>
    Generated by <strong>WebSentinel v1.0</strong>
</p>

</body>
</html>
""")

    print(f"\n[+] HTML report generated: {output_file}")

    return output_file
