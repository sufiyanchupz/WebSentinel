from flask import Flask, render_template_string, abort
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "websentinel.db"

app = Flask(__name__)


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSentinel Dashboard</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 30px;
            background: #f4f6f8;
            color: #222;
        }

        .header {
            background: #111827;
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
        }

        .header h1 {
            margin: 0 0 8px 0;
        }

        .cards {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            min-width: 180px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .card h3 {
            margin-top: 0;
        }

        .value {
            font-size: 28px;
            font-weight: bold;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 12px;
            overflow: hidden;
        }

        th, td {
            padding: 14px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }

        th {
            background: #e5e7eb;
        }

        .view-btn {
            display: inline-block;
            padding: 8px 14px;
            background: #111827;
            color: white;
            text-decoration: none;
            border-radius: 6px;
        }

        .view-btn:hover {
            opacity: 0.85;
        }
    </style>
</head>

<body>

<div class="header">
    <h1>WebSentinel v1.0</h1>
    <p>Automated Web Security Assessment Dashboard</p>
</div>

<div class="cards">

    <div class="card">
        <h3>Total Scans</h3>
        <div class="value">{{ total_scans }}</div>
    </div>

    <div class="card">
        <h3>Latest Score</h3>
        <div class="value">{{ latest_score }}/100</div>
    </div>

    <div class="card">
        <h3>Latest Risk</h3>
        <div class="value">{{ latest_risk }}</div>
    </div>

    <div class="card">
        <h3>Total Findings</h3>
        <div class="value">{{ total_findings }}</div>
    </div>

</div>

<h2>Recent Scans</h2>

<table>
    <tr>
        <th>ID</th>
        <th>Target</th>
        <th>Status</th>
        <th>Score</th>
        <th>Risk</th>
        <th>Scan Time</th>
        <th>Action</th>
    </tr>

    {% for scan in scans %}
    <tr>
        <td>{{ scan[0] }}</td>
        <td>{{ scan[1] }}</td>
        <td>{{ scan[2] }}</td>
        <td>{{ scan[3] }}/100</td>
        <td>{{ scan[4] }}</td>
        <td>{{ scan[5] }}</td>
        <td>
            <a class="view-btn" href="/scan/{{ scan[0] }}">
                View
            </a>
        </td>
    </tr>
    {% endfor %}

</table>

</body>
</html>
"""


DETAILS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Details - WebSentinel</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 30px;
            background: #f4f6f8;
            color: #222;
        }

        .header {
            background: #111827;
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
        }

        .section {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .info {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 12px;
        }

        .label {
            font-weight: bold;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }

        th {
            background: #e5e7eb;
        }

        .back-btn {
            display: inline-block;
            padding: 10px 16px;
            background: #111827;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            margin-bottom: 20px;
        }

        .high {
            font-weight: bold;
        }

        .count-box {
            display: inline-block;
            background: #f3f4f6;
            padding: 12px 18px;
            border-radius: 8px;
            margin-right: 10px;
            margin-bottom: 10px;
        }
    </style>
</head>

<body>

<a class="back-btn" href="/">← Back to Dashboard</a>

<div class="header">
    <h1>WebSentinel Scan Details</h1>
    <p>Scan ID: {{ scan[0] }}</p>
</div>

<div class="section">

    <h2>Scan Information</h2>

    <div class="info">

        <div class="label">Scan ID</div>
        <div>{{ scan[0] }}</div>

        <div class="label">Target</div>
        <div>{{ scan[1] }}</div>

        <div class="label">Scan Time</div>
        <div>{{ scan[2] }}</div>

        <div class="label">Status Code</div>
        <div>{{ scan[3] }}</div>

        <div class="label">Security Score</div>
        <div>{{ scan[4] }}/100</div>

        <div class="label">Risk Level</div>
        <div class="high">{{ scan[5] }}</div>

    </div>

</div>


<div class="section">

    <h2>Input Analysis Summary</h2>

    <div class="count-box">
        <strong>Forms:</strong> {{ forms|length }}
    </div>

    <div class="count-box">
        <strong>URL Parameters:</strong> {{ parameters|length }}
    </div>

</div>


<div class="section">

    <h2>Forms and Inputs</h2>

    {% if forms %}

    <table>

        <tr>
            <th>Form ID</th>
            <th>Action</th>
            <th>Method</th>
            <th>Input Name</th>
            <th>Input Type</th>
        </tr>

        {% for form in forms %}

        <tr>
            <td>{{ form[0] }}</td>
            <td>{{ form[1] }}</td>
            <td>{{ form[2] }}</td>
            <td>{{ form[3] or "(unnamed)" }}</td>
            <td>{{ form[4] }}</td>
        </tr>

        {% endfor %}

    </table>

    {% else %}

    <p>No form data recorded for this scan.</p>

    {% endif %}

</div>


<div class="section">

    <h2>URL Parameters</h2>

    {% if parameters %}

    <table>

        <tr>
            <th>Parameter</th>
        </tr>

        {% for parameter in parameters %}

        <tr>
            <td>{{ parameter[0] }}</td>
        </tr>

        {% endfor %}

    </table>

    {% else %}

    <p>No URL parameters recorded for this scan.</p>

    {% endif %}

</div>


<div class="section">

    <h2>Security Findings</h2>

    {% if findings %}

    <table>

        <tr>
            <th>Type</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Deduction</th>
        </tr>

        {% for finding in findings %}

        <tr>
            <td>{{ finding[0] }}</td>
            <td>{{ finding[1] }}</td>
            <td>{{ finding[2] }}</td>
            <td>-{{ finding[3] }}</td>
        </tr>

        {% endfor %}

    </table>

    {% else %}

    <p>No findings recorded for this scan.</p>

    {% endif %}

</div>

</body>
</html>
"""


def get_connection():
    return sqlite3.connect(DATABASE_FILE)


def get_dashboard_data():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("""
        SELECT security_score, risk_level
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    latest = cursor.fetchone()

    if latest:
        latest_score = latest[0]
        latest_risk = latest[1]
    else:
        latest_score = 0
        latest_risk = "N/A"

    cursor.execute("SELECT COUNT(*) FROM findings")
    total_findings = cursor.fetchone()[0]

    cursor.execute("""
        SELECT id,
               target,
               status_code,
               security_score,
               risk_level,
               scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """)

    scans = cursor.fetchall()

    connection.close()

    return (
        total_scans,
        latest_score,
        latest_risk,
        total_findings,
        scans
    )


@app.route("/")
def dashboard():

    (
        total_scans,
        latest_score,
        latest_risk,
        total_findings,
        scans
    ) = get_dashboard_data()

    return render_template_string(
        DASHBOARD_HTML,
        total_scans=total_scans,
        latest_score=latest_score,
        latest_risk=latest_risk,
        total_findings=total_findings,
        scans=scans
    )


@app.route("/scan/<int:scan_id>")
def scan_details(scan_id):

    connection = get_connection()
    cursor = connection.cursor()

    # Scan information
    cursor.execute("""
        SELECT id,
               target,
               scan_time,
               status_code,
               security_score,
               risk_level
        FROM scans
        WHERE id = ?
    """, (scan_id,))

    scan = cursor.fetchone()

    if scan is None:
        connection.close()
        abort(404)

    # Findings
    cursor.execute("""
        SELECT finding_type,
               finding_name,
               severity,
               deduction
        FROM findings
        WHERE scan_id = ?
        ORDER BY id
    """)

    findings = cursor.fetchall()

    # Form inputs
    cursor.execute("""
        SELECT form_id,
               action,
               method,
               input_name,
               input_type
        FROM form_inputs
        WHERE scan_id = ?
        ORDER BY form_id, id
    """)

    forms = cursor.fetchall()

    # URL parameters
    cursor.execute("""
        SELECT parameter_name
        FROM url_parameters
        WHERE scan_id = ?
        ORDER BY id
    """)

    parameters = cursor.fetchall()

    connection.close()

    return render_template_string(
        DETAILS_HTML,
        scan=scan,
        findings=findings,
        forms=forms,
        parameters=parameters
    )


if __name__ == "__main__":

    print("\n===================================")
    print("       WebSentinel Dashboard")
    print("===================================")
    print("Open: http://127.0.0.1:5000")
    print("Press CTRL+C to stop.")
    print("===================================\n")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

