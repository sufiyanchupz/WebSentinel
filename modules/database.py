import sqlite3
from datetime import datetime
from pathlib import Path


DATABASE_DIR = Path("database")
DATABASE_FILE = DATABASE_DIR / "websentinel.db"


def get_connection():
    DATABASE_DIR.mkdir(exist_ok=True)
    return sqlite3.connect(DATABASE_FILE)


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    # Scan information
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            status_code INTEGER,
            security_score INTEGER,
            risk_level TEXT
        )
    """)

    # Security findings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            finding_type TEXT NOT NULL,
            finding_name TEXT NOT NULL,
            severity TEXT,
            deduction INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # Discovered forms and input fields
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS form_inputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            form_id INTEGER,
            action TEXT,
            method TEXT,
            input_name TEXT,
            input_type TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # Discovered URL parameters
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            parameter_name TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    connection.commit()
    connection.close()


def save_scan(
    target,
    status_code,
    score,
    risk,
    findings,
    input_results=None
):
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save scan
    cursor.execute("""
        INSERT INTO scans (
            target,
            scan_time,
            status_code,
            security_score,
            risk_level
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        target,
        scan_time,
        status_code,
        score,
        risk
    ))

    scan_id = cursor.lastrowid

    # Save findings
    for finding in findings:
        cursor.execute("""
            INSERT INTO findings (
                scan_id,
                finding_type,
                finding_name,
                severity,
                deduction
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            finding.get("type", "Unknown"),
            finding.get("name", "Unknown"),
            finding.get("severity", "Unknown"),
            finding.get("deduction", 0)
        ))

    # Save form/input information
    if input_results:
        forms = input_results.get("forms", [])

        for form in forms:
            form_id = form.get("form_id")
            action = form.get("action", "")
            method = form.get("method", "")

            for field in form.get("inputs", []):
                cursor.execute("""
                    INSERT INTO form_inputs (
                        scan_id,
                        form_id,
                        action,
                        method,
                        input_name,
                        input_type
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    form_id,
                    action,
                    method,
                    field.get("name"),
                    field.get("type", "unknown")
                ))

        # Save URL parameters
        parameters = input_results.get("parameters", [])

        for parameter in parameters:
            cursor.execute("""
                INSERT INTO url_parameters (
                    scan_id,
                    parameter_name
                )
                VALUES (?, ?)
            """, (
                scan_id,
                parameter
            ))

    connection.commit()
    connection.close()

    print(f"[+] Scan saved to database: Scan ID {scan_id}")

    return scan_id


if __name__ == "__main__":
    initialize_database()
    print(f"[+] Database initialized: {DATABASE_FILE}")
