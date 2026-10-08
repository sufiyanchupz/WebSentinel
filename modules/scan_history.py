import sqlite3
from modules.database import DATABASE_FILE


def show_scan_history():
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, target, scan_time, status_code,
               security_score, risk_level
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    print("\n===================================")
    print("        WebSentinel Scan History")
    print("===================================\n")

    if not scans:
        print("[-] No scan history found.")
        return

    print(
        f"{'ID':<5}"
        f"{'Target':<32}"
        f"{'Status':<8}"
        f"{'Score':<8}"
        f"{'Risk':<10}"
        f"{'Scan Time'}"
    )

    print("-" * 95)

    for scan in scans:
        scan_id, target, scan_time, status, score, risk = scan

        print(
            f"{scan_id:<5}"
            f"{target[:30]:<32}"
            f"{status:<8}"
            f"{score:<8}"
            f"{risk:<10}"
            f"{scan_time}"
        )


if __name__ == "__main__":
    show_scan_history()
