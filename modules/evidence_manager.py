from datetime import datetime
from pathlib import Path


EVIDENCE_DIR = Path("evidence")


def save_recon_evidence(recon_result):
    EVIDENCE_DIR.mkdir(exist_ok=True)

    file_path = EVIDENCE_DIR / "recon.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("=== WebSentinel Reconnaissance Evidence ===\n")
        file.write(
            f"Timestamp: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        file.write(
            f"Target       : {recon_result.get('target', 'Unknown')}\n"
        )
        file.write(
            f"Status Code  : "
            f"{recon_result.get('status_code', 'Unknown')}\n"
        )
        file.write(
            f"Final URL    : "
            f"{recon_result.get('final_url', 'Unknown')}\n"
        )
        file.write(
            f"Server       : "
            f"{recon_result.get('server', 'Unknown')}\n"
        )
        file.write(
            f"Content-Type : "
            f"{recon_result.get('content_type', 'Unknown')}\n"
        )
        file.write(
            f"Page Size    : "
            f"{recon_result.get('size', 'Unknown')} bytes\n"
        )

        file.write("\nResponse Headers:\n")

        for header, value in recon_result.get("headers", {}).items():
            file.write(f"{header}: {value}\n")

    print(f"[+] Recon evidence saved: {file_path}")
    return str(file_path)


def save_header_evidence(header_results):
    EVIDENCE_DIR.mkdir(exist_ok=True)

    file_path = EVIDENCE_DIR / "headers.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("=== WebSentinel Security Header Evidence ===\n")
        file.write(
            f"Timestamp: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        for header, result in header_results.items():
            status = result.get("status", "unknown").upper()

            file.write(f"Header : {header}\n")
            file.write(f"Status : {status}\n")

            if status == "PRESENT":
                file.write(
                    f"Value  : {result.get('value', 'Unknown')}\n"
                )
            else:
                file.write(
                    f"Description : "
                    f"{result.get('description', 'No description')}\n"
                )

            file.write("-" * 50 + "\n")

    print(f"[+] Header evidence saved: {file_path}")
    return str(file_path)


def save_exposure_evidence(exposure_findings):
    EVIDENCE_DIR.mkdir(exist_ok=True)

    file_path = EVIDENCE_DIR / "exposure.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("=== WebSentinel Exposure Evidence ===\n")
        file.write(
            f"Timestamp: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        if not exposure_findings:
            file.write("No potential exposures detected.\n")
        else:
            for finding in exposure_findings:
                file.write(
                    f"Path       : "
                    f"{finding.get('path', 'Unknown')}\n"
                )
                file.write(
                    f"HTTP Status: "
                    f"{finding.get('status_code', 'Unknown')}\n"
                )
                file.write(
                    f"Severity   : "
                    f"{finding.get('severity', 'Unknown')}\n"
                )
                file.write("-" * 50 + "\n")

    print(f"[+] Exposure evidence saved: {file_path}")
    return str(file_path)


def save_misconfig_evidence(misconfig_findings):
    EVIDENCE_DIR.mkdir(exist_ok=True)

    file_path = EVIDENCE_DIR / "misconfig.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("=== WebSentinel Misconfiguration Evidence ===\n")
        file.write(
            f"Timestamp: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        if not misconfig_findings:
            file.write("No misconfiguration observations detected.\n")
        else:
            for finding in misconfig_findings:
                file.write(
                    f"Type     : "
                    f"{finding.get('type', 'Unknown')}\n"
                )
                file.write(
                    f"Finding  : "
                    f"{finding.get('name', 'Unknown')}\n"
                )
                file.write(
                    f"Severity : "
                    f"{finding.get('severity', 'Unknown')}\n"
                )
                file.write("-" * 50 + "\n")

    print(f"[+] Misconfiguration evidence saved: {file_path}")
    return str(file_path)
