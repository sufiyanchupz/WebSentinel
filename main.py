from modules.recon import perform_recon
from modules.crawler import crawl
from modules.tech_detect import detect_technology
from modules.security_headers import analyze_headers
from modules.exposure_scan import scan_exposure
from modules.input_analyzer import analyze_inputs
from modules.misconfig_scan import check_misconfigurations
from modules.risk_score import calculate_risk
from modules.report_generator import generate_report

from modules.evidence_manager import (
    save_recon_evidence,
    save_header_evidence,
    save_exposure_evidence,
    save_misconfig_evidence
)

from modules.database import save_scan
from modules.scan_history import show_scan_history


def run_scan():
    print("\n===================================")
    print("        WebSentinel Security Scan")
    print("===================================\n")

    target = input("Enter authorized target URL: ").strip()

    # 1. Reconnaissance
    print("\n[1] Reconnaissance")

    try:
        recon_result = perform_recon(target)
    except ValueError as error:
        print(f"\n[-] Invalid target URL: {error}")
        return

    if recon_result is None:
        print("\n[-] Target is unreachable. Scan stopped.")
        return

    save_recon_evidence(recon_result)

    # 2. URL Discovery
    print("\n[2] URL Discovery")
    discovered_urls = crawl(target)

    # 3. Technology Detection
    print("\n[3] Technology Detection")
    technologies = detect_technology(target)

    # 4. Security Header Analysis
    print("\n[4] Security Header Analysis")
    header_results = analyze_headers(target)

    save_header_evidence(header_results)

    # 5. Sensitive Resource Exposure
    print("\n[5] Sensitive Resource Exposure")
    exposure_findings = scan_exposure(target)

    save_exposure_evidence(exposure_findings)

    # 6. Input and Parameter Analysis
    print("\n[6] Input and Parameter Analysis")
    input_results = analyze_inputs(target)

    # 7. Security Misconfiguration
    print("\n[7] Security Misconfiguration")
    misconfig_findings = check_misconfigurations(target)

    save_misconfig_evidence(misconfig_findings)

    # 8. Risk Assessment
    print("\n[8] Risk Assessment")

    score, risk, findings = calculate_risk(
        header_results,
        exposure_findings,
        target,
        misconfig_findings
    )

    # 9. Database Storage
    print("\n[9] Database Storage")

    save_scan(
        target=target,
        status_code=recon_result["status_code"],
        score=score,
        risk=risk,
        findings=findings,
        input_results=input_results
    )

    # 10. HTML Report
    print("\n[10] Report Generation")

    generate_report(
        target=target,
        recon_result=recon_result,
        discovered_urls=discovered_urls,
        technologies=technologies,
        header_results=header_results,
        exposure_findings=exposure_findings,
        input_results=input_results,
        score=score,
        risk=risk,
        findings=findings
    )

    # Final Assessment
    print("\n===================================")
    print("        FINAL ASSESSMENT")
    print("===================================")

    print(f"Target             : {target}")
    print(f"Status Code        : {recon_result['status_code']}")
    print(f"URLs Discovered    : {len(discovered_urls)}")
    print(f"Technologies       : {len(technologies)}")
    print(f"Forms              : {len(input_results.get('forms', []))}")
    print(
        f"URL Parameters     : "
        f"{len(input_results.get('parameters', []))}"
    )
    print(f"Exposures Found    : {len(exposure_findings)}")
    print(
        f"Misconfigurations  : "
        f"{len(misconfig_findings)}"
    )
    print(f"Security Score     : {score}/100")
    print(f"Risk Level         : {risk}")

    print("\nFindings:")

    if findings:
        for finding in findings:
            print(
                f"  [-] {finding['type']} | "
                f"{finding['name']} | "
                f"{finding['severity']} | "
                f"-{finding['deduction']} points"
            )
    else:
        print("  [+] No findings detected.")

    print("\n[+] Scan completed successfully.")


def main():
    while True:
        print("\n===================================")
        print("        WebSentinel v1.0")
        print("===================================")
        print("1. New Security Scan")
        print("2. Scan History")
        print("3. Exit")
        print("===================================")

        choice = input("Select option: ").strip()

        if choice == "1":
            run_scan()

        elif choice == "2":
            show_scan_history()

        elif choice == "3":
            print("\n[+] Exiting WebSentinel. Goodbye!")
            break

        else:
            print(
                "\n[-] Invalid option. "
                "Please select 1, 2, or 3."
            )


if __name__ == "__main__":
    main()
