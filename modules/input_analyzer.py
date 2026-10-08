import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs


def analyze_inputs(url):
    print(f"\n[*] Analyzing forms and parameters: {url}\n")

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "WebSentinel/1.0"}
        )
        response.raise_for_status()

    except requests.RequestException as error:
        print(f"[-] Request failed: {error}")
        return {
            "forms": [],
            "parameters": [],
            "findings": []
        }

    soup = BeautifulSoup(response.text, "html.parser")

    forms = []
    findings = []

    # -----------------------------
    # Analyze HTML forms
    # -----------------------------
    for index, form in enumerate(soup.find_all("form"), start=1):

        action = form.get("action") or url
        method = (form.get("method") or "GET").upper()

        action_url = urljoin(url, action)

        inputs = []

        for element in form.find_all(
            ["input", "textarea", "select"]
        ):
            field_name = element.get("name")
            field_type = element.get("type", "textarea")

            inputs.append({
                "name": field_name,
                "type": field_type
            })

        form_info = {
            "form_id": index,
            "action": action_url,
            "method": method,
            "inputs": inputs
        }

        forms.append(form_info)

    # -----------------------------
    # Analyze URL parameters
    # -----------------------------
    parsed_url = urlparse(url)
    query_parameters = parse_qs(parsed_url.query)

    parameters = list(query_parameters.keys())

    # -----------------------------
    # Basic security observations
    # -----------------------------

    for form in forms:

        has_password = any(
            field["type"].lower() == "password"
            for field in form["inputs"]
        )

        has_csrf_token = any(
            field["name"]
            and "csrf" in field["name"].lower()
            for field in form["inputs"]
        )

        if has_password and not has_csrf_token:
            findings.append({
                "type": "Form Security Observation",
                "name": f"Form {form['form_id']}: No obvious CSRF token",
                "severity": "LOW"
            })

    # -----------------------------
    # Display results
    # -----------------------------

    print(f"[+] Forms discovered: {len(forms)}")
    print(f"[+] URL parameters: {len(parameters)}")

    if forms:
        print("\nForms:")

        for form in forms:
            print(
                f"\n    Form {form['form_id']}"
                f"\n    Action : {form['action']}"
                f"\n    Method : {form['method']}"
            )

            if form["inputs"]:
                print("    Inputs:")

                for field in form["inputs"]:
                    name = field["name"] or "(unnamed)"
                    field_type = field["type"]

                    print(
                        f"        - {name} "
                        f"[{field_type}]"
                    )
            else:
                print("    Inputs: None")

    if parameters:
        print("\nURL Parameters:")

        for parameter in parameters:
            print(f"    - {parameter}")

    if findings:
        print("\nPotential Security Observations:")

        for finding in findings:
            print(
                f"    [-] {finding['name']} "
                f"| {finding['severity']}"
            )
    else:
        print("\n[+] No basic input security observations detected.")

    return {
        "forms": forms,
        "parameters": parameters,
        "findings": findings
    }


if __name__ == "__main__":

    target = input("Enter authorized target URL: ").strip()

    try:
        analyze_inputs(target)

    except ValueError as error:
        print(f"[-] Error: {error}")
