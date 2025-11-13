import csv
import json
import sys
import getpass
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress SSL warnings (you can remove this if you use proper certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
This script reads access rules from a CSV file and bulk-adds them
to a Cisco FMC access policy using the FMC REST API.

Usage:
    python fmc_bulk_add_rules.py "<PolicyName>" fmc_bulk_rules.csv
"""

# === Configuration ===
# Change this to your domain UUID if different
DOMAIN_UUID = "e276abec-e0f2-11e3-8169-6d9ed49b625f"


def get_credentials():
    fmc_host = input("FMC IP or hostname: ").strip()
    fmc_user = input("FMC Username: ").strip()
    fmc_pass = getpass.getpass("FMC Password: ")
    return fmc_host, fmc_user, fmc_pass


def get_token(fmc_host, fmc_user, fmc_pass):
    url = f"https://{fmc_host}/api/fmc_platform/v1/auth/generatetoken"
    resp = requests.post(
        url,
        auth=HTTPBasicAuth(fmc_user, fmc_pass),
        verify=False,
    )
    resp.raise_for_status()
    token = resp.headers.get("X-auth-access-token")
    if not token:
        raise RuntimeError("No X-auth-access-token header returned from FMC.")
    return token


def get_policy_id(base_url, headers, policy_name):
    """
    Look up an access policy ID by its name.
    """
    url = f"{base_url}/policy/accesspolicies?expanded=true&limit=1000"
    resp = requests.get(url, headers=headers, verify=False)
    resp.raise_for_status()
    data = resp.json()

    items = data.get("items", [])
    for p in items:
        if p.get("name") == policy_name:
            return p.get("id")

    raise ValueError(f"Access policy '{policy_name}' not found.")


def load_rules_from_csv(csv_path):
    """
    Read rules from CSV and return a list of JSON rule payloads.

    Expected columns (header row):
        name, action, enabled, logBegin, logEnd, sendEventsToFMC
    """
    rules = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("name", "").strip()
            if not name:
                # Skip rows without a rule name
                continue

            action = row.get("action", "ALLOW").strip().upper()
            enabled_str = row.get("enabled", "True").strip()
            log_begin_str = row.get("logBegin", "False").strip()
            log_end_str = row.get("logEnd", "True").strip()
            send_events_str = row.get("sendEventsToFMC", "True").strip()

            def to_bool(s):
                return str(s).strip().lower() in ("true", "1", "yes", "y")

            rule = {
                "name": name,
                "action": action,
                "enabled": to_bool(enabled_str),
                "logBegin": to_bool(log_begin_str),
                "logEnd": to_bool(log_end_str),
                "sendEventsToFMC": to_bool(send_events_str),
                "type": "AccessRule",
                # Conditions (zones, networks, ports, etc.) omitted:
                # this means "any/any" in the policy. You can extend this
                # later if you want to reference specific objects.
            }

            rules.append(rule)

    if not rules:
        raise ValueError("No valid rules found in CSV file.")

    return rules


def bulk_post_rules(base_url, headers, policy_id, rules):
    """
    Use FMC bulk rule posting to add many rules in a single request.

    API:
      POST /policy/accesspolicies/{policy_id}/accessrules?bulk=true

    Payload:
      [ {rule1}, {rule2}, ... ]
    """
    url = f"{base_url}/policy/accesspolicies/{policy_id}/accessrules?bulk=true"

    resp = requests.post(url, headers=headers, json=rules, verify=False)
    # For debugging, you might want to inspect resp.status_code / resp.text
    if resp.status_code == 429:
        raise RuntimeError("Received HTTP 429 (Too Many Requests) from FMC. Try again later.")
    resp.raise_for_status()
    return resp.json()


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python fmc_bulk_add_rules.py \"<PolicyName>\" <rules_csv_file>\n"
            "Example: python fmc_bulk_add_rules.py \"My Access Policy\" fmc_bulk_rules.csv"
        )
        sys.exit(1)

    policy_name = sys.argv[1]
    csv_path = sys.argv[2]

    fmc_host, fmc_user, fmc_pass = get_credentials()
    base_url = f"https://{fmc_host}/api/fmc_config/v1/domain/{DOMAIN_UUID}"

    print(f"🔐 Getting auth token from FMC {fmc_host}...")
    token = get_token(fmc_host, fmc_user, fmc_pass)
    headers = {
        "X-auth-access-token": token,
        "Content-Type": "application/json",
    }

    print(f"🔎 Looking up policy ID for '{policy_name}'...")
    try:
        policy_id = get_policy_id(base_url, headers, policy_name)
    except ValueError as e:
        print(e)
        sys.exit(1)

    print(f"✅ Found policy ID: {policy_id}")

    print(f"📥 Loading rules from CSV: {csv_path}")
    rules = load_rules_from_csv(csv_path)
    print(f"📋 Number of rules loaded: {len(rules)}")

    print("📤 Sending bulk POST to FMC...")
    result = bulk_post_rules(base_url, headers, policy_id, rules)

    # You can tailor this; FMC returns details per rule.
    print("✅ Bulk POST completed.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
