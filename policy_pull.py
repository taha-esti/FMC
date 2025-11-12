import requests
import time
import sys
import csv
import os
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin
import urllib3
import getpass

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
This script fetches all access rules from a given Cisco FMC access policy
and writes selected fields (including rule name) to a CSV file.

Usage:
    python policy_pull.py "<PolicyName>"
"""

# === FMC Configuration ===
FMC_HOST = input("FMC IP address: ")
FMC_USER = input("FMC Username: ")
FMC_PASS = getpass.getpass("FMC Password: ")
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"

# === Functions ===
def get_token():
    url = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = requests.post(url, auth=HTTPBasicAuth(FMC_USER, FMC_PASS), verify=False)
    r.raise_for_status()
    return r.headers['X-auth-access-token']

def get_policy_id(headers, policy_name):
    url = f"{BASE_URL}/policy/accesspolicies"
    r = requests.get(url, headers=headers, verify=False)
    r.raise_for_status()
    for item in r.json().get('items', []):
        if item.get('name') == policy_name:
            return item['id']
    raise ValueError(f"Policy '{policy_name}' not found")

def list_rules(headers, policy_id, limit=100, expanded=True):
    """
    Return ALL rules from the policy using pagination.
    If expanded=True, FMC returns full rule objects (so we can avoid per-rule GETs).
    Falls back to non-expanded if needed.
    """
    params = f"limit={limit}"
    if expanded:
        params += "&expanded=true"
    url = f"{BASE_URL}/policy/accesspolicies/{policy_id}/accessrules?{params}"

    items = []
    while True:
        r = _request_with_retry("GET", url, headers=headers, verify=False)
        data = r.json()
        batch = data.get("items", [])
        items.extend(batch)

        paging = data.get("paging") or {}
        next_href = (paging.get("next") or {}).get("href")
        if not next_href:
            break
        # next_href is a full path; join with base host in case it’s relative
        url = urljoin(f"https://{FMC_HOST}", next_href)
    return items

def fetch_access_rule(headers, policy_id, rule_id):
    url = f"{BASE_URL}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}"
    r = _request_with_retry("GET", url, headers=headers, verify=False)
    return r.json()

# === Helper formatters ===
def _format_objects_and_literals(obj):
    """Helper to combine FMC objects and literals into a readable string."""
    if not obj:
        return ""
    parts = []
    for o in obj.get("objects", []):
        name = o.get("name") or o.get("value")
        if name:
            parts.append(str(name))
    for lit in obj.get("literals", []):
        val = lit.get("value") or lit.get("name")
        if val:
            parts.append(str(val))
    return "; ".join(parts)

def _format_app_filters(rule):
    """Extract application filters and applications."""
    parts = []
    for key in ("applicationFilters", "applicationFilter", "applicationFilterIds"):
        val = rule.get(key)
        if isinstance(val, list):
            for item in val:
                name = item.get("name") or item.get("value")
                if name:
                    parts.append(str(name))
    apps = rule.get("applications")
    if isinstance(apps, dict):
        for item in apps.get("applications", []):
            name = item.get("name") or item.get("value")
            if name:
                parts.append(str(name))
    return "; ".join(parts)

def _get_bool_field(rule, *keys):
    """Return boolean-like fields as True/False or empty."""
    for k in keys:
        if k in rule:
            val = rule[k]
            if isinstance(val, bool):
                return "True" if val else "False"
            if isinstance(val, str):
                return val
    return ""

def _format_comments(rule):
    """Extract comments or descriptions, including comment history."""
    for k in ("comments", "comment", "description"):
        val = rule.get(k)
        if isinstance(val, str):
            return val
    comments = rule.get("comments")
    if isinstance(comments, list):
        return "; ".join(str(c) for c in comments)
    history = rule.get("commentHistoryList")
    if isinstance(history, list) and history:
        texts = []
        for entry in history:
            c = entry.get("comment")
            if c:
                texts.append(str(c))
        if texts:
            return " | ".join(texts)
    return ""

def _request_with_retry(method, url, headers=None, verify=False, max_retries=5, backoff_base=0.8):
    """
    Do a requests.<method> with 429/5xx retry and exponential backoff.
    Respects Retry-After header if present.
    """
    for attempt in range(1, max_retries + 1):
        r = requests.request(method, url, headers=headers, verify=verify)
        # Success
        if r.status_code < 400:
            return r
        # Handle 429 / 5xx with backoff
        if r.status_code == 429 or 500 <= r.status_code < 600:
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = backoff_base * (2 ** (attempt - 1))
            else:
                wait = backoff_base * (2 ** (attempt - 1))
            time.sleep(wait)
            continue
        # Other errors: raise immediately
        r.raise_for_status()
    # If we’re here, we exhausted retries
    r.raise_for_status()

def extract_rule_info(rule):
    """Extract all required fields for CSV output."""
    rule_name = rule.get("name", "")
    action = rule.get("action", "")
    enabled = _get_bool_field(rule, "enabled")  # <-- NEW

    source_zones = _format_objects_and_literals(rule.get("sourceZones"))
    destination_zones = _format_objects_and_literals(rule.get("destinationZones"))
    source_networks = _format_objects_and_literals(rule.get("sourceNetworks"))
    destination_networks = _format_objects_and_literals(rule.get("destinationNetworks"))
    application_filters = _format_app_filters(rule)
    source_ports = _format_objects_and_literals(rule.get("sourcePorts"))
    destination_ports = _format_objects_and_literals(rule.get("destinationPorts"))

    intrusion_policy = ""
    for key in ("intrusionPolicy", "ipsPolicy"):
        ipol = rule.get(key)
        if isinstance(ipol, dict):
            intrusion_policy = ipol.get("name") or ipol.get("id") or ""
            if intrusion_policy:
                break

    log_begin = _get_bool_field(rule, "logBegin", "logAtBeginning")
    log_end = _get_bool_field(rule, "logEnd", "logAtEnd")
    comments = _format_comments(rule)

    return [
        rule_name,
        action,
        enabled,
        source_zones,
        destination_zones,
        source_networks,
        destination_networks,
        application_filters,
        source_ports,
        destination_ports,
        intrusion_policy,
        log_begin,
        log_end,
        comments,
    ]

# === Main ===
def main():
    if len(sys.argv) != 2:
        print("Usage: python policy_pull.py \"<PolicyName>\"")
        sys.exit(1)

    policy_name = sys.argv[1]
    safe_filename = policy_name.replace(" ", "_").replace("/", "_")
    output_file = f"outputs/{safe_filename}_rules.csv"

    # Ensure outputs directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    token = get_token()
    headers = {
        'X-auth-access-token': token,
        'Content-Type': 'application/json'
    }

    print(f"Fetching policy '{policy_name}'...")

    try:
        policy_id = get_policy_id(headers, policy_name)
    except ValueError as e:
        print(str(e))
        sys.exit(1)

    print(f"✅ Found policy ID: {policy_id}")

    rules_summary = list_rules(headers, policy_id)
    print(f"📋 Number of rules found: {len(rules_summary)}")

    header = [
        "Rule Name",
        "Action",
        "Enabled",  # <-- NEW
        "Source Zones",
        "Destination Zones",
        "Source Networks",
        "Destination Networks",
        "Application filters",
        "Source Ports",
        "Destination Ports",
        "Intrusion Policy",
        "Log at Beginning of Connection",
        "Log at End of Connection",
        "Comments",
    ]

    with open(output_file, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for item in rules_summary:
            # If expanded=true delivered full rule objects, great.
            # Some FMC versions may still give partials; we detect and fetch detail as needed.
            rule_obj = item
            # Heuristic: if some expected fields are missing (e.g., sourcePorts, intrusionPolicy),
            # fetch the full rule with backoff (rate-limit safe).
            needs_detail = not any(k in item for k in ("sourcePorts", "destinationPorts", "intrusionPolicy", "applications"))
            if needs_detail and item.get("id"):
                rule_obj = fetch_access_rule(headers, policy_id, item["id"])
                # Tiny courtesy delay to be gentle on rate limits (optional)
                time.sleep(0.05)

            row = extract_rule_info(rule_obj)
            writer.writerow(row)

    print(f"✅ CSV file created: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    main()
