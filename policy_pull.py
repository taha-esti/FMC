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
FMC_HOST = "10.255.255.8"
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

def list_rules(headers, policy_id):
    rules = []
    url = f"{BASE_URL}/policy/accesspolicies/{policy_id}/accessrules?expanded=true&limit=1000"

    while url:
        r = requests.get(url, headers=headers, verify=False)
        r.raise_for_status()
        data = r.json()

        items = data.get("items", [])
        rules.extend(items)

        paging = data.get("paging")
        next_href = None

        # Case 1: paging is a dict (most common FMC shape)
        if isinstance(paging, dict):
            # Sometimes next is directly under paging["next"]["href"]
            if isinstance(paging.get("next"), dict):
                next_href = paging["next"].get("href")
            # Sometimes there's a pages sub-object: paging["pages"]["next"]["href"]
            elif isinstance(paging.get("pages"), dict):
                next_href = (paging["pages"].get("next") or {}).get("href")
            # Very rare: href directly on paging
            elif "href" in paging:
                next_href = paging.get("href")

        # Case 2: paging is a list (what you’re seeing now)
        elif isinstance(paging, list) and paging:
            first = paging[0]
            if isinstance(first, dict):
                if isinstance(first.get("next"), dict):
                    next_href = first["next"].get("href")
                elif isinstance(first.get("pages"), dict):
                    next_href = (first["pages"].get("next") or {}).get("href")
                elif "href" in first:
                    next_href = first.get("href")

        # If we didn't find a next_href, stop paginating
        url = next_href

    return rules


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

def _extract_metadata_field(rule, key):
    """
    Try to pull a string field from either the rule itself
    or from rule['metadata'][key].
    """
    # Sometimes it might be directly on the rule (rare but cheap to check)
    direct = rule.get(key)
    if isinstance(direct, str):
        return direct

    meta = rule.get("metadata")
    if isinstance(meta, dict):
        val = meta.get(key)
        if isinstance(val, str):
            return val

    return ""


def extract_rule_info(rule):
    """Extract all required fields for CSV output."""
    rule_name = rule.get("name", "")
    action = rule.get("action", "")
    enabled = _get_bool_field(rule, "enabled")
    meta = rule.get("metadata", {})
    section = meta.get("section", "")
    category = meta.get("category", "")
    if category == "--Undefined--":
        category = ""

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
        section,
        category,
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
        "Enabled",
        "Section",
        "Category",
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
