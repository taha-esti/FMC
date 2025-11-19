import requests
import sys
import csv
import os
from collections import defaultdict
from requests.auth import HTTPBasicAuth
import urllib3
import getpass
import time

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
This script fetches existing network-related objects from Cisco FMC and writes
them to a CSV file.

Objects included:
  - Hosts
  - Networks
  - Ranges
  - FQDNs
  - Network Groups

Output CSV columns:
  name, type, value, description, group

Usage:
    python objects_pull.py
"""

# === FMC Configuration ===
FMC_HOST = input("FMC IP address: ")
FMC_USER = input("FMC Username: ")
FMC_PASS = getpass.getpass("FMC Password: ")
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"


# === Auth ===

def get_token():
    url = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = requests.post(url, auth=HTTPBasicAuth(FMC_USER, FMC_PASS), verify=False)
    r.raise_for_status()
    return r.headers['X-auth-access-token']


def get_with_retry(url, headers, max_retries=5):
    """
    Wrapper around requests.get that retries on HTTP 429 with exponential backoff.
    """
    backoff = 1  # starting backoff in seconds

    for attempt in range(1, max_retries + 1):
        r = requests.get(url, headers=headers, verify=False)

        # Handle rate limiting
        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    wait = int(retry_after)
                except ValueError:
                    wait = backoff
            else:
                wait = backoff

            print(f"⚠️ 429 from {url} (attempt {attempt}/{max_retries}), sleeping {wait} seconds...")
            time.sleep(wait)
            backoff = min(backoff * 2, 60)  # cap the backoff
            continue

        # For anything else, raise if it's bad; return if OK
        r.raise_for_status()
        return r

    raise requests.HTTPError(f"Too many 429 responses for {url}")


# === Generic paging helper ===

def get_all_items(url, headers):
    """
    Fetch all items from an FMC collection endpoint, following paging if present.
    Returns the raw 'items' list (each item is already expanded when using expanded=true).
    """
    items = []
    next_url = url

    while next_url:
        r = get_with_retry(next_url, headers=headers)
        data = r.json()

        if isinstance(data.get("items"), list):
            items.extend(data["items"])

        # Paging can live under either 'paging' or 'metadata.paging'
        paging = data.get("paging") or data.get("metadata", {}).get("paging")

        if paging:
            nxt = paging.get("next")
            if isinstance(nxt, str):
                next_url = nxt
            elif isinstance(nxt, dict):
                next_url = nxt.get("href")
            else:
                next_url = None
        else:
            next_url = None

        # Small sleep between pages to be extra nice to FMC
        time.sleep(0.1)

    return items


# === Object fetching / processing ===

def fetch_all_objects(headers):
    """
    Fetch hosts, networks, ranges, FQDNs, and network groups.

    Uses ?expanded=true so each item in 'items' is already a full object,
    avoiding one GET per object (which was causing 429 rate limits).

    Returns:
        all_objects: list of dicts with:
            - id
            - name
            - type
            - value
            - description
        groups_raw: list of full NetworkGroup JSON objects
    """
    # Use expanded=true so we don't have to fetch each object individually
    collection_urls = [
        f"{BASE_URL}/object/hosts?limit=500&expanded=true",
        f"{BASE_URL}/object/networks?limit=500&expanded=true",
        f"{BASE_URL}/object/ranges?limit=500&expanded=true",
        f"{BASE_URL}/object/fqdns?limit=500&expanded=true",
        f"{BASE_URL}/object/networkgroups?limit=200&expanded=true",
    ]

    all_objects = []
    groups_raw = []

    for url in collection_urls:
        print(f"📥 Fetching from {url} ...")
        items = get_all_items(url, headers)
        print(f"   → {len(items)} items (expanded)")

        for full in items:
            obj_id = full.get("id")
            obj_type = full.get("type", "")
            name = full.get("name", "")
            desc = full.get("description", "")

            value = ""

            if obj_type in ("Host", "Network", "Range"):
                value = full.get("value", "")
            elif obj_type == "FQDN":
                value = full.get("value") or full.get("fqdn", "")
            elif obj_type == "NetworkGroup":
                # For groups, summarize members as value
                members = []
                for m in full.get("objects", []):
                    m_name = m.get("name") or m.get("value")
                    if m_name:
                        members.append(str(m_name))
                for lit in full.get("literals", []):
                    lit_val = lit.get("value") or lit.get("name")
                    if lit_val:
                        members.append(str(lit_val))
                value = "; ".join(members)
                groups_raw.append(full)

            all_objects.append({
                "id": obj_id,
                "name": name,
                "type": obj_type,
                "value": value,
                "description": desc,
            })

    return all_objects, groups_raw


def map_object_to_groups(all_objects, groups_raw):
    """
    Build a mapping from object ID to group names it's a member of,
    then annotate all_objects with a 'group' field.
    """
    id_to_groups = defaultdict(list)

    for g in groups_raw:
        g_name = g.get("name", "")
        if not g_name:
            continue

        for member in g.get("objects", []):
            mid = member.get("id")
            if mid:
                id_to_groups[mid].append(g_name)

        # literals have no ID and can't be mapped back reliably

    for obj in all_objects:
        groups = id_to_groups.get(obj["id"], [])
        if groups:
            obj["group"] = "; ".join(sorted(set(groups)))
        else:
            obj["group"] = ""

    return all_objects


# === Main ===

def main():
    output_file = "outputs/fmc_objects.csv"
    os.makedirs("outputs", exist_ok=True)

    token = get_token()
    headers = {
        'X-auth-access-token': token,
        'Content-Type': 'application/json'
    }

    print("🔐 Authenticated to FMC, fetching objects...")

    all_objects, groups_raw = fetch_all_objects(headers)
    all_objects = map_object_to_groups(all_objects, groups_raw)

    # Write CSV
    header = ["name", "type", "value", "description", "group"]

    with open(output_file, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for obj in all_objects:
            writer.writerow([
                obj.get("name", ""),
                obj.get("type", ""),
                obj.get("value", ""),
                obj.get("description", ""),
                obj.get("group", ""),
            ])

    print(f"✅ CSV file created: {os.path.abspath(output_file)}")
    print(f"   Total objects written: {len(all_objects)}")


if __name__ == "__main__":
    main()
