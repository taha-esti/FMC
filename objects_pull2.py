import requests
import sys
import csv
import os
from collections import defaultdict
from requests.auth import HTTPBasicAuth
import urllib3

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
FMC_HOST = '10.255.255.8'
FMC_USER = 'apiUser'
FMC_PASS = 'ESTI2025!'
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"


# === Auth ===

def get_token():
    url = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = requests.post(url, auth=HTTPBasicAuth(FMC_USER, FMC_PASS), verify=False)
    r.raise_for_status()
    return r.headers['X-auth-access-token']


# === Generic paging helper ===

def get_all_items(url, headers):
    """
    Fetch all items from an FMC collection endpoint, following paging if present.
    Returns the raw 'items' list (summary objects).
    """
    items = []
    next_url = url

    while next_url:
        r = requests.get(next_url, headers=headers, verify=False)
        r.raise_for_status()
        data = r.json()

        items.extend(data.get("items", []))

        paging = data.get("paging") or data.get("metadata", {}).get("paging")
        if paging and paging.get("next"):
            next_url = paging["next"]
        else:
            next_url = None

    return items


def fetch_full_object(item, headers):
    """
    Given a summary object, fetch the full object from its self link (if present).
    Falls back to the summary if no self link exists.
    """
    self_link = item.get("links", {}).get("self")
    if not self_link:
        return item

    r = requests.get(self_link, headers=headers, verify=False)
    r.raise_for_status()
    return r.json()


# === Object fetching / processing ===

def fetch_all_objects(headers):
    """
    Fetch hosts, networks, ranges, FQDNs, and network groups.

    Returns:
        all_objects: list of dicts with:
            - id
            - name
            - type
            - value
            - description
        groups_raw: list of full NetworkGroup JSON objects
    """
    collection_urls = [
        f"{BASE_URL}/object/hosts?limit=1000",
        f"{BASE_URL}/object/networks?limit=1000",
        f"{BASE_URL}/object/ranges?limit=1000",
        f"{BASE_URL}/object/fqdns?limit=1000",
        f"{BASE_URL}/object/networkgroups?limit=1000",
    ]

    all_objects = []
    groups_raw = []

    for url in collection_urls:
        print(f"📥 Fetching from {url} ...")
        summary_items = get_all_items(url, headers)
        print(f"   → {len(summary_items)} items (summary)")

        for summary in summary_items:
            full = fetch_full_object(summary, headers)

            obj_id = full.get("id")
            obj_type = full.get("type") or summary.get("type", "")
            name = full.get("name", "")
            desc = full.get("description", "")

            # Default value
            value = ""

            # Normalize type a bit – FMC types are usually "Host", "Network", etc.
            if obj_type in ("Host", "Network", "Range"):
                # IPv4/IPv6 host/network/range objects
                value = full.get("value", "")
            elif obj_type == "FQDN":
                # FQDN objects may use 'value' or 'fqdn' depending on version
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
    output_file = "fmc_objects.csv"

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
