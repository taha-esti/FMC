import requests
import csv
import os
from collections import defaultdict
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
This script fetches existing port objects from Cisco FMC and writes
them to a CSV file.

Objects included (depending on FMC version/endpoints available):
  - TCP/UDP port objects
  - Protocol port objects
  - Port groups / protocol port object groups

Output CSV columns:
  name, type, value, description, group

Usage:
    python ports_pull.py
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


def safe_get_all_items(url, headers):
    """
    Wrapper around get_all_items that gracefully skips 404 endpoints.
    """
    try:
        return get_all_items(url, headers)
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"   → Endpoint {url} not found (404), skipping")
            return []
        raise


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

def fetch_all_port_objects(headers):
    """
    Fetch port objects and port groups from all likely endpoints.

    Returns:
        all_objects: list of dicts with:
            - id
            - name
            - type
            - value
            - description
        groups_raw: list of full group JSON objects (for membership mapping)
    """

    # Try all common port-related endpoints; some may 404 depending on FMC version.
    collection_urls = [
        f"{BASE_URL}/object/ports?limit=1000",
        f"{BASE_URL}/object/protocolportobjects?limit=1000",
        f"{BASE_URL}/object/portgroups?limit=1000",
        f"{BASE_URL}/object/protocolportobjectgroups?limit=1000",
    ]

    all_objects = []
    groups_raw = []

    for url in collection_urls:
        print(f"📥 Fetching from {url} ...")
        summary_items = safe_get_all_items(url, headers)
        if not summary_items:
            continue

        print(f"   → {len(summary_items)} items (summary)")

        for summary in summary_items:
            full = fetch_full_object(summary, headers)

            obj_id = full.get("id")
            obj_type = (full.get("type") or summary.get("type") or "").strip()
            name = full.get("name", "")
            desc = full.get("description", "")

            # Determine if this is a group by type name containing "Group"
            is_group = "Group" in obj_type

            # Build a "value" string
            if not is_group:
                # Regular port object: format like TCP/80 or UDP/53-55
                port = full.get("port") or full.get("value", "")
                proto = full.get("protocol") or full.get("proto", "")
                if isinstance(proto, str):
                    proto = proto.upper()
                if port and proto:
                    value = f"{proto}/{port}"
                else:
                    value = port or proto or ""
            else:
                # Group: summarize members as value
                members = []

                # Objects referenced by ID
                for m in full.get("objects", []):
                    m_name = m.get("name") or m.get("value")
                    if m_name:
                        members.append(str(m_name))

                # Literal ports (no separate object)
                for lit in full.get("literals", []):
                    lit_port = lit.get("port") or lit.get("value")
                    lit_proto = lit.get("protocol") or lit.get("proto", "")
                    if isinstance(lit_proto, str):
                        lit_proto = lit_proto.upper()
                    if lit_port and lit_proto:
                        members.append(f"{lit_proto}/{lit_port}")
                    elif lit_port:
                        members.append(str(lit_port))

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
    output_file = "port_objects_fmc.csv"

    token = get_token()
    headers = {
        'X-auth-access-token': token,
        'Content-Type': 'application/json'
    }

    print("🔐 Authenticated to FMC, fetching port objects...")

    all_objects, groups_raw = fetch_all_port_objects(headers)
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
    print(f"   Total port objects written: {len(all_objects)}")


if __name__ == "__main__":
    main()
