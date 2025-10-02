import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === FMC Configuration ===
FMC_HOST = '10.255.255.8'
FMC_USER = 'apiUser'
FMC_PASS = 'ESTI2025!'
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"
CSV_FILE = 'policy_test.csv'
POLICY_NAME = 'My_Access_Policy'  # Change as needed


def get_token():
    """
    Authenticate to FMC and return the access token and domain UUID.
    """
    url = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = requests.post(url, auth=HTTPBasicAuth(FMC_USER, FMC_PASS), verify=False)
    r.raise_for_status()
    return r.headers['X-auth-access-token'], r.headers['DOMAIN_UUID']


def get_or_create_access_policy_id(policy_name: str, headers: dict) -> str:
    """
    Retrieve the ID of an existing access policy or create a new one if it doesn't exist.
    """
    url = f"{BASE_URL}/policy/accesspolicies"
    r = requests.get(url, headers=headers, verify=False)
    r.raise_for_status()
    for item in r.json().get('items', []):
        if item['name'] == policy_name:
            print(f"Found existing access policy: {policy_name}")
            return item['id']

    payload = {
        "type": "AccessPolicy",
        "name": policy_name,
        "defaultAction": {"action": "BLOCK"}
    }
    r = requests.post(url, headers=headers, json=payload, verify=False)
    if r.status_code == 201:
        new_id = r.json()['id']
        print(f"Created new access policy: {policy_name} (ID: {new_id})")
        return new_id
    else:
        raise RuntimeError(f"Failed to create access policy '{policy_name}': {r.text}")

def get_existing_objects(endpoint: str, headers: dict, limit: int = None, sort_by: str = None) -> dict:
    """
    Fetch existing FMC objects with optional limit and sorting (done client-side if needed).
    """
    obj_map = {}
    url = f"{BASE_URL}/object/{endpoint}?limit=7000"

    while url:
        r = requests.get(url, headers=headers, verify=False)
        r.raise_for_status()
        data = r.json()

        for item in data.get('items', []):
            obj_map[item['name']] = item['id']
            if limit and not sort_by and len(obj_map) >= limit:
                return obj_map  # early exit if no sorting and limit hit

        next_page = data.get('paging', {}).get('next')
        url = next_page[0] if isinstance(next_page, list) else next_page

    # Client-side sort + limit
    if sort_by:
        reverse = sort_by.endswith(".desc")
        sorted_items = sorted(obj_map.items(), key=lambda x: x[0].lower(), reverse=reverse)
        if limit:
            sorted_items = sorted_items[:limit]
        obj_map = dict(sorted_items)

    return obj_map


def split_objects(field_value: str, obj_map: dict, obj_type: str, debug: bool = False) -> list:
    """
    Split a comma-separated string of object names into a list of dictionaries 
    with type and ID, based on the provided object map.
    """

    if debug:
        print(f"🔍 Processing {obj_type} objects from field: '{field_value}'")
        print(f"🔍 Available {obj_type} objects: {list(obj_map.keys())}")

    # Handle empty or missing field
    if pd.isna(field_value) or not field_value.strip():
        return []
    objs = []
    # Split the field value by commas and strip whitespace
    for name in map(str.strip, field_value.split(',')):
        match = next((k for k in obj_map if k.strip().lower() == name.lower()), None)
        if match:
            objs.append({'type': obj_type, 'id': obj_map[match]})
        else:
            print(f"⚠️ Skipping missing {obj_type} object: {name}")

    if debug:
        print(f"🔍 Processed {len(objs)} {obj_type} objects: {[obj['id'] for obj in objs]}")
    return objs


def create_access_rule(rule: dict, headers: dict, policy_id: str):
    """
    Create a new access rule in the specified access policy.
    The rule is defined by the provided dictionary.
    If the rule is successfully created, print a success message.
    If the creation fails, print an error message with the status code and response text.
    """
    url = f"{BASE_URL}/policy/accesspolicies/{policy_id}/accessrules"
    r = requests.post(url, headers=headers, json=rule, verify=False)
    if r.status_code == 201:
        print(f"✅ Created rule: {rule['name']}")
    else:
        print(f"❌ Failed to create rule '{rule['name']}': {r.status_code} - {r.text}")


def main():
    # Authenticate and get the access token
    token, _ = get_token()
    headers = {'X-auth-access-token': token, 'Content-Type': 'application/json'}

    # Read the CSV file and prepare the DataFrame
    df = pd.read_csv(CSV_FILE, dtype=str).fillna('')
    df.columns = df.columns.str.strip()

    # Ensure required columns are present
    required_columns = {'name', 'action', 'sourceNetworks', 'destinationNetworks', 'destinationPorts'}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in CSV: {missing}")

    # Get access policy ID
    access_policy_id = get_or_create_access_policy_id(POLICY_NAME, headers)

    # Fetch existing objects from FMC
    network_map = get_existing_objects("networks", headers)
    service_map = get_existing_objects("protocolportobjects", headers)
    zone_map = get_existing_objects("securityzones", headers)
    url_map = get_existing_objects("urls", headers)
    url_category_map = get_existing_objects("urlcategories", headers)
    application_map = get_existing_objects("applications", headers)

    print(f"✅ Retrieved {len(application_map)} Applications:")

    # print(f"✅ Retrieved {len(url_category_map)} URL Categories:")
    # for name in sorted(url_category_map.keys(), key=str.lower):
    #     print(f"  - {name}")

    # Process each rule in CSV
    for _, row in df.iterrows():
        print(f"\n🔹 Processing rule: {row['name']}")

        # Split FMC object references
        src_objs = split_objects(row['sourceNetworks'], network_map, 'Network')
        dst_objs = split_objects(row['destinationNetworks'], network_map, 'Network')
        port_objs = split_objects(row['destinationPorts'], service_map, 'ProtocolPortObject')
        src_ports = split_objects(row.get('sourcePorts', ''), service_map, 'ProtocolPortObject')
        src_zones = split_objects(row.get('sourceZones', ''), zone_map, 'SecurityZone')
        dst_zones = split_objects(row.get('destinationZones', ''), zone_map, 'SecurityZone')
        urls = split_objects(row.get('urls', ''), url_map, 'Url')
        applications = split_objects(row.get('applications', ''), application_map, 'Application')

        print(f"🔍 Applications for rule '{row['name']}': {[a['id'] for a in applications]}")

        # Parse urlCategoriesWithReputation
        categories = []
        raw_field = row.get('urlCategoriesWithReputation', '')
        print(f"🔍 Raw urlCategoriesWithReputation: '{raw_field}'")
        for entry in map(str.strip, raw_field.split(',')):
            if not entry:
                continue
            try:
                parts = list(map(str.strip, entry.split('|')))
                cat_name = parts[0]
                rep = parts[1].upper() if len(parts) > 1 and parts[1] else None

                if cat_name in url_category_map:
                    obj = {
                        "type": "UrlCategoryAndReputation",
                        "category": {
                            "name": cat_name,
                            "id": url_category_map[cat_name],
                            "type": "URLCategory"
                        }
                    }
                    if rep:
                        obj["reputation"] = rep
                    categories.append(obj)
                else:
                    print(f"⚠️ Skipping missing URL category: {cat_name}")
            except Exception as e:
                print(f"⚠️ Skipping malformed entry '{entry}': {e}")

        if not src_objs or not dst_objs or not port_objs:
            print(f"⚠️ Skipping rule '{row['name']}' due to missing core objects")
            continue

        # Build the rule payload
        rule = {
            "action": row.get('action', 'ALLOW').upper(),
            "enabled": True,
            "type": "AccessRule",
            "name": row['name'],
            "sourceNetworks": {"objects": src_objs},
            "destinationNetworks": {"objects": dst_objs},
            "destinationPorts": {"objects": port_objs}
        }
        # Optional fields
        if src_ports:
            rule["sourcePorts"] = {"objects": src_ports}
        if src_zones:
            rule["sourceZones"] = {"objects": src_zones}
        if dst_zones:
            rule["destinationZones"] = {"objects": dst_zones}

        if applications:
            rule["applications"] = {"applications": applications}
        if urls or categories:
            rule["urls"] = {}
            if urls:
                rule["urls"]["objects"] = urls
            if categories:
                rule["urls"]["urlCategoriesWithReputation"] = categories

        print("📦 Final rule payload:")
        from pprint import pprint
        pprint(rule)

        create_access_rule(rule, headers, access_policy_id)


if __name__ == "__main__":
    main()