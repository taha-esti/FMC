import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import urllib3
'''
This script reads a CSV file containing definitions for various ProtocolPortObjects (services)
and creates them in Cisco FMC via its REST API. It also groups services into PortObjectGroups
'''
# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# FMC configuration
FMC_HOST = '10.255.255.8'
FMC_USER = 'admin'
FMC_PASS = 'ESit2024!'
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
SERVICE_FILE = 'Service-Objects.csv'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"


def get_token(host: str, user: str, pwd: str) -> str:
    """Authenticate and return FMC token"""
    url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"
    resp = requests.post(url, auth=HTTPBasicAuth(user, pwd), verify=False)
    resp.raise_for_status()
    return resp.headers['X-auth-access-token']


def load_services(path: str) -> pd.DataFrame:
    """Load service definitions from CSV"""
    df = pd.read_csv(path, dtype=str)
    return df.fillna('')


def fetch_existing_services(headers: dict) -> dict:
    """Fetch existing protocol port objects into name->id cache"""
    cache = {}
    r = requests.get(f"{BASE_URL}/object/protocolportobjects", headers=headers, verify=False)
    r.raise_for_status()
    for item in r.json().get('items', []):
        cache[item['name']] = item['id']
    return cache


def create_or_get_service(name: str, protocol: str, port_val: str, headers: dict, cache: dict) -> (str, str):
    """
    Create or retrieve a ProtocolPortObject; uses cache to skip existing.
    Returns (id, 'ProtocolPortObject') or (None, None) if skip.
    """
    # check cache first
    if name in cache:
        print(f"Skipped existing service '{name}'")
        return cache[name], 'ProtocolPortObject'

    payload = {
        'name': name,
        'protocol': protocol.upper(),
        'port': port_val,
        'type': 'ProtocolPortObject'
    }
    resp = requests.post(f"{BASE_URL}/object/protocolportobjects", headers=headers, json=payload, verify=False)
    if resp.status_code == 201:
        obj_id = resp.json()['id']
        cache[name] = obj_id
        return obj_id, 'ProtocolPortObject'
    elif resp.status_code == 400:
        # likely duplicate or invalid skip
        print(f"Skipped existing or invalid service '{name}' (HTTP 400)")
        return None, None
    else:
        resp.raise_for_status()


def build_created_list(df: pd.DataFrame, headers: dict, cache: dict) -> list:
    """Process rows and return list of created items with types"""
    created = []
    for _, row in df.iterrows():
        name = row['name']
        protocol = row['type']
        val = row['value']
        obj_id, obj_type = create_or_get_service(name, protocol, val, headers, cache)
        if not obj_id:
            continue
        print(f"{obj_type} '{name}' => {obj_id}")
        created.append({'id': obj_id, 'type': obj_type, 'group': row.get('group','').strip()})
    return created


def build_groups(created: list) -> dict:
    """Aggregate created items into groups by group name"""
    groups = {}
    for item in created:
        grp = item['group']
        if grp:
            groups.setdefault(grp, []).append({'type': item['type'], 'id': item['id']})
    return groups


def create_groups(groups: dict, headers: dict):
    """Create PortObjectGroup for each group name"""
    for grp_name, members in groups.items():
        payload = {'name': grp_name, 'type': 'PortObjectGroup', 'objects': members}
        resp = requests.post(f"{BASE_URL}/object/portobjectgroups", headers=headers, json=payload, verify=False)
        if resp.status_code == 201:
            print(f"Created group: {grp_name} ({len(members)} members)")
        elif resp.status_code == 400:
            print(f"Group already exists: {grp_name}")
        else:
            resp.raise_for_status()


def main():
    token = get_token(FMC_HOST, FMC_USER, FMC_PASS)
    headers = {'X-auth-access-token': token, 'Content-Type': 'application/json'}
    df = load_services(SERVICE_FILE)
    cache = fetch_existing_services(headers)
    created = build_created_list(df, headers, cache)
    groups = build_groups(created)
    create_groups(groups, headers)

if __name__ == '__main__':
    main()
