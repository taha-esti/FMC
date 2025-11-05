import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import urllib3
'''
This script reads a CSV file containing definitions for various FMC objects (hosts, networks, FQDNs, ranges, URLs)
and creates them in Cisco FMC via its REST API. It also groups objects into NetworkGroups and UrlGroups based on the CSV data.
'''
 
# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# Mapping object types to FMC endpoints
OBJECT_ENDPOINTS = {
    'host': 'hosts',
    'network': 'networks',
    'fqdn': 'fqdns',
    'range': 'ranges',
    'url': 'urls'
}
# Group category to endpoint and FMC group type
GROUP_CONFIG = {
    'network': ('networkgroups', 'NetworkGroup'),
    'url': ('urlgroups', 'UrlGroup')
}
 
class FMCClient:
    # FMC API client for creating and managing objects in Cisco FMC
    # Handles authentication, object creation, and group management
    def __init__(self, host, username, password, domain_uuid):
        self.base = f"https://{host}/api/fmc_config/v1/domain/{domain_uuid}"
        self.token = self._login(host, username, password)
        # preload existing objects for lookup
        self.existing = {otype: self._fetch_objects(endpoint)
                         for otype, endpoint in OBJECT_ENDPOINTS.items() if otype != 'url'}
        # url objects separate
        self.existing['url'] = self._fetch_objects(OBJECT_ENDPOINTS['url'])

    
    def _login(self, host, user, pwd):
        """Authenticate and return FMC token"""
        # Generate token for authentication
        # Returns the token for subsequent requests
        url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"
        r = requests.post(url, auth=HTTPBasicAuth(user, pwd), verify=False)
        r.raise_for_status()
        return r.headers['X-auth-access-token']
 
    def _headers(self):
        """Return headers for API requests"""
        # Include the token in the headers for authentication
        return {'X-auth-access-token': self.token, 'Content-Type': 'application/json'}
 
    def _fetch_objects(self, endpoint):
        """Fetch all objects from a given endpoint into a name->id map"""
        # Fetch existing objects from the FMC API
        # Returns a dictionary mapping object names to their IDs
        url = f"{self.base}/object/{endpoint}"
        r = requests.get(url, headers=self._headers(), verify=False)
        r.raise_for_status()
        items = r.json().get('items', [])
        return {item['name']: item['id'] for item in items}
 
    def create_object(self, otype, name, value, description, dns_resolution=None):
        """Create an object of a given type, or return existing ID"""
        # Create or retrieve an object in the FMC
        endpoint = OBJECT_ENDPOINTS[otype]
        payload = {'name': name, 'type': otype, 'description': description}
        if otype == 'fqdn':
            payload['value'] = value
            if dns_resolution:
                payload['dnsResolution'] = dns_resolution
        elif otype == 'url':
            payload['url'] = value
        else:
            payload['value'] = value
        r = requests.post(f"{self.base}/object/{endpoint}", headers=self._headers(), json=payload, verify=False)
        # on success, add to existing cache
        if r.status_code == 201:
            obj_id = r.json().get('id')
            self.existing[otype][name] = obj_id
        return r
 
    def get_object_id(self, otype, name):
        """Lookup object ID from cache, return None if not found"""
        # Retrieve the ID of an object by its name from the existing cache
        # Returns the ID if found, otherwise None
        return self.existing.get(otype, {}).get(name)
 
    def create_group(self, category, group_name, members):
        """Create a group of objects"""
        # Create a group of objects in the FMC
        endpoint, gtype = GROUP_CONFIG[category]
        payload = {'name': group_name, 'type': gtype, 'objects': members}
        return requests.post(f"{self.base}/object/{endpoint}", headers=self._headers(), json=payload, verify=False)
 
 
def load_objects(csv_file):
    """Load object definitions from CSV"""
    # Load object definitions from a CSV file
    return pd.read_csv(csv_file, dtype=str).fillna('')
 
 
def main():
    # Configuration
    host = '10.255.255.8'
    user = 'apiUser'
    pwd = 'ESTI2025!'
    domain = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
    csv_file = 'Objects.csv'
 
    fmc = FMCClient(host, user, pwd, domain)
    df = load_objects(csv_file)
 
    created = []
    # 1) Create or fetch objects
    for _, row in df.iterrows():
        otype = row['type'].strip().lower()
        name, val = row['name'], row['value']
        resp = fmc.create_object(otype, name, val, row.get('description',''), row.get('dnsResolution',''))
        if resp.status_code == 201:
            oid = fmc.get_object_id(otype, name)
            print(f"Created {otype} '{name}': {oid}")
        elif resp.status_code == 400:
            oid = fmc.get_object_id(otype, name)
            if oid:
                print(f"Existing {otype} '{name}': {oid}")
            else:
                print(f"Failed to create or find {otype} '{name}'")
                continue
        else:
            resp.raise_for_status()
        created.append({'type': otype, 'id': oid, 'group': row.get('group','')})
 
    # 2) Build and create groups
    groups = {}
    for item in created:
        grp = item['group']
        if not grp:
            continue
        cat = 'url' if item['type'] == 'url' else 'network'
        groups.setdefault((grp, cat), []).append({'type': item['type'].capitalize(), 'id': item['id']})
 
    for (grp_name, cat), members in groups.items():
        resp = fmc.create_group(cat, grp_name, members)
        if resp.status_code == 201:
            print(f"Created group '{grp_name}' ({cat}) with {len(members)} members")
        else:
            print(f"Skipped group '{grp_name}' ({cat}) (status {resp.status_code})")
 
if __name__ == '__main__':
    main()
 
 