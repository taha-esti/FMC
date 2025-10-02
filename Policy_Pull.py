import requests
import sys
from requests.auth import HTTPBasicAuth
from pprint import pprint
import urllib3

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === FMC Configuration ===
FMC_HOST = '10.255.255.8'
FMC_USER = 'apiUser'
FMC_PASS = 'ESTI2025!'
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"
POLICY_NAME = 'My_Access_Policy'


def get_token():
    url = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = requests.post(url, auth=HTTPBasicAuth(FMC_USER, FMC_PASS), verify=False)
    r.raise_for_status()
    return r.headers['X-auth-access-token']


def get_policy_id(headers):
    url = f"{BASE_URL}/policy/accesspolicies"
    r = requests.get(url, headers=headers, verify=False)
    r.raise_for_status()
    for item in r.json().get('items', []):
        if item['name'] == POLICY_NAME:
            return item['id']
    raise ValueError(f"Policy '{POLICY_NAME}' not found")


def get_rule_id_by_name(headers, policy_id, rule_name):
    url = f"{BASE_URL}/policy/accesspolicies/{policy_id}/accessrules?limit=1000"
    r = requests.get(url, headers=headers, verify=False)
    r.raise_for_status()
    for item in r.json().get('items', []):
        if item['name'] == rule_name:
            return item['id']
    raise ValueError(f"Rule '{rule_name}' not found in policy ID {policy_id}")


def fetch_access_rule(headers, policy_id, rule_id):
    url = f"{BASE_URL}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}"
    r = requests.get(url, headers=headers, verify=False)
    r.raise_for_status()
    return r.json()


def main():
    if len(sys.argv) != 2:
        print("Usage: python policy_pull.py <RuleName>")
        sys.exit(1)

    rule_name = sys.argv[1]

    token = get_token()
    headers = {
        'X-auth-access-token': token,
        'Content-Type': 'application/json'
    }

    policy_id = get_policy_id(headers)
    print(f"✅ Found policy ID: {policy_id}")

    rule_id = get_rule_id_by_name(headers, policy_id, rule_name)
    print(f"✅ Found rule ID: {rule_id}")

    rule_json = fetch_access_rule(headers, policy_id, rule_id)

    print("📦 Access Rule JSON:")
    pprint(rule_json)


if __name__ == "__main__":
    main()
