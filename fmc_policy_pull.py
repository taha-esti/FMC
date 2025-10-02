#!/usr/bin/env python3
"""
FMC Access Policies (and Rules) -> CSV

- Writes access_policies.csv with all Access Policies in a domain
- Writes access_policy_rules.csv with all rules for each policy
- Follows FMC paging automatically
"""

import csv
import sys
from typing import Dict, Iterable, List, Optional
import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === FMC Configuration ===
FMC_HOST = '10.255.255.8'
FMC_USER = 'apiUser'
FMC_PASS = 'ESTI2025!'
DOMAIN_UUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"


# ---------- HTTP helpers ----------

def get_token() -> Dict[str, str]:
    url = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"
    r = requests.post(url, auth=HTTPBasicAuth(FMC_USER, FMC_PASS), verify=False)
    r.raise_for_status()
    token = r.headers.get("X-auth-access-token")
    if not token:
        raise RuntimeError("No X-auth-access-token header returned from FMC.")
    return {"X-auth-access-token": token, "Content-Type": "application/json"}


def get_all_items(url: str, headers: Dict[str, str]) -> List[dict]:
    items: List[dict] = []
    next_url = url if ("?" in url) else f"{url}?limit=1000"

    while next_url:
        r = requests.get(next_url, headers=headers, verify=False)
        r.raise_for_status()
        data = r.json() or {}
        page_items = data.get("items", [])
        if not isinstance(page_items, list):
            page_items = []
        items.extend(page_items)
        paging = data.get("paging", {})
        next_url = paging.get("next")

    return items


# ---------- Flattening helpers ----------

def names_from_list(objs: Optional[Iterable[dict]]) -> str:
    if not objs:
        return ""
    return "; ".join([str(x.get("name", "")) for x in objs if isinstance(x, dict)])


def names_from_objlist_key(obj: dict, key: str) -> str:
    if not obj:
        return ""
    val = obj.get(key)
    if isinstance(val, dict) and "objects" in val and isinstance(val["objects"], list):
        return names_from_list(val["objects"])
    if isinstance(val, list):
        return names_from_list(val)
    return ""


def safe_get(d: dict, *path, default=""):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur if cur is not None else default


# ---------- CSV writers ----------

def write_policies_csv(policies: List[dict], outfile: str = "access_policies.csv") -> None:
    fieldnames = [
        "id", "name", "type", "description",
        "defaultAction.action", "defaultAction.logBegin", "defaultAction.logEnd",
        "defaultAction.sendEventsToFMC",
        "lastModifiedTime", "metadata.domain.name", "metadata.domain.id"
    ]
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for p in policies:
            row = {
                "id": p.get("id", ""),
                "name": p.get("name", ""),
                "type": p.get("type", ""),
                "description": p.get("description", ""),
                "defaultAction.action": safe_get(p, "defaultAction", "action"),
                "defaultAction.logBegin": safe_get(p, "defaultAction", "logBegin"),
                "defaultAction.logEnd": safe_get(p, "defaultAction", "logEnd"),
                "defaultAction.sendEventsToFMC": safe_get(p, "defaultAction", "sendEventsToFMC"),
                "lastModifiedTime": p.get("lastModifiedTime", ""),
                "metadata.domain.name": safe_get(p, "metadata", "domain", "name"),
                "metadata.domain.id": safe_get(p, "metadata", "domain", "id"),
            }
            w.writerow(row)


def write_rules_csv(headers: Dict[str, str], policies: List[dict],
                    outfile: str = "access_policy_rules.csv") -> None:
    fieldnames = [
        "policy_id", "policy_name",
        "rule_id", "rule_name", "enabled", "action",
        "sourceZones", "destinationZones",
        "sourceNetworks", "destinationNetworks",
        "sourcePorts", "destinationPorts",
        "urls", "urlCategories", "applications",
        "users", "vlanTags",
        "ipsPolicy", "filePolicy", "securityIntelligence",
        "logBegin", "logEnd", "sendEventsToFMC",
        "hitCount", "lastModifiedTime"
    ]

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for p in policies:
            pid = p.get("id")
            pname = p.get("name", "")
            if not pid:
                continue

            rules_url = f"{BASE_URL}/policy/accesspolicies/{pid}/accessrules"
            rules = get_all_items(rules_url, headers=headers)

            for r in rules:
                row = {
                    "policy_id": pid,
                    "policy_name": pname,
                    "rule_id": r.get("id", ""),
                    "rule_name": r.get("name", ""),
                    "enabled": r.get("enabled", ""),
                    "action": r.get("action", ""),
                    "sourceZones": names_from_objlist_key(r, "sourceZones"),
                    "destinationZones": names_from_objlist_key(r, "destinationZones"),
                    "sourceNetworks": names_from_objlist_key(r, "sourceNetworks"),
                    "destinationNetworks": names_from_objlist_key(r, "destinationNetworks"),
                    "sourcePorts": names_from_objlist_key(r, "sourcePorts"),
                    "destinationPorts": names_from_objlist_key(r, "destinationPorts"),
                    "urls": names_from_objlist_key(r, "urls"),
                    "urlCategories": names_from_objlist_key(r, "urlCategories"),
                    "applications": names_from_objlist_key(r, "applications"),
                    "users": names_from_objlist_key(r, "users"),
                    "vlanTags": names_from_objlist_key(r, "vlanTags"),
                    "ipsPolicy": names_from_list([safe_get(r, "ipsPolicy")]) if safe_get(r, "ipsPolicy") else "",
                    "filePolicy": names_from_list([safe_get(r, "filePolicy")]) if safe_get(r, "filePolicy") else "",
                    "securityIntelligence": names_from_list([safe_get(r, "securityIntelligence")]) if safe_get(r, "securityIntelligence") else "",
                    "logBegin": r.get("logBegin", ""),
                    "logEnd": r.get("logEnd", ""),
                    "sendEventsToFMC": r.get("sendEventsToFMC", ""),
                    "hitCount": safe_get(r, "metadata", "ruleIndex"),
                    "lastModifiedTime": r.get("lastModifiedTime", ""),
                }
                w.writerow(row)


# ---------- Main ----------

def main():
    try:
        headers = get_token()
    except requests.HTTPError as e:
        print(f"[AUTH ERROR] {e.response.status_code} {e.response.text}", file=sys.stderr)
        sys.exit(2)

    try:
        policies_url = f"{BASE_URL}/policy/accesspolicies"
        policies = get_all_items(policies_url, headers=headers)
        if not policies:
            print("No access policies found.")
        else:
            write_policies_csv(policies)
            print(f"✅ Wrote {len(policies)} policies to access_policies.csv")

            write_rules_csv(headers, policies)
            print(f"✅ Wrote rules to access_policy_rules.csv")

    except requests.HTTPError as e:
        print(f"[HTTP ERROR] {e.response.status_code} {e.response.text}", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(4)


if __name__ == "__main__":
    main()
