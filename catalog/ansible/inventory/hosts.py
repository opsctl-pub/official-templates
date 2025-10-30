#!/usr/bin/env python3
"""
Dynamic inventory script for Ansible.
Resolves target server details via OpsControl Facets API.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


def _get_api_base() -> str:
    """Return API base URL from env, defaulting to in-cluster address."""
    return os.getenv("API_URL", "http://opsctl-api:8173")


def _get_api_token() -> Optional[str]:
    """Return bearer token for API authentication if provided."""
    token = os.getenv("API_TOKEN")
    return token.strip() if token else None


def fetch_servers(org_id: str) -> Dict[str, Any]:
    """Fetch servers facet for the organization."""
    url = f"{_get_api_base()}/api/v1/facets/servers?organization_id={org_id}"
    req = urllib.request.Request(url)
    token = _get_api_token()
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 401 and token:
            # Retry without token in dev environments
            with urllib.request.urlopen(urllib.request.Request(url)) as response:
                return json.loads(response.read().decode())
        raise


def resolve_server(org_id: str, target_server: str) -> Optional[Dict[str, Any]]:
    """Return server facet entry matching ID or name."""
    try:
        payload = fetch_servers(org_id)
    except Exception as exc:  # noqa: BLE001
        print(f"Error querying Facets API: {exc}", file=sys.stderr)
        return None

    for item in payload.get("items", []):
        if item.get("id") == target_server or item.get("name") == target_server:
            return item
    return None


def build_inventory(server: Optional[Dict[str, Any]], fallback: str) -> Dict[str, Any]:
    """Construct inventory structure."""
    inventory: Dict[str, Any] = {"_meta": {"hostvars": {}}}

    if not server:
        direct_ip = os.getenv("TARGET_SERVER_IP")
        host = direct_ip or fallback
        hostvars = {
            "ansible_host": host,
            "server_id": fallback,
            "server_name": fallback,
            "ansible_user": os.getenv("ANSIBLE_DEFAULT_USER", "root"),
        }

        ssh_key_path = os.getenv("ANSIBLE_SSH_KEY_PATH", "/secrets/ssh_key")
        if os.path.exists(ssh_key_path):
            hostvars["ansible_ssh_private_key_file"] = ssh_key_path

        ssh_args = os.getenv("ANSIBLE_SSH_ARGS")
        if ssh_args:
            hostvars["ansible_ssh_common_args"] = ssh_args

        inventory["all"] = {"hosts": [host]}
        inventory["_meta"]["hostvars"][host] = hostvars
        return inventory

    hostname = server.get("name") or server.get("id") or fallback
    ansible_host = (
        os.getenv("TARGET_SERVER_IP")
        or server.get("ip_address")
        or hostname
    )
    host_label = ansible_host

    inventory["all"] = {"hosts": [host_label]}
    hostvars = {
        "ansible_host": ansible_host,
        "server_id": server.get("id"),
        "provider": server.get("provider"),
        "region": server.get("region"),
        "ansible_user": os.getenv("ANSIBLE_DEFAULT_USER", "root"),
        "server_name": hostname,
    }

    ssh_key_path = os.getenv("ANSIBLE_SSH_KEY_PATH", "/secrets/ssh_key")
    if os.path.exists(ssh_key_path):
        hostvars["ansible_ssh_private_key_file"] = ssh_key_path

    ssh_args = os.getenv("ANSIBLE_SSH_ARGS")
    if ssh_args:
        hostvars["ansible_ssh_common_args"] = ssh_args

    inventory["_meta"]["hostvars"][host_label] = hostvars

    metadata = server.get("metadata") or {}
    environment = metadata.get("environment")
    if environment:
        inventory.setdefault(f"env_{environment}", {"hosts": []})["hosts"].append(host_label)

    provider = server.get("provider")
    if provider:
        inventory.setdefault(f"provider_{provider}", {"hosts": []})["hosts"].append(host_label)

    return inventory


def main() -> int:
    """Entry point."""
    target_server = os.getenv("TARGET_SERVER") or os.getenv("target_server")
    org_id = os.getenv("ORGANIZATION_ID") or os.getenv("org_id")

    if not target_server or not org_id:
        print("Inventory requires TARGET_SERVER and ORGANIZATION_ID", file=sys.stderr)
        print(json.dumps({"_meta": {"hostvars": {}}}))
        return 0

    target_ip = os.getenv("TARGET_SERVER_IP")
    server = None
    if target_ip:
        server = {
            "id": target_server,
            "name": target_server,
            "ip_address": target_ip,
        }
    else:
        server = resolve_server(org_id, target_server)
    inventory = build_inventory(server, target_server)
    print(json.dumps(inventory, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
