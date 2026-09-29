"""Read-only private upstream verification on the authenticated runner target."""

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import subprocess
import socket
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit


def docker(*args):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=15, check=True,
    )
    if len(result.stdout) > 1048576:
        raise ValueError("private_evidence_too_large")
    return result.stdout


def inspect(name, *, image=False):
    value = json.loads(docker(*(["image"] if image else []), "inspect", name))
    if len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("private_runtime_ambiguous")
    return value[0]


def backend(challenge, action):
    value = inspect(challenge["container_name"])
    labels = value["Config"].get("Labels") or {}
    for key, expected in {
        "managed": "true",
        "org_id": challenge["organization_id"],
        "deployment_id": challenge["deployment_id"],
        "revision_id": challenge["revision_id"],
    }.items():
        if labels.get("com.opsctl." + key) != expected:
            raise ValueError("private_backend_identity_mismatch")
    image = inspect(challenge["image"], image=True)
    if (
        value["Config"]["Image"] != challenge["image"]
        or challenge["image"] not in (image.get("RepoDigests") or [])
        or value["Image"] != image["Id"]
        or value["State"].get("Running") is not True
    ):
        raise ValueError("private_backend_revision_mismatch")
    endpoint = urlsplit(challenge["backend_url"])
    bindings = value["NetworkSettings"]["Ports"].get(
        str(challenge["container_port"]) + "/tcp", []
    ) or []
    if {"HostIp": endpoint.hostname, "HostPort": str(endpoint.port)} not in bindings:
        raise ValueError("private_backend_binding_mismatch")
    return {
        "container_id": value["Id"],
        "image_id": value["Image"],
        "started_at": value["State"]["StartedAt"],
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def tls_evidence(peer):
    """Bounded metadata from the same verified connection as the response."""
    certificate = peer.getpeercert(binary_form=True)
    metadata = peer.getpeercert()
    if not certificate or len(certificate) > 65536:
        raise ValueError("private_edge_tls_evidence_missing")
    issuer = ",".join(key + "=" + value for entry in metadata["issuer"] for key, value in entry)
    if not issuer or len(issuer) > 1024:
        raise ValueError("private_edge_tls_evidence_invalid")
    return {
        "status": "verified", "trust_profile": "system_webpki",
        "issuer": issuer,
        "leaf_fingerprint_sha256": hashlib.sha256(certificate).hexdigest(),
        "not_before": datetime.fromtimestamp(
            ssl.cert_time_to_seconds(metadata["notBefore"]), timezone.utc,
        ).isoformat().replace("+00:00", "Z"),
        "not_after": datetime.fromtimestamp(
            ssl.cert_time_to_seconds(metadata["notAfter"]), timezone.utc,
        ).isoformat().replace("+00:00", "Z"),
        "protocol": peer.version(), "reason": None,
    }


def edge_request(challenge):
    """Fetch the public edge with Host/SNI and a pinned public DNS answer."""
    host = challenge["host"]
    addresses = {item[4][0] for item in socket.getaddrinfo(
        host, 443, type=socket.SOCK_STREAM,
    )}
    if not addresses or any(
        not ipaddress.ip_address(value).is_global
        or ipaddress.ip_address(value).is_multicast for value in addresses
    ):
        raise ValueError("private_edge_address_invalid")
    address = sorted(addresses)[0]
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(host, timeout=6, context=context)
    connection._create_connection = lambda unused, timeout, source_address: socket.create_connection(
        (address, 443), timeout, source_address,
    )
    try:
        connection.connect()
        tls = tls_evidence(connection.sock)
        connection.request("GET", challenge["path"], headers={
            "Host": host,
            "X-Opsctl-Verification-Nonce": challenge["nonce"],
        })
        response = connection.getresponse()
        headers = {}
        for name in challenge["cache_header_names"]:
            values = response.headers.get_all(name, [])
            if len(values) != 1 or len(values[0]) > 128:
                raise ValueError("private_edge_cache_evidence_invalid")
            headers[name] = values[0]
        return response.status, response.read(65537), {
            "tls": tls, "destination": address, "cache_headers": headers,
        }
    finally:
        connection.close()


def gateway(challenge):
    candidates = docker(
        "ps", "-q", "--no-trunc",
        "--filter", "label=com.opsctl.managed=true",
        "--filter", "label=com.opsctl.component=traefik_gateway",
        "--filter", "label=com.opsctl.org_id=" + challenge["organization_id"],
    ).splitlines()
    if len(candidates) != 1:
        raise ValueError("private_gateway_identity_ambiguous")
    value = inspect(candidates[0])
    labels = value["Config"].get("Labels") or {}
    if (
        labels.get("com.opsctl.managed") != "true"
        or labels.get("com.opsctl.component") != "traefik_gateway"
        or labels.get("com.opsctl.org_id") != challenge["organization_id"]
        or value["State"].get("Running") is not True
    ):
        raise ValueError("private_gateway_identity_mismatch")
    for line in docker("logs", "--since", challenge["issued_at"], "--tail", "256", value["Id"]).splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("request_X-Opsctl-Verification-Nonce") == challenge["nonce"]:
            raise ValueError("private_nonce_already_used")
    started = datetime.now(timezone.utc).isoformat()
    evidence = {}
    if challenge.get("edge_binding") is not None:
        status, body, evidence = edge_request(challenge)
    else:
        request = urllib.request.Request(
            "http://127.0.0.1:" + str(challenge["gateway_port"]) + challenge["path"],
            headers={
                "Host": challenge["host"],
                "X-Opsctl-Verification-Nonce": challenge["nonce"],
                "Cache-Control": "no-cache, no-store",
            },
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=6) as response:
            status = response.status
            body = response.read(65537)
    if (
        len(body) > 65536
        or status != challenge["expected_status"]
        or challenge["body_contains"] not in body.decode("utf-8", errors="replace")
    ):
        raise ValueError("private_response_mismatch")
    matches = []
    for _ in range(20):
        matches = []
        for line in docker("logs", "--since", started, "--tail", "256", value["Id"]).splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("request_X-Opsctl-Verification-Nonce") == challenge["nonce"]:
                matches.append(entry)
        if matches:
            break
        time.sleep(0.1)
    if len(matches) != 1:
        raise ValueError("private_request_telemetry_missing_or_duplicate")
    entry = matches[0]
    if (
        entry.get("RouterName") != challenge["router"] + "@file"
        or entry.get("ServiceURL") != challenge["backend_url"]
        or entry.get("OriginStatus") != status
        or entry.get("DownstreamStatus") != status
        or entry.get("RequestHost") != challenge["host"]
        or entry.get("RequestMethod") != "GET"
        or entry.get("RequestPath") != challenge["path"]
    ):
        raise ValueError("private_upstream_mismatch")
    if challenge.get("edge_binding") is not None:
        if entry.get("TLSVersion") not in {"1.2", "1.3"}:
            raise ValueError("private_edge_origin_tls_missing")
        evidence["origin_tls_observed"] = True
    return {
        "backend_url": challenge["backend_url"],
        "router": challenge["router"],
        "status": status,
        "body_match": True,
        **evidence,
    }


def main():
    raw = base64.b64decode(sys.argv[1], validate=True)
    if len(raw) > 16384:
        raise ValueError("private_contract_too_large")
    request = json.loads(raw)
    challenge = request["challenge"]
    action = request["action"]
    now = datetime.now(timezone.utc)
    if not (
        datetime.fromisoformat(challenge["issued_at"]) <= now
        <= datetime.fromisoformat(challenge["expires_at"])
    ):
        raise ValueError("private_challenge_expired")
    if action == "gateway":
        observation = gateway(challenge)
    elif action in {"backend_before", "backend_after"}:
        observation = backend(challenge, action)
        if action == "backend_after":
            before = request["before"]
            if any(observation[key] != before[key] for key in observation):
                raise ValueError("private_backend_replaced")
    else:
        raise ValueError("private_action_invalid")
    result = {
        "action": action,
        "nonce": challenge["nonce"],
        "challenge_digest": hashlib.sha256(json.dumps(
            challenge, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode()).hexdigest(),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        **observation,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        reason = str(error)
        code = reason if re.fullmatch(r"private_[a-z_]{1,80}", reason) else "private_verification_failed"
        print(json.dumps({"error_code": code}))
        raise SystemExit(1)
