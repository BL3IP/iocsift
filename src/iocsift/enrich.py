"""Enrichment for extracted IOCs.

Offline by default (pure stdlib classification). With ``online=True`` it adds reverse
DNS and a Shodan InternetDB lookup (https://internetdb.shodan.io/) which is FREE and
needs NO API key. All network calls fail soft.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.request
from typing import Any, Dict
from urllib.parse import urlparse

from .models import IOC

_INTERNETDB = "https://internetdb.shodan.io/{}"


def enrich_ioc(ioc: IOC, online: bool = False) -> IOC:
    """Populate ``ioc.enrichment`` in place and return the IOC."""
    t = ioc.type
    if t in ("ipv4", "ipv6"):
        ioc.enrichment = _enrich_ip(ioc.value, online)
    elif t in ("md5", "sha1", "sha256"):
        ioc.enrichment = {"algorithm": t, "length": len(ioc.value)}
    elif t == "domain":
        ioc.enrichment = _enrich_domain(ioc.value, online)
    elif t == "url":
        ioc.enrichment = _enrich_url(ioc.value)
    elif t == "email":
        ioc.enrichment = {"domain": ioc.value.split("@")[-1]}
    elif t == "cve":
        ioc.enrichment = {"year": int(ioc.value.split("-")[1])}
    return ioc


def _enrich_ip(value: str, online: bool) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        obj = ipaddress.ip_address(value)
    except ValueError:
        return {"error": "invalid ip address"}
    info.update(
        version=obj.version,
        is_private=obj.is_private,
        is_global=obj.is_global,
        is_loopback=obj.is_loopback,
        is_reserved=obj.is_reserved,
        is_multicast=obj.is_multicast,
    )
    if online and obj.is_global:
        info["reverse_dns"] = _reverse_dns(value)
        info["shodan_internetdb"] = _internetdb(value)
    return info


def _enrich_domain(value: str, online: bool) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "tld": value.rsplit(".", 1)[-1].lower(),
        "labels": value.count(".") + 1,
    }
    if online:
        try:
            info["resolves_to"] = socket.gethostbyname(value)
        except OSError:
            info["resolves_to"] = None
    return info


def _enrich_url(value: str) -> Dict[str, Any]:
    parsed = urlparse(value)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
    }


def _reverse_dns(value: str):
    try:
        return socket.gethostbyaddr(value)[0]
    except OSError:
        return None


def _internetdb(value: str) -> Dict[str, Any]:
    """Free, keyless Shodan InternetDB lookup; returns ports/vulns/tags."""
    try:
        req = urllib.request.Request(
            _INTERNETDB.format(value),
            headers={"User-Agent": "iocsift/0.1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
        }
    except Exception as exc:  # noqa: BLE001 - network must never crash a scan
        return {"error": str(exc)}
