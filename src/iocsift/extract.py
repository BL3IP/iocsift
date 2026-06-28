"""Regex-based IOC extraction from arbitrary text/logs."""
from __future__ import annotations

import ipaddress
import re
from typing import List

from .defang import refang
from .models import IOC

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)

# longest-first so a sha256 is never mis-tagged as a shorter hash
HASH_PATTERNS = (
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
)

# common file extensions we never want to report as a domain
_FILE_EXT = {
    "txt", "pdf", "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "png", "jpg",
    "jpeg", "gif", "svg", "log", "json", "csv", "py", "md", "html", "htm", "zip",
    "gz", "tar", "rar", "7z", "xml", "yml", "yaml", "cfg", "ini", "ps1", "sh",
    "bat", "bin", "dat", "db", "sql", "conf", "toml", "lock",
}


def extract_iocs(text: str) -> List[IOC]:
    """Extract a deduplicated list of IOCs from ``text`` (auto-refangs first)."""
    text = refang(text)
    found: "dict[tuple, IOC]" = {}

    def add(ioc_type: str, value: str) -> None:
        key = (ioc_type, value)
        if key not in found:
            found[key] = IOC(value=value, type=ioc_type)

    # URLs and emails first so their host parts are not double-counted as domains
    urls = [u.rstrip(".,;)”\"'") for u in URL_RE.findall(text)]
    for url in urls:
        add("url", url)
    emails = EMAIL_RE.findall(text)
    for email in emails:
        add("email", email)
    covered = " ".join(urls) + " " + " ".join(emails)

    for ip in IPV4_RE.findall(text):
        add("ipv4", ip)

    for candidate in IPV6_RE.findall(text):
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        add("ipv6", candidate)

    seen_hashes = set()
    for algo, pattern in HASH_PATTERNS:
        for h in pattern.findall(text):
            hl = h.lower()
            if hl in seen_hashes:
                continue
            seen_hashes.add(hl)
            add(algo, hl)

    for cve in CVE_RE.findall(text):
        add("cve", cve.upper())

    for domain in DOMAIN_RE.findall(text):
        if domain.rsplit(".", 1)[-1].lower() in _FILE_EXT:
            continue
        if domain in covered:
            continue
        add("domain", domain)

    return list(found.values())
