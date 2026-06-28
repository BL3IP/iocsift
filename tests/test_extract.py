from iocsift.extract import extract_iocs

SAMPLE = """
2026-06-27 12:00:01 ALERT outbound connection from 10.0.0.5 to 45.83.122.10
Beacon URL: hxxp://evil-domain[.]com/payload.bin
Phish sender: attacker[at]bad-actor[.]net
EICAR md5: 44d88612fea8a8f36de82e1278abb02f
Dropper sha256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Exploited CVE-2021-44228 (log4shell) and cve-2017-0144 (eternalblue).
Artifacts written to report.txt and triage_notes.pdf
"""


def _by_type(iocs):
    out = {}
    for i in iocs:
        out.setdefault(i.type, set()).add(i.value)
    return out


def test_extracts_public_and_private_ipv4():
    bt = _by_type(extract_iocs(SAMPLE))
    assert "45.83.122.10" in bt["ipv4"]
    assert "10.0.0.5" in bt["ipv4"]


def test_refangs_url_and_email():
    bt = _by_type(extract_iocs(SAMPLE))
    assert any("evil-domain.com" in u for u in bt["url"])
    assert "attacker@bad-actor.net" in bt["email"]


def test_hashes_classified_by_length():
    bt = _by_type(extract_iocs(SAMPLE))
    assert "44d88612fea8a8f36de82e1278abb02f" in bt["md5"]
    assert (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        in bt["sha256"]
    )


def test_cve_normalised_uppercase():
    bt = _by_type(extract_iocs(SAMPLE))
    assert {"CVE-2021-44228", "CVE-2017-0144"} <= bt["cve"]


def test_filenames_are_not_domains():
    bt = _by_type(extract_iocs(SAMPLE))
    domains = bt.get("domain", set())
    assert "report.txt" not in domains
    assert "triage_notes.pdf" not in domains


def test_dedup_is_stable():
    iocs = extract_iocs("8.8.8.8 8.8.8.8 8.8.8.8")
    assert len([i for i in iocs if i.type == "ipv4"]) == 1
