from iocsift.enrich import enrich_ioc
from iocsift.models import IOC


def test_private_ip_offline():
    e = enrich_ioc(IOC(value="10.0.0.5", type="ipv4")).enrichment
    assert e["is_private"] is True
    assert e["is_global"] is False


def test_public_ip_offline_has_no_network_fields():
    e = enrich_ioc(IOC(value="8.8.8.8", type="ipv4")).enrichment
    assert e["is_global"] is True
    assert "shodan_internetdb" not in e  # online disabled by default


def test_hash_algorithm():
    e = enrich_ioc(IOC(value="44d88612fea8a8f36de82e1278abb02f", type="md5")).enrichment
    assert e["algorithm"] == "md5"
    assert e["length"] == 32


def test_cve_year():
    e = enrich_ioc(IOC(value="CVE-2021-44228", type="cve")).enrichment
    assert e["year"] == 2021


def test_url_parts():
    e = enrich_ioc(IOC(value="http://evil.com:8080/a/b", type="url")).enrichment
    assert e["host"] == "evil.com"
    assert e["port"] == 8080
    assert e["path"] == "/a/b"


def test_email_domain():
    e = enrich_ioc(IOC(value="bad@evil.com", type="email")).enrichment
    assert e["domain"] == "evil.com"
