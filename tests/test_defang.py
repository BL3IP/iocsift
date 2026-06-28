from iocsift.defang import defang, refang


def test_roundtrip_url():
    assert refang(defang("http://evil.com/a")) == "http://evil.com/a"


def test_roundtrip_https_url():
    assert refang(defang("https://evil.com/a?b=1")) == "https://evil.com/a?b=1"


def test_roundtrip_email():
    assert refang(defang("user@evil.com")) == "user@evil.com"


def test_defang_has_markers_and_hides_real():
    d = defang("http://evil.com")
    assert "[.]" in d and "hxxp" in d
    assert "evil.com" not in d


def test_refang_handles_variants():
    assert refang("evil(.)com") == "evil.com"
    assert refang("evil[dot]com") == "evil.com"
    assert refang("user(at)evil[.]com") == "user@evil.com"
