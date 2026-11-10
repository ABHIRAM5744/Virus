import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import globalfeeds as g


def test_radar_attacks():
    j = {"result": {"top_0": [{"originCountryAlpha2": "ru", "originCountryName": "Russia", "targetCountryAlpha2": "US", "targetCountryName": "United States", "value": "12.5"},
                              {"originCountryAlpha2": "CN", "targetCountryAlpha2": None, "value": "3"}, {"originCountryAlpha2": "BR", "targetCountryAlpha2": "DE", "value": "x"}]}}
    r = g.parse_radar_attacks(j)
    assert r == [{"from": "RU", "to": "US", "from_name": "Russia", "to_name": "United States", "pct": 12.5}]


def test_threatfox_abuseipdb_otx_ransomware():
    tf = g.parse_threatfox({"data": [{"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc", "confidence_level": 90},
                                     {"ioc": "evil.com", "ioc_type": "domain"}]})
    assert len(tf) == 1 and tf[0]["ip"] == "1.2.3.4" and tf[0]["port"] == "443"
    ab = g.parse_abuseipdb({"data": [{"ipAddress": "5.6.7.8", "abuseConfidenceScore": 100, "countryCode": "NL"}, {"ipAddress": "bad"}]})
    assert [x["ip"] for x in ab] == ["5.6.7.8"]
    ot = g.parse_otx({"results": [{"id": "p1", "name": "X", "indicators": [{"type": "IPv4", "indicator": "9.9.9.9"}, {"type": "domain", "indicator": "a.b"}]}]})
    assert ot[0]["ips"] == ["9.9.9.9"] and ot[0]["n_ind"] == 2
    rw = g.parse_ransomware([{"victim": "Acme", "group": "lockbit", "country": "US"}, {"victim": "x", "country": ""}])
    assert len(rw) == 1 and rw[0]["cc"] == "US"


def test_country_xy():
    import geo
    assert geo.country_xy("in")[2] == "India" and geo.country_xy("ZZ") is None


def test_live_firehol_parses():
    """Real network test: runs against the live FireHOL lists on GitHub (skipped if offline)."""
    import intel, pytest
    try:
        ips = intel.parse_ip_lines(intel._fetch(g.FIREHOL.format("blocklist_de_ssh"), 30))
    except Exception:
        pytest.skip("offline")
    assert len(ips) > 100
