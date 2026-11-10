"""Parser tests. Fixtures follow each feed's documented format; run:  python -m pytest tests -q   (or python tests/test_parsers.py)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import intel  # noqa: E402


def test_feodo():
    rows = intel.parse_feodo('[{"ip_address":"1.2.3.4","port":443,"status":"online","malware":"QakBot","as_name":"X","country":"NL",'
                             '"first_seen":"2026-11-01 10:00:00","last_online":"2026-11-09"},{"ip_address":"10.0.0.1"}]')
    assert rows[0]["ip"] == "1.2.3.4" and rows[0]["malware"] == "QakBot" and rows[0]["status"] == "online"


def test_kev_sorted_newest_first():
    rows = intel.parse_kev('{"vulnerabilities":[{"cveID":"CVE-1","dateAdded":"2026-01-01"},{"cveID":"CVE-2","dateAdded":"2026-02-01","knownRansomwareCampaignUse":"Known"}]}')
    assert rows[0]["cve"] == "CVE-2" and rows[0]["ransomware"] is True and rows[1]["ransomware"] is False


def test_dshield():
    rows = intel.parse_dshield('[{"source":"5.6.7.8","reports":"1,200","targets":40,"firstseen":"a","lastseen":"b"}]')
    assert rows[0]["ip"] == "5.6.7.8" and rows[0]["reports"] == 1200


def test_ip_lines_ignore_comments():
    assert intel.parse_ip_lines("# header\n1.2.3.4 # x\n\n5.6.7.8;foo\nnot-an-ip\n") == ["1.2.3.4", "5.6.7.8"]


def test_ipsum_levels():
    assert intel.parse_ipsum("# c\n1.1.1.1\t2\n2.2.2.2\t3\n3.3.3.3\t10\n") == ["2.2.2.2", "3.3.3.3"]


def test_urls_and_urlhaus():
    assert intel.parse_urls("junk\nhttp://a.example/x\nhttps://b.example") == ["http://a.example/x", "https://b.example"]
    csv_text = '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"1","2026-11-09","http://bad.example/a.exe","online","x","malware_download","elf","l","r"\n' \
               '"2","2026-11-09","http://old.example/b","offline","x","malware_download","","l","r"\n'
    rows = intel.parse_urlhaus(csv_text)
    assert len(rows) == 1 and rows[0]["url"] == "http://bad.example/a.exe"


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
