"""Run this on YOUR network to verify every live source works:   python check_sources.py
Prints, per source: HTTP status, how many items parsed, and a sample. Exit code 1 if any source fails."""
import sys
import intel

CHECKS = [
    ("feodo", intel.parse_feodo), ("blocklist_de", intel.parse_ip_lines), ("dshield", intel.parse_dshield), ("kev", intel.parse_kev),
    ("openphish", intel.parse_urls), ("urlhaus", intel.parse_urlhaus), ("et_compromised", intel.parse_ip_lines),
    ("blocklist_all", intel.parse_ip_lines), ("tor_exit", intel.parse_ip_lines), ("ipsum", intel.parse_ipsum),
]
import globalfeeds as gf
for fname, *_ in gf.FIREHOL_SETS:
    CHECKS.append(("fh:" + fname, intel.parse_ip_lines))
    intel.URLS["fh:" + fname] = gf.FIREHOL.format(fname)
CHECKS.append(("phishing-db", intel.parse_urls)); intel.URLS["phishing-db"] = gf.PHISH_NEW
bad = 0
for key, parser in CHECKS:
    try:
        rows = parser(intel._fetch(intel.URLS[key], 40))
        print(f"OK   {key:15s} {len(rows):7d} items   sample: {str(rows[0])[:90] if rows else '-'}")
        if not rows:
            bad += 1
    except Exception as e:  # noqa: BLE001
        bad += 1
        print(f"FAIL {key:15s} {str(e)[:110]}")
sys.exit(1 if bad else 0)
