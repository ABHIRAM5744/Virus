import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import live, tools

TLE = """ISS (ZARYA)
1 25544U 98067A   24300.51782528  .00016717  00000-0  30106-3 0  9993
2 25544  51.6416 247.4627 0006703 130.5360 325.0288 15.50000000 99999
GPS BIIR-2  (PRN 13)
1 24876U 97035A   24300.12345678  .00000010  00000-0  00000-0 0  9990
2 24876  55.5000 100.0000 0100000  50.0000 310.0000  2.00560000 99990"""


def test_tle():
    s = live.parse_tle(TLE, "stations")
    assert [x["n"] for x in s] == ["ISS (ZARYA)", "GPS BIIR-2  (PRN 13)"] and s[0]["l1"].startswith("1 ")


def test_opensky_quakes():
    p = live.parse_opensky({"states": [["abc", "UAE1 ", "UAE", 0, 0, 55.3, 25.2, 11000, False, 240, 90], ["g", "x", "x", 0, 0, 1, 1, 0, True, 0, 0], ["n", "", "", 0, 0, None, None, 0, False, 0, 0]]})
    assert len(p) == 1 and p[0][2] == 25.2 and p[0][5] == 90 and p[0][6] == 240
    q = live.parse_quakes({"features": [{"id": "u1", "properties": {"mag": 5.1, "place": "X", "time": 1}, "geometry": {"coordinates": [10.0, 20.0, 5.0]}}, {"bad": 1}]})
    assert len(q) == 1 and q[0]["mag"] == 5.1 and q[0]["lat"] == 20.0


def test_offline_tools():
    r = tools.run("subnet", "10.0.0.0/24"); assert r["ok"] and "254" in str(r["result"])
    assert not tools.run("subnet", "nonsense")["ok"]
    assert not tools.run("nope", "x")["ok"]
    h = tools.run("hash", "44d88612fea8a8f36de82e1278abb02f"); assert h["ok"] or "network" in h["error"]
