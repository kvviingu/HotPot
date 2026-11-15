"""Tests for the operator tool: per-install identity, bundle rendering, release unpacking.

Run with:  python -m unittest discover -s tests
"""
import io
import os
import re
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import hotpot  # noqa: E402
import persona  # noqa: E402


def render(ident):
    """The tarball hotpot would send to a VM, for the given identity."""
    tmp = tempfile.mkdtemp()
    with mock.patch.object(persona, "PATH", os.path.join(tmp, "persona.json")), \
            mock.patch.object(hotpot, "CONF", os.path.join(ROOT, "honeypot.conf.example")):
        persona.save(ident)
        vms = hotpot.VMs.__new__(hotpot.VMs)
        return tarfile.open(fileobj=io.BytesIO(vms.bundle({})))


class IdentityTest(unittest.TestCase):
    def test_generate_differs_from_reference(self):
        p = persona.generate("10.0.0.99")
        self.assertFalse(persona.is_reference(p))
        self.assertNotEqual(p["check"], persona.REFERENCE["check"])
        self.assertEqual(set(p["creds"]), set(persona.REFERENCE["creds"]))
        for k, v in persona.REFERENCE["creds"].items():
            self.assertNotEqual(p["creds"][k], v)
            self.assertEqual(len(p["creds"][k]), len(v) if not v.startswith("nbk_") else len(p["creds"][k]))

    def test_reference_has_no_swaps(self):
        self.assertEqual(persona.pairs(persona.reference()), [])

    def test_substitute_is_single_pass(self):
        p = persona.generate()
        text = "Northbridge Logistics at northbridge-logistics.com runs fileserver01 (NB-AGENT-CHECK-7f3a)"
        out = persona.substitute(text, p)
        self.assertIn(f"{p['brand']} {p['industry']}", out)
        self.assertIn(f"{p['check']}-{p['tokens']['motd']}", out)
        self.assertNotIn("orthbridge", out)

    def test_change_control_tokens_are_swapped(self):
        p = persona.generate()
        out = persona.substitute('logger -t nb-ops "CHG-7f3a <your name>" and CHG-5b1d in /etc/nb-ops', p)
        self.assertIn(f"CHG-{p['tokens']['motd']}", out)
        self.assertIn(f"CHG-{p['tokens']['runbook']}", out)
        self.assertIn(f"/etc/{p['ini']}-ops", out)
        self.assertNotIn("7f3a", out)

    def test_a_credential_added_later_gets_its_own_stable_value(self):
        # persona.json written before the AWS secret existed: no public reference value, same on every load
        old = persona.generate()
        del old["creds"]["runbook_aws_secret"]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "persona.json")
            persona.save(old, path)
            a, b = persona.load(path), persona.load(path)
        ref = persona.REFERENCE["creds"]["runbook_aws_secret"]
        self.assertEqual(a["creds"]["runbook_aws_secret"], b["creds"]["runbook_aws_secret"])
        self.assertNotEqual(a["creds"]["runbook_aws_secret"], ref)
        self.assertEqual(len(a["creds"]["runbook_aws_secret"]), len(ref))
        self.assertEqual(a["creds"]["runbook_ssh"], old["creds"]["runbook_ssh"])

    def test_ssh_side_bait_does_not_address_ai(self):
        # a line written to "AI assistants" told a careful agent it was in a honeypot; the web lures keep theirs
        fs = os.path.join(ROOT, "cowrie", "honeyfs")
        for base, _, names in os.walk(fs):
            for n in names:
                with open(os.path.join(base, n), encoding="utf-8", errors="replace") as f:
                    text = f.read()
                for word in ("AI assistant", "AI agent", "AGENT-CHECK", "LLM-driven"):
                    self.assertNotIn(word, text, os.path.join(base, n))
        for rel in ("etc/motd", "root/RUNBOOK.md"):
            with open(os.path.join(fs, rel), encoding="utf-8") as f:
                self.assertRegex(f.read(), r'logger -t nb-ops "CHG-[0-9a-f]{4} ')

    def test_load_rejects_bad_values(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "persona.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"brand": "evil; rm -rf /", "host": "$(id)"}')
            p = persona.load(path)
            self.assertEqual(p["brand"], persona.REFERENCE["brand"])
            self.assertEqual(p["host"], persona.REFERENCE["host"])


class IdentityCheckTest(unittest.TestCase):
    """After a deploy: does what attackers see carry this install's identity?"""
    MINE = dict(persona.REFERENCE, brand="Kingsport", industry="Cargo", host="fs-main", check="KC-AGENT-CHECK")

    def test_matching_identity_passes(self):
        self.assertEqual(hotpot.identity_problems(self.MINE, "<h1>Kingsport Cargo</h1>", "fs-main\n", "Kingsport"), [])
        self.assertEqual(hotpot.identity_problems(self.MINE), [])                       # nothing was checked

    def test_reference_identity_showing_through_is_reported(self):
        bad = hotpot.identity_problems(self.MINE, "<h1>Northbridge Logistics</h1>", "fileserver01", "Northbridge NOC")
        self.assertEqual(len(bad), 4)
        self.assertTrue(any("reference identity" in b for b in bad))
        self.assertTrue(any("fileserver01" in b for b in bad))

    def test_a_dead_web_honeypot_is_reported(self):
        self.assertIn("sent nothing", hotpot.identity_problems(self.MINE, "")[0])

    def test_an_install_on_the_reference_identity_does_not_flag_itself(self):
        ref = persona.REFERENCE
        self.assertEqual(hotpot.identity_problems(ref, "Northbridge Logistics", ref["host"], "Northbridge"), [])


class SystemTest(unittest.TestCase):
    REAL = ("7.0.0-1013-oracle", "#13~24.04.1-Ubuntu SMP PREEMPT Fri Sep 25 09:28:21 UTC 2026",
            "24.04.5 LTS (Noble Numbat)")

    def test_read_values(self):
        self.assertEqual(persona.system_from(*self.REAL),
                         {"kernel": self.REAL[0], "kbuild": self.REAL[1], "os": "24.04.5 LTS"})

    def test_odd_values_are_dropped(self):
        self.assertEqual(persona.system_from("$(reboot)", "no hash", "Arch Linux"), {})

    def test_swapped_in_files_but_not_identity(self):
        p = persona.reference()
        p.update(persona.system_from(*self.REAL))
        self.assertTrue(persona.is_reference(p))     # the kernel is not part of the identity
        text = ("Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-1013-oracle x86_64)\n"
                "#13-Ubuntu SMP PREEMPT_DYNAMIC Mon Sep 16 14:43:28 UTC 2024\n26.1.3-0ubuntu1~24.04.1")
        out = persona.substitute(text, p)
        self.assertIn("Ubuntu 24.04.5 LTS (GNU/Linux 7.0.0-1013-oracle x86_64)", out)
        self.assertIn(self.REAL[1], out)
        self.assertIn("26.1.3-0ubuntu1~24.04.1", out)   # a package version, not the OS release

    def test_bad_saved_values_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "persona.json")
            p = persona.reference()
            p.update({"kernel": "6.9; rm -rf /", "os": "24.04.5 LTS"})
            persona.save(p, path)
            got = persona.load(path)
        self.assertNotIn("kernel", got)
        self.assertEqual(got["os"], "24.04.5 LTS")


class BundleTest(unittest.TestCase):
    def test_no_reference_value_reaches_the_vms(self):
        p = persona.generate("10.0.0.99")
        tar = render(p)
        refs = [a for a, _ in persona.pairs(p)]
        for m in tar.getmembers():
            self.assertNotIn("northbridge", m.name.lower(), m.name)
            if not m.isfile() or m.name == "honeypot.conf":
                continue
            try:
                text = tar.extractfile(m).read().decode("utf-8")
            except UnicodeDecodeError:
                continue
            for r in refs:
                self.assertNotIn(r, text, f"{r!r} left in {m.name}")

    def test_canary_regex_follows_the_identity(self):
        p = persona.generate()
        app = render(p).extractfile("web/app.py").read().decode("utf-8")
        self.assertIn(re.escape(p["check"]).replace("\\-", "-"), app)


class UpdateTest(unittest.TestCase):
    def fake_release(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            def add(name, data=b"x"):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            add("owner-HotPot-abc/hotpot.py", b'VERSION = "9.9.9"\n')
            add("owner-HotPot-abc/honeypot.conf", b"FROM RELEASE")
            add("owner-HotPot-abc/persona.json", b"FROM RELEASE")
            add("owner-HotPot-abc/secrets/openrouter.env", b"FROM RELEASE")
            add("owner-HotPot-abc/../escape.txt", b"FROM RELEASE")
            add("owner-HotPot-abc/web/app.py", b"new")
            link = tarfile.TarInfo("owner-HotPot-abc/link")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            t.addfile(link)
        return buf.getvalue()

    def test_unpack_keeps_install_files_and_stays_inside(self):
        with tempfile.TemporaryDirectory() as parent:
            d = os.path.join(parent, "hotpot")
            os.makedirs(d)
            with open(os.path.join(d, "honeypot.conf"), "w") as f:
                f.write("MINE")
            n = hotpot.unpack_release(self.fake_release(), d)
            self.assertEqual(n, 2)
            with open(os.path.join(d, "honeypot.conf")) as f:
                self.assertEqual(f.read(), "MINE")
            self.assertFalse(os.path.exists(os.path.join(d, "persona.json")))
            self.assertFalse(os.path.exists(os.path.join(d, "secrets")))
            self.assertFalse(os.path.exists(os.path.join(parent, "escape.txt")))
            self.assertFalse(os.path.lexists(os.path.join(d, "link")))
            with open(os.path.join(d, "hotpot.py")) as f:
                self.assertEqual(hotpot.version_of(f.read()), "9.9.9")

    def test_version_order(self):
        self.assertGreater(hotpot.vtuple("v1.2.10"), hotpot.vtuple("1.2.9"))
        self.assertEqual(hotpot.vtuple("v1.0.0"), hotpot.vtuple("1.0.0"))


if __name__ == "__main__":
    unittest.main()
