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

    def test_load_rejects_bad_values(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "persona.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"brand": "evil; rm -rf /", "host": "$(id)"}')
            p = persona.load(path)
            self.assertEqual(p["brand"], persona.REFERENCE["brand"])
            self.assertEqual(p["host"], persona.REFERENCE["host"])


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
