"""Tests for the backend collector's per-file version cap (backend/nb-collect.py)."""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("nb_collect", os.path.join(HERE, "..", "backend", "nb-collect.py"))
nb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nb)


class VersionCap(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def file(self, name, data):
        p = os.path.join(self.dir.name, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_text_file_is_capped(self):
        st, dst = {}, self.file("a", b"alias ls='ls'\n")
        kept = [nb.keep_version(st, "/root/.bashrc", 0o644, dst, 100) for _ in range(8)]
        self.assertEqual(kept, [True] * nb.VERSIONS_PER_FILE + [False] * (8 - nb.VERSIONS_PER_FILE))

    def test_programs_and_binaries_are_always_kept(self):
        st = {}
        elf, script = self.file("b", b"\x7fELF\x02\x01\x01\0\0\0"), self.file("c", b"#!/bin/sh\necho hi\n")
        text = self.file("d", b"plain\n")
        for _ in range(10):
            self.assertTrue(nb.keep_version(st, "/tmp/x", 0o644, elf, 100))
            self.assertTrue(nb.keep_version(st, "/tmp/y.sh", 0o644, script, 100))
            self.assertTrue(nb.keep_version(st, "/tmp/z", 0o755, text, 100))

    def test_paths_count_separately_and_restart_resets(self):
        st, dst = {}, self.file("e", b"* * * * * root true\n")
        for _ in range(nb.VERSIONS_PER_FILE):
            nb.keep_version(st, "/etc/cron.d/a", 0o644, dst, 100)
        self.assertFalse(nb.keep_version(st, "/etc/cron.d/a", 0o644, dst, 100))
        self.assertTrue(nb.keep_version(st, "/etc/cron.d/b", 0o644, dst, 100))
        self.assertTrue(nb.keep_version(st, "/etc/cron.d/a", 0o644, dst, 200))   # container restarted

    def test_bad_state_starts_fresh(self):
        st, dst = {"versions": "junk"}, self.file("f", b"x\n")
        self.assertTrue(nb.keep_version(st, "/root/.profile", 0o644, dst, 100))


if __name__ == "__main__":
    unittest.main()
