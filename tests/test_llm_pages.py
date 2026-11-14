"""dashboard/server.py: the AI pages tab (pages the web honeypot's LLM fallback wrote and saved)."""
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import server  # noqa: E402

IP, IP2 = "45.155.205.10", "185.195.233.186"


def ev(t, handler, path="/secrets.yml"):
    return {"t": t, "method": "GET", "path": path, "handler": handler}


class LlmPages(unittest.TestCase):
    def setUp(self):
        self.saved = (dict(server.LLM_PAGES), dict(server.MODEL), list(server.CFG.get("own_ips", [])))
        server.CFG["own_ips"] = []

    def tearDown(self):
        server.LLM_PAGES.clear(); server.LLM_PAGES.update(self.saved[0])
        server.MODEL.clear(); server.MODEL.update(self.saved[1])
        server.CFG["own_ips"] = self.saved[2]

    def test_counts_serves_and_who_asked_first(self):
        acc = {}
        server.note_llm_hits({"ip": IP, "id": "w-1"}, [ev(1, "notfound_llm_queued"), ev(2, "admin_login_fail")], acc)
        server.note_llm_hits({"ip": IP2, "id": "w-2"}, [ev(5, "llm_cached"), ev(9, "llm_cached")], acc)
        a = acc["GET /secrets.yml"]
        self.assertEqual(a["n"], 2)
        self.assertEqual(a["last"], 9)
        self.assertEqual(a["ips"], {IP2})
        self.assertEqual(a["asked"], {"t": 1, "ip": IP, "id": "w-1"})
        self.assertEqual(len(acc), 1)

    def test_view_joins_cache_rows_with_hits(self):
        acc = {}
        server.note_llm_hits({"ip": IP2, "id": "w-2"}, [ev(5, "llm_cached")], acc)
        server.MODEL["llm_hits"] = acc
        server.LLM_PAGES.update(t=time.time(), error="", usage=[["2026-11-14", 106]], pages=[
            ["GET /secrets.yml", 200, "text/plain", "m:free", "2026-11-14T12:00:00+00:00", 30, "<script>x</script>"],
            ["GET /never", 404, "text/html", "m:free", "2026-11-13T12:00:00+00:00", 10, "nf"],
            "junk"])
        v = server.llm_pages_view(False, False)
        self.assertEqual(len(v["pages"]), 2)
        p = v["pages"][0]
        self.assertEqual((p["method"], p["path"], p["served"], p["visitors"]), ("GET", "/secrets.yml", 1, 1))
        self.assertEqual(p["body"], "<script>x</script>")   # sent as data; the page shows it as text
        self.assertEqual(v["pages"][1]["served"], 0)
        self.assertEqual(v["usage"], [["2026-11-14", 106]])

    def test_own_ip_is_left_out(self):
        acc = {}
        server.note_llm_hits({"ip": IP2, "id": "w-2"}, [ev(1, "llm_new"), ev(5, "llm_cached")], acc)
        server.MODEL["llm_hits"] = acc
        server.CFG["own_ips"] = [IP2]
        server.LLM_PAGES.update(t=time.time(), error="", usage=[], pages=[
            ["GET /secrets.yml", 200, "text/plain", "m", "2026-11-14T12:00:00+00:00", 3, "abc"]])
        p = server.llm_pages_view(False, False)["pages"][0]
        self.assertEqual((p["served"], p["visitors"], p["asked"]), (0, 0, None))
        p = server.llm_pages_view(False, True)["pages"][0]
        self.assertEqual(p["served"], 2)


    def test_preview_only_for_saved_html(self):
        server.LLM_PAGES.update(t=time.time(), error="", usage=[], pages=[
            ["GET /a", 200, "text/html", "m", "2026-11-14T12:00:00+00:00", 9, "<h1>x</h1>"],
            ["GET /b", 200, "application/json", "m", "2026-11-14T12:00:00+00:00", 2, "{}"]])
        self.assertEqual(server.llm_preview("GET /a"), b"<h1>x</h1>")
        self.assertIsNone(server.llm_preview("GET /b"))
        self.assertIsNone(server.llm_preview("GET /missing"))

    def test_preview_policy_blocks_scripts_and_outside_loads(self):
        csp = server.PREVIEW_CSP
        self.assertIn("default-src 'none'", csp)
        self.assertIn("sandbox", csp)
        self.assertNotIn("script-src", csp)
        self.assertNotIn("http", csp)
        self.assertIn("frame-src 'self'", server.CSP)   # the frame cannot be navigated to an outside site


if __name__ == "__main__":
    unittest.main()
