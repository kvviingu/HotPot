"""dashboard/server.py: the Samples tab's list of file versions the backend did not store."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import server  # noqa: E402

A, B = "a" * 64, "b" * 64


def ev(t, path, sha, why="near_duplicate", size=10):
    return {"type": "file_capped", "t": t, "path": path, "sha256": sha, "why": why, "size": size}


class DroppedView(unittest.TestCase):
    def test_groups_by_path_newest_first(self):
        r = server.dropped_view([ev(1, "/root/.bashrc", A), ev(5, "/root/.bashrc", B, "version_cap", 12),
                                 ev(3, "/etc/cron.d/x", A)])
        self.assertEqual(r["total"], 3)
        self.assertEqual(r["path_count"], 2)
        top = r["paths"][0]
        self.assertEqual(top["path"], "/root/.bashrc")
        self.assertEqual(top["count"], 2)
        self.assertEqual(top["why"], {"near_duplicate": 1, "version_cap": 1})
        self.assertEqual((top["first"], top["last"], top["sha"], top["size"]), (1, 5, B, 12))

    def test_attacker_values_are_checked(self):
        r = server.dropped_view([ev(1, "/x", "not-a-hash"), ev(2, "", A), ev(3, "/y", A, "<script>", "9"),
                                 ev(4, "/z" * 400, A)])
        self.assertEqual(r["total"], 2)
        y = next(g for g in r["paths"] if g["path"] == "/y")
        self.assertEqual(y["why"], {"other": 1})
        self.assertIsNone(y["size"])
        self.assertTrue(all(len(g["path"]) <= 300 for g in r["paths"]))

    def test_list_is_capped(self):
        r = server.dropped_view([ev(i, f"/f{i}", A) for i in range(server.DROPPED_PATHS + 20)])
        self.assertEqual(len(r["paths"]), server.DROPPED_PATHS)
        self.assertEqual(r["path_count"], server.DROPPED_PATHS + 20)
        self.assertEqual(r["paths"][0]["path"], f"/f{server.DROPPED_PATHS + 19}")


if __name__ == "__main__":
    unittest.main()
