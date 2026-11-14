"""web/app.py: saved AI pages are dropped when the install's identity changes."""
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_app(data_dir):
    """Import web/app.py with its data in `data_dir`. aiohttp is not needed for the cache code."""
    stubs = {} if importlib.util.find_spec("aiohttp") else {"aiohttp": mock.MagicMock(), "aiohttp.web": mock.MagicMock(),
                                                           "aiohttp.web_protocol": mock.MagicMock()}
    spec = importlib.util.spec_from_file_location("hotpot_web_app", os.path.join(ROOT, "web", "app.py"))
    app = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, {"DATA_DIR": data_dir, "OPENROUTER_API_KEY": ""}), mock.patch.dict(sys.modules, stubs):
        spec.loader.exec_module(app)
    return app


class IdentityChange(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.app = load_app(self.dir.name)
        self.addCleanup(self.dir.cleanup)
        self.addCleanup(self.app.log_file.close)
        self.addCleanup(self.app.db.close)

    def pages(self):
        return self.app.db.execute("SELECT COUNT(*) FROM llm_cache").fetchone()[0]

    def add_page(self):
        self.app.db.execute("INSERT INTO llm_cache VALUES ('GET /about', 200, 'text/html', '<p>old name</p>', 'm', 't')")
        self.app.db.commit()

    def test_first_run_keeps_pages_and_remembers_the_identity(self):
        self.add_page()
        self.assertEqual(self.app.forget_other_identity(), 0)
        self.assertEqual(self.app.forget_other_identity(), 0)
        self.assertEqual(self.pages(), 1)

    def test_a_new_identity_drops_every_saved_page_once(self):
        self.app.forget_other_identity()
        self.add_page()
        with mock.patch.object(self.app, "COMPANY", "Kingsport Cargo"), mock.patch.object(self.app, "log") as log:
            self.assertEqual(self.app.forget_other_identity(), 1)
            self.assertEqual(self.pages(), 0)
            self.assertEqual(log.call_args[0][0]["event"], "llm_cache_identity_reset")
            self.add_page()
            self.assertEqual(self.app.forget_other_identity(), 0)
            self.assertEqual(self.pages(), 1)


if __name__ == "__main__":
    unittest.main()
