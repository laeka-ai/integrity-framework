import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PI = Path(__file__).resolve().parent.parent / "adapters" / "pi"
GUARD = PI / "hooks" / "install-guard.py"
SAMPLE = PI / "data" / "malicious-packages.sample.json"


class TestPiInstallGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_guard(self, command, malicious=SAMPLE, raw=None):
        cfg = self.dir / "cfg.json"
        cfg.write_text(json.dumps({"malicious_file": str(malicious), "timeout_s": 1,
                                   "registries": {"npm": "http://127.0.0.1:9", "pypi": "http://127.0.0.1:9",
                                                  "crates": "http://127.0.0.1:9"}}))
        env = {"PATH": os.environ["PATH"], "INSTALL_GUARD_CONFIG": str(cfg),
               "INSTALL_GUARD_JOURNAL": str(self.dir / "j.jsonl"),
               "PI_HOST_AUTHORIZATIONS": str(self.dir / "none.jsonl")}
        payload = raw if raw is not None else json.dumps({"tool_args": {"command": command}})
        return subprocess.run([sys.executable, "-I", str(GUARD)], input=payload,
                              capture_output=True, text=True, env=env, timeout=60)

    def test_line_without_install_passes_with_no_network(self):
        self.assertEqual(self.run_guard("ls -la && echo done").returncode, 0)

    def test_listed_malicious_package_is_refused_before_any_registry_call(self):
        rows = json.loads(SAMPLE.read_text())["packages"]
        pypi = next(r for r in rows if r[0] == "pypi" and r[2] == "all")
        r = self.run_guard("pip install %s" % pypi[1])
        self.assertEqual(r.returncode, 2)
        self.assertIn(pypi[3], r.stderr)
        self.assertIn("Install refused", r.stderr)

    def test_hidden_in_nesting_and_chains_is_still_found(self):
        rows = json.loads(SAMPLE.read_text())["packages"]
        pypi = next(r for r in rows if r[0] == "pypi" and r[2] == "all")
        for c in ("ls && pip install %s" % pypi[1], 'bash -c "pip install %s"' % pypi[1],
                  "echo $(pip install %s)" % pypi[1], "FOO=1 /usr/bin/env pip install %s" % pypi[1]):
            self.assertEqual(self.run_guard(c).returncode, 2, c)

    def test_pinned_version_not_listed_is_not_refused_by_the_base(self):
        rows = json.loads(SAMPLE.read_text())["packages"]
        crate = next(r for r in rows if r[0] == "crates")
        r = self.run_guard("cargo add %s@=1.2.3" % crate[1])
        self.assertNotIn("Install refused", r.stderr)  # held later (no registry), not by the base

    def test_bare_cargo_version_is_a_range_and_is_refused(self):
        rows = json.loads(SAMPLE.read_text())["packages"]
        crate = next(r for r in rows if r[0] == "crates")
        self.assertEqual(self.run_guard("cargo add %s@1.2.3" % crate[1]).returncode, 2)

    def test_unreadable_base_holds_every_install(self):
        r = self.run_guard("pip install requests", malicious=self.dir / "missing.json")
        self.assertEqual(r.returncode, 2)
        self.assertIn("could not read its malicious-package base", r.stderr)

    def test_computed_name_is_held(self):
        self.assertEqual(self.run_guard("npm install $PKG").returncode, 2)

    def test_unreadable_context_fails_closed(self):
        self.assertEqual(self.run_guard("", raw="not json").returncode, 2)


if __name__ == "__main__":
    unittest.main()
