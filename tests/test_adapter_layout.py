"""Every command wired by a settings example must point at a file that ships."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "adapters" / "claude-code"


class TestAdapterLayout(unittest.TestCase):
    def test_settings_examples_wire_existing_hooks(self):
        for name in ("settings.example.json", "settings.researcher.example.json"):
            data = json.loads((ADAPTER / name).read_text(encoding="utf-8"))
            cmds = re.findall(r"\$HARNESS_HOME/(\S+\.py)", json.dumps(data["hooks"]))
            self.assertTrue(cmds, name)
            for rel in cmds:
                self.assertTrue((ROOT / rel).is_file(), "%s wires a missing file: %s" % (name, rel))

    def test_hooks_dir_holds_the_entry_points_core_does_not(self):
        self.assertTrue((ADAPTER / "hooks" / "destructive-command-gate.py").is_file())
        self.assertFalse((ROOT / "core" / "gates").exists())


if __name__ == "__main__":
    unittest.main()
