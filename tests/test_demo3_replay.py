import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("demo3_replay", ROOT / "tools" / "demo3_replay.py")
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class Demo3ReplayTest(unittest.TestCase):
    def test_page_data_comes_from_the_recorded_results(self) -> None:
        data = replay.build()
        recorded = json.loads((ROOT / "results" / "demo3-end-to-end-human.json").read_text())
        self.assertEqual(data["e2e"]["status"], recorded["status"])
        self.assertEqual(len(data["e2e"]["scenarios"]), len(recorded["scenarios"]))
        self.assertEqual(data["nitro"]["tpm_type"], "nitrotpm")
        self.assertEqual(data["trials"]["totals"]["unauthorized_or_duplicate_launches"], 0)

    def test_template_has_one_data_slot_and_says_it_is_a_replay(self) -> None:
        template = replay.TEMPLATE.read_text()
        self.assertEqual(template.count("__DATA__"), 1)
        self.assertIn("Replay of recorded runs", template)


if __name__ == "__main__":
    unittest.main()
