import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import seats  # noqa: E402

CARD = """---
agent: %s
person: A Person
github: a-person
account: a-person-bot
model: Claude, by Anthropic
harness: Claude Code
since: 2026-10-19
---
Builds and checks things.
"""


class Seats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "agents"))
        os.makedirs(os.path.join(self.tmp, "log"))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def put(self, path, text):
        with open(os.path.join(self.tmp, path), "w") as fh:
            fh.write(text)

    def test_repo(self):
        self.assertEqual(seats.check(HERE)["flags"], [])

    def test_seated(self):
        self.put("agents/zb.md", CARD % "zb")
        self.put("log/zb.s2", "")
        self.assertEqual(seats.check(self.tmp), {"seats": ["zb"], "flags": []})

    def test_unseated(self):
        self.put("log/zb.s2", "")
        self.assertEqual(seats.check(self.tmp)["flags"],
                         [["SEAT", "zb", "no card"]])

    def test_name_mismatch(self):
        self.put("agents/zc.md", CARD % "zb")
        self.assertIn(["CARD", "zc.md", "agent"],
                      seats.check(self.tmp)["flags"])

    def test_missing_field(self):
        self.put("agents/zb.md", (CARD % "zb").replace("model: ", "x: "))
        self.assertIn(["CARD", "zb.md", "model"],
                      seats.check(self.tmp)["flags"])

    def test_bad_values(self):
        bad = (CARD % "zb").replace("2026-10-19", "19 Oct").replace(
            "github: a-person", "github: a person")
        self.put("agents/zb.md", bad)
        flags = seats.check(self.tmp)["flags"]
        self.assertIn(["CARD", "zb.md", "since"], flags)
        self.assertIn(["CARD", "zb.md", "github"], flags)

    def test_no_front_matter(self):
        self.put("agents/zb.md", "zb\n")
        self.assertEqual(seats.check(self.tmp)["flags"],
                         [["CARD", "zb.md", "front matter"]])


if __name__ == "__main__":
    unittest.main()
