import json
import os
import shutil
import subprocess
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

    def test_parse(self):
        head, body = seats.parse(CARD % "zb")
        self.assertEqual((head["agent"], head["account"], body),
                         ("zb", "a-person-bot", "Builds and checks things."))
        self.assertEqual(seats.parse("zb\n"), (None, None))

    def git(self, *a):
        return subprocess.run(["git", "-C", self.tmp] + list(a), check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "x")
        return self.git("rev-parse", "HEAD")

    def test_actor(self):
        self.git("init", "-q", "-b", "main")
        for k, v in (("user.name", "z"), ("user.email", "z@z"),
                     ("commit.gpgsign", "false")):
            self.git("config", k, v)
        self.put("agents/zb.md", CARD % "zb")
        base = self.commit()
        self.put("log/zb.s2", "x\n")
        self.put("log/zq.s2", "x\n")
        logs = self.commit()
        out = seats.actor(self.tmp, "A-Person-Bot", base)
        self.assertEqual(out["logs"], ["zb", "zq"])
        self.assertEqual(out["flags"], [["ACTOR", "zq", "A-Person-Bot"]])
        self.assertEqual(seats.actor(self.tmp, "other", base)["flags"],
                         [["ACTOR", "zb", "other"], ["ACTOR", "zq", "other"]])
        self.assertEqual(seats.actor(self.tmp, "x", "0" * 40)["flags"],
                         [["ACTOR", "base", "0" * 40]])
        self.git("update-ref", "refs/remotes/origin/main", base)
        for since in ("0" * 40, "f" * 40, "nope"):
            self.assertEqual(seats.actor(self.tmp, "a-person-bot",
                                         since)["logs"], ["zb", "zq"])
        self.put("agents/zb.md", (CARD % "zb").replace("a-person-bot", "zx"))
        self.put("log/zb.s2", "x\ny\n")
        self.commit()
        self.assertEqual(seats.actor(self.tmp, "zx", logs),
                         {"actor": "zx", "logs": ["zb"],
                          "flags": [["ACTOR", "zb", "zx"]]})
        self.assertEqual(seats.actor(self.tmp, "a-person-bot", logs)["flags"],
                         [])
        r = subprocess.run([sys.executable, os.path.join(HERE, "seats.py"),
                            "--actor", "zx", "--since", logs, self.tmp],
                           capture_output=True, text=True)
        self.assertEqual((r.returncode, json.loads(r.stdout)["flags"]),
                         (1, [["ACTOR", "zb", "zx"]]))


if __name__ == "__main__":
    unittest.main()
