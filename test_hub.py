import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hub  # noqa: E402

JOIN = "2|1760000000|hub|2|7|10|5|100|100|(102 code)|0||0"


def run(*args, cwd=HERE, env=None):
    r = subprocess.run([sys.executable, os.path.join(cwd, "hub.py")]
                       + list(args), cwd=cwd, capture_output=True, text=True,
                       env=env)
    return r.returncode, r.stdout, r.stderr


def codes(text, agent="za"):
    _, errs = hub.parse_log(agent, text, ".")
    return [e[0] for e in errs]


class Ex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ex = os.path.join(self.tmp, "ex")
        shutil.copytree(os.path.join(HERE, "ex"), self.ex)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_check(self):
        rc, out, _ = run("--root", self.ex, "check")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["packets"], 14)

    def test_views(self):
        want = {"ka": ([], ["ka/1760000110"]),
                "kb": (["ka/1760000110"], []),
                "kc": (["ka/1760000110"], []),
                "kd": ([], [])}
        for me, (inbox, watch) in want.items():
            rc, out, _ = run("--root", self.ex, "--as", me, "--now",
                             "1760000500", "state")
            s = json.loads(out)
            self.assertEqual([a for a, _ in s["inbox"]], inbox, me)
            self.assertEqual(s["watch"], watch, me)
            self.assertEqual(s["flags"], [])

    def test_fold(self):
        rc, out, _ = run("--root", self.ex, "--now", "1760000500", "state",
                         "--all")
        items = {i["addr"]: i for i in json.loads(out)["items"]}
        self.assertEqual(items["ka/1760000100"]["st"], 4)
        self.assertEqual(items["kd/1760000150"]["st"], 6)
        self.assertEqual(items["ka/1760000110"]["st"], 8)
        rc, out, _ = run("--root", self.ex, "--now", "1760000170", "state")
        items = {i["addr"]: i for i in json.loads(out)["items"]}
        self.assertEqual(items["ka/1760000110"]["own"], "kd")

    def test_put_now(self):
        rc, out, err = run("--root", self.ex, "--as", "kb", "--now",
                           "1760000500", "put",
                           "2|_|t3|2|1|2|2|90|0|(100 ka/1760000110)|0||3600",
                           "2|_|t3|2|3|5|1|85|90|(100 ka/1760000110)|2||0")
        self.assertEqual(rc, 0, err)
        ids = [l.split("|")[1] for l in json.loads(out)["put"]]
        self.assertEqual(ids, ["1760000500", "1760000500.1"])
        rc, out, _ = run("--root", self.ex, "--as", "kc", "--now",
                         "1760000600", "state")
        self.assertEqual([a for a, _ in json.loads(out)["inbox"]],
                         ["kb/1760000500.1"])

    def test_put_skew(self):
        rc, out, err = run("--root", self.ex, "--as", "kd", "--now",
                           "1760000100", "put",
                           "2|_|t1|4|3|10|0|50|50|(100 kc/1760000410)|0||0")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["put"][0].split("|")[1],
                         "1760000410.1")

    def test_put_refuse(self):
        rc, _, err = run("--root", self.ex, "--as", "kb", "--now",
                         "1760000500", "put",
                         "2|_|t3|2|1|2|2|0|0|(100 ka/1760000110)|0||3600")
        self.assertEqual(rc, 0, err)
        path = os.path.join(self.ex, "log", "kd.s2")
        with open(path) as fh:
            before = fh.read()
        bad = {
            "ERR:REF": "2|_|t3|4|1|2|2|0|0|(100 zz/1760000000)|0||0",
            "ERR:LEASE": "2|_|t3|4|1|2|2|0|0|(100 ka/1760000110)|0||0",
            "ERR:PROSE": "2|_|t3|4|7|3|1|0|0|(102 please help)|0||0",
        }
        for code, line in bad.items():
            rc, _, err = run("--root", self.ex, "--as", "kd", "--now",
                             "1760000600", "put", line)
            self.assertEqual(rc, 1, code)
            self.assertIn(code, err)
        with open(path) as fh:
            self.assertEqual(fh.read(), before)

    def test_primer(self):
        rc, out, _ = run()
        p = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertNotIn(6, p["F"] + p["T"])
        self.assertTrue(p["next"])


class Lines(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(codes(JOIN + "\n"), [])

    def test_reject(self):
        bad = {
            "ERR:ROLE": "2|1760000001|t|6|1|3|0|0|0||0||0",
            "ERR:BODY": "2|1760000001|t|2|1|3|0|0|0|(hello world)|0||0",
            "ERR:CODE": "2|1760000001|t|2|1|99|0|0|0||0||0",
            "ERR:RE": "2|1760000001|t|2|1|2|2|0|0||0||0",
            "ERR:ID": "2|b441|t|2|1|3|0|0|0||0||0",
            "ERR:SHAPE": "2|1760000001|t|2|1|3|0|0|0||0|0",
            "ERR:RCP": "2|1760000001|t|2|1|3|0|0|0||0||0|0000000000000000",
            "ERR:CANON": "2|1760000001|t|2|1|3|0|0|0|(103  o0000000000000000)"
                         "|0||0",
            "ERR:PROSE": "2|1760000001|t|2|1|3|0|0|0|(21 the-whole-thing)"
                         "|0||0",
        }
        for code, line in bad.items():
            self.assertIn(code, codes(JOIN + "\n" + line + "\n"), code)
        self.assertEqual(codes(JOIN + "\n" + JOIN + "\n"), ["ERR:ORDER"])
        self.assertEqual(codes("2|1760000001|t|2|1|3|0|0|0||0||0\n"),
                         ["ERR:JOIN"])

    def test_empty_expr(self):
        self.assertIn("ERR:BODY", codes(
            JOIN + "\n2|1760000001|t|2|1|3|0|0|0|()|0||0\n"))

    def test_rcp(self):
        line = "2|1760000001|t|2|1|3|0|0|0||0||0"
        self.assertEqual(codes(JOIN + "\n" + hub.rcp_sum(line).join(
            [line + "|", ""]) + "\n"), [])


def pkts(**logs):
    out = []
    for agent, lines in logs.items():
        p, errs = hub.parse_log(agent, "\n".join(lines) + "\n", ".")
        assert not errs, errs
        out += p
    return sorted(out, key=lambda p: (p["key"], p["agent"]))


class Fold(unittest.TestCase):
    def test_lease_and_self_verify(self):
        j = "2|1760000000|hub|%d|7|10|5|0|0|(102 x)|0||0"
        ps = pkts(
            za=[j % 1, "2|1760000010|t|1|7|1|5|0|0||1||0"],
            zb=[j % 2, "2|1760000020|t|2|1|2|2|0|0|(100 za/1760000010)|0||100",
                "2|1760000040|t|2|1|3|4|0|0|(100 za/1760000010)|0||0"],
            zc=[j % 2, "2|1760000030|t|2|1|2|2|0|0|(100 za/1760000010)|0||0"],
        )
        _, items, _, flags = hub.fold(ps, 1760000050)
        self.assertEqual(items["za/1760000010"]["own"], "zb")
        self.assertEqual(items["za/1760000010"]["st"], 2)
        self.assertEqual(sorted(f[0] for f in flags), ["ERR:AUTH", "ERR:LEASE"])
        _, items, _, _ = hub.fold(ps, 1760000200)
        self.assertEqual(items["za/1760000010"]["st"], 8)

    def test_reply_before_item(self):
        j = "2|1760000000|hub|%d|7|10|5|0|0|(102 x)|0||0"
        ps = pkts(
            za=[j % 1, "2|1760000100|t|1|7|1|5|0|0||1||0"],
            zb=[j % 2, "2|1760000090|t|2|1|2|2|0|0|(100 za/1760000100)|0||0"],
        )
        _, items, _, flags = hub.fold(ps, 1760000200)
        self.assertIsNone(items["za/1760000100"]["own"])
        self.assertEqual(flags, [["ERR:ORDER", "zb/1760000090",
                                  "za/1760000100"]])


class Pin(unittest.TestCase):
    def test_vendored(self):
        with open(os.path.join(HERE, "sym2", "PIN")) as fh:
            _, path, want = fh.read().split()
        with open(os.path.join(HERE, "sym2", os.path.basename(path)),
                  "rb") as fh:
            got = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(got, want)


class Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def clone(self, name):
        d = os.path.join(self.tmp, name)
        shutil.copytree(HERE, d, ignore=shutil.ignore_patterns(
            ".git", "log", "obj", ".hub-self", "__pycache__"))
        return d

    def test_join_put_obj(self):
        d = self.clone("w")
        rc, out, _ = run("--as", "zz", "join", "2", "code", cwd=d)
        self.assertEqual(rc, 0, out)
        rc, out, err = run("put", "2|_|t|2|7|3|1|50|50||0||0",
                           "2|_|t|2|7|3|1|50|50||0||0", cwd=d)
        self.assertEqual(rc, 0, err)
        ids = [l.split("|")[1] for l in json.loads(out)["put"]]
        self.assertLess(hub.pid_key(ids[0]), hub.pid_key(ids[1]))
        rc, _, err = run("put", "2|_|t|6|7|3|1|50|50||0||0", cwd=d)
        self.assertEqual(rc, 1)
        self.assertIn("ERR:ROLE", err)
        src = os.path.join(self.tmp, "a.txt")
        with open(src, "wb") as fh:
            fh.write(b"x")
        rc, out, _ = run("obj", src, cwd=d)
        oid = json.loads(out)["oid"]
        rc, out, _ = run("get", oid, cwd=d)
        self.assertEqual(out, "x")
        with open(os.path.join(d, "obj", oid + ".txt"), "wb") as fh:
            fh.write(b"y")
        rc, out, _ = run("check", cwd=d)
        self.assertEqual(rc, 1)

    def git(self, d, *a):
        return subprocess.run(["git", "-C", d] + list(a), check=True,
                              capture_output=True, text=True).stdout

    def remote(self):
        bare = os.path.join(self.tmp, "bare.git")
        self.git(self.tmp, "init", "-q", "--bare", bare)
        os.environ.update(GIT_AUTHOR_NAME="z", GIT_AUTHOR_EMAIL="z@z",
                          GIT_COMMITTER_NAME="z", GIT_COMMITTER_EMAIL="z@z")
        return bare

    def worker(self, name, bare):
        d = self.clone(name)
        self.git(d, "init", "-q", "-b", "b-" + name)
        self.git(d, "config", "commit.gpgsign", "false")
        self.git(d, "remote", "add", "origin", bare)
        return d

    def test_resume(self):
        bare = self.remote()
        d = self.worker("za", bare)
        run("--as", "za", "join", "1", "x", cwd=d)
        rc, out, err = run("put", "2|_|t|1|7|1|5|0|0||1||0", cwd=d)
        self.assertEqual(rc, 0, err)
        first = json.loads(out)["put"][0]
        self.assertEqual(run("push", cwd=d)[0], 0)
        d2 = self.worker("za2", bare)
        self.assertEqual(run("sync", cwd=d2)[0], 0)
        rc, out, err = run("--as", "za", "join", "1", "x", cwd=d2)
        self.assertEqual(rc, 0, err)
        self.assertTrue(json.loads(out)["resume"])
        rc, out, err = run("put", "2|_|t|1|7|3|1|0|0||0||0", cwd=d2)
        self.assertEqual(rc, 0, err)
        with open(os.path.join(d2, "log", "za.s2")) as fh:
            lines = fh.read().split("\n")
        self.assertEqual(lines[1], first)
        self.assertEqual(run("check", cwd=d2)[0], 0)

    def test_push_scope(self):
        bare = self.remote()
        d = self.worker("za", bare)
        run("--as", "za", "join", "1", "x", cwd=d)
        with open(os.path.join(d, "note"), "w") as fh:
            fh.write("x")
        self.git(d, "add", "note")
        rc, _, err = run("push", cwd=d)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.git(d, "show", "--name-only", "--format=",
                                  "HEAD").split(), ["log/za.s2"])
        self.assertIn("A  note", self.git(d, "status", "--porcelain"))

    def test_branches(self):
        bare = self.remote()
        for name, role in (("za", "1"), ("zb", "2")):
            d = self.worker(name, bare)
            rc, out, err = run("--as", name, "join", role, "x", cwd=d)
            self.assertEqual(rc, 0, err)
            rc, out, err = run("push", cwd=d)
            self.assertEqual(rc, 0, err)
        rc, _, _ = run("sync", cwd=d)
        self.assertEqual(rc, 0)
        rc, out, _ = run("state", cwd=d)
        self.assertEqual(sorted(json.loads(out)["agents"]), ["za", "zb"])
        rc, out, _ = run("check", cwd=d)
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
