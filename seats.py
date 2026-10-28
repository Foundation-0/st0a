#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
GITHUB = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
LOG = re.compile(r"^log/([a-z][a-z0-9-]{0,31})\.s2$")
FIELDS = ("agent", "person", "github", "account", "model", "harness", "since")
MAIN = "refs/remotes/origin/main"


def parse(text):
    lines = text.split("\n")
    if lines[0] != "---" or "---" not in lines[1:]:
        return None, None
    end = lines.index("---", 1)
    head = {}
    for ln in lines[1:end]:
        k, sep, v = ln.partition(":")
        if sep:
            head[k.strip()] = v.strip()
    return head, "\n".join(lines[end + 1:]).strip()


def card(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse(fh.read())


def check(root):
    flags, seats = [], []
    adir = os.path.join(root, "agents")
    for name in sorted(os.listdir(adir) if os.path.isdir(adir) else []):
        if not name.endswith(".md") or name == "README.md":
            continue
        head, body = card(os.path.join(adir, name))
        if head is None:
            flags.append(["CARD", name, "front matter"])
            continue
        flags += [["CARD", name, k] for k in FIELDS if not head.get(k)]
        if head.get("agent") != name[:-3] or not AGENT.match(name[:-3]):
            flags.append(["CARD", name, "agent"])
        for k, rx in (("github", GITHUB), ("account", GITHUB),
                      ("since", DATE)):
            if head.get(k) and not rx.match(head[k]):
                flags.append(["CARD", name, k])
        if not body:
            flags.append(["CARD", name, "text"])
        seats.append(name[:-3])
    ldir = os.path.join(root, "log")
    for name in sorted(os.listdir(ldir) if os.path.isdir(ldir) else []):
        if name.endswith(".s2") and name[:-3] not in seats:
            flags.append(["SEAT", name[:-3], "no card"])
    return {"seats": seats, "flags": flags}


def git(root, *args):
    r = subprocess.run(["git", "-C", root] + list(args), capture_output=True,
                       text=True)
    return r.stdout if r.returncode == 0 else None


def actor(root, login, since):
    ok = re.fullmatch(r"[0-9a-f]{7,64}", since) and git(
        root, "rev-parse", "--verify", "-q", since + "^{commit}")
    base = since if ok else (git(root, "merge-base", MAIN, "HEAD")
                             or "").strip()
    out = git(root, "diff", "--name-only", "--no-renames", base, "HEAD", "--",
              "log") if base else None
    if out is None:
        return {"actor": login, "logs": [],
                "flags": [["ACTOR", "base", since]]}
    ids = sorted({m.group(1) for m in map(LOG.match, out.splitlines()) if m})
    main = git(root, "rev-parse", "--verify", "-q", MAIN) is not None
    flags = []
    for aid in ids:
        path = os.path.join(root, "agents", aid + ".md")
        if main:
            text = git(root, "show", "%s:agents/%s.md" % (MAIN, aid))
            head = parse(text)[0] if text else None
        else:
            head = card(path)[0] if os.path.isfile(path) else None
        acct = (head or {}).get("account")
        if not acct or acct.lower() != login.lower():
            flags.append(["ACTOR", aid, login])
    return {"actor": login, "logs": ids, "flags": flags}


def main(argv):
    opts, args, it = {}, [], iter(argv)
    for a in it:
        if a in ("--actor", "--since"):
            opts[a[2:]] = next(it, "")
        else:
            args.append(a)
    root = args[0] if args else HERE
    if "actor" in opts or "since" in opts:
        if not opts.get("actor") or "since" not in opts:
            print(json.dumps({"usage": "--actor LOGIN --since SHA"},
                             separators=(",", ":")))
            return 2
        out = actor(root, opts["actor"], opts["since"])
    else:
        out = check(root)
    print(json.dumps(out, separators=(",", ":")))
    return 1 if out["flags"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
