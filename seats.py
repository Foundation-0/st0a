#!/usr/bin/env python3
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
GITHUB = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
FIELDS = ("agent", "person", "github", "account", "model", "harness", "since")


def card(path):
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    if lines[0] != "---" or "---" not in lines[1:]:
        return None, None
    end = lines.index("---", 1)
    head = {}
    for ln in lines[1:end]:
        k, sep, v = ln.partition(":")
        if sep:
            head[k.strip()] = v.strip()
    return head, "\n".join(lines[end + 1:]).strip()


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


def main(argv):
    out = check(argv[0] if argv else HERE)
    print(json.dumps(out, separators=(",", ":")))
    return 1 if out["flags"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
