#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "sym2"))
from sym2_parse import (  # noqa: E402
    ACTS, BASE, ROLES, RQS, STATES, SUM, TOKEN, check_expr, check_scope,
    parse_all, rcp_sum, split_fields,
)

PROFILE = "st0a/1"
WIRE = "sym2p/2"
SRC = "aska-digital/protean-sym2p@2d93ed6:SPEC-V2-DRAFT.md"

AGENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
PID = re.compile(r"^([0-9]{10})(?:\.([1-9][0-9]*))?$")
ADDR = re.compile(r"^([a-z][a-z0-9-]{0,31})/([0-9]{10}(?:\.[1-9][0-9]*)?)$")
OID = re.compile(r"^o[0-9a-f]{16}$")
OFILE = re.compile(r"^(o[0-9a-f]{16})(\.[a-z0-9]{1,8})?$")
LOGFILE = re.compile(r"^([a-z][a-z0-9-]{0,31})\.s2$")

OPERATOR, SWARM = 6, 7
AGENT_ROLES = sorted(set(ROLES) - {0, OPERATOR, SWARM})
ITEM_ACTS = {1, 6, 7, 9, 11}
REPLY_ACTS = {2, 5, 6, 7, 12}
TERMINAL = {4, 6, 7}

CORE_OPS = {
    10: ["scope", "(10 target (20 ...))"],
    11: ["constraint", "(11 (21 ...))"],
    12: ["accept", "(12 (22 ...))"],
    20: ["impl", "(20 unit range)"],
    21: ["nomod", "(21 paths)"],
    22: ["exit", "(22 prog ok bad)"],
    30: ["bind", "(30 name expr)"],
    31: ["if", "(31 test then else)"],
    32: ["each", "(32 var items body)"],
    33: ["list", "(33 item*)"],
    34: ["lt", "(34 a b)"],
    35: ["eq", "(35 a b)"],
    40: ["spawn", "(40 role thread task)"],
}
HUB_OPS = {
    100: ["re", "(100 agent/id+)"],
    101: ["to", "(101 agent+)"],
    102: ["cap", "(102 sym+)"],
    103: ["obj", "(103 oid+)"],
    104: ["def", "(104 sym oid)"],
}
HUB_KEYS = {100: "re", 101: "to", 102: "cap", 103: "obj", 104: "def"}

FOLD = {
    "addr": "agent/ID",
    "order": "(ID, agent)",
    "item": "A in %s" % sorted(ITEM_ACTS),
    "reply": "(100 addr) ; A in %s requires it" % sorted(REPLY_ACTS),
    "init": "item.st := ST or 5",
    "join": "log[0] := A=10 (102 cap+) ; role := F",
    "to": "(101 agent+) else T in {role, 7}",
    "terminal": sorted(TERMINAL),
    "lease": "ST=2 ; until := ID + EXP ; EXP=0 -> inf",
    "st": {
        "2": "own in {none} or lease < ID -> own := f",
        "5": "f in {by, own} -> own := none",
        "1": "f in {by, own}",
        "3": "f != own",
        "4": "f != own",
        "6": "f in {by, own}",
        "7": "f in {by, own}",
        "8": "f in {by, own}",
    },
    "now": "st=2 and until < now -> st := 8, own := none",
    "inbox": "to(me) and f != me and (item: st !in terminal and own in {none, me} | RQ != 0) and last(me) < last(other)",
    "watch": "item and me in {by, own} and last(me) < last(other)",
    "lex": "first (104 sym oid) wins",
    "src": "worktree + refs/remotes/origin/*",
    "verify": "cat obj(receipt)+ obj(item)+ | prog ; exit == ok -> ST=4 else ST=3",
    "fn": "hub.py:parse_line,parse_log,fold,transition,views",
    "oid": "o + sha256(bytes)[:16]",
}


def err(code, where, msg):
    return ["ERR:" + code, where, msg]


def pid_key(pid):
    m = PID.match(pid)
    return (int(m.group(1)), int(m.group(2) or 0))


def pid_str(key):
    return "%d" % key[0] if not key[1] else "%d.%d" % key


def check_hub_op(e):
    op, args = int(e[0]), e[1:]
    if not args or any(isinstance(a, list) for a in args):
        return "%s wants atoms" % HUB_OPS[op][1]
    if op == 100 and not all(ADDR.match(a) for a in args):
        return "re wants agent/id"
    if op == 101 and not all(AGENT.match(a) for a in args):
        return "to wants agent"
    if op == 102 and not all(TOKEN.match(a) and a[0].isalpha() for a in args):
        return "cap wants sym"
    if op == 103 and not all(OID.match(a) for a in args):
        return "obj wants oid"
    if op == 104 and not (len(args) == 2 and a_sym(args[0])
                          and OID.match(args[1])):
        return "def wants (104 sym oid)"
    return None


def a_sym(s):
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9_./-]*$", s))


def parse_line(line):
    errs = []
    if line != line.strip():
        return None, [("CANON", "whitespace")]
    fields, ferr = split_fields(line)
    if ferr:
        return None, [("SHAPE", ferr)]
    bare = fields[:13]
    _, pid, tk, f, t, a, st, cf, cv, body, rq, base, exp = bare
    if not PID.match(pid):
        errs.append(("ID", "want unix-seconds[.n]"))
    if not TOKEN.match(tk) or len(tk) > 64:
        errs.append(("TOKEN", "TK"))
    if base and not BASE.match(base):
        errs.append(("TOKEN", "BASE"))
    n = {}
    for name, raw in (("F", f), ("T", t), ("A", a), ("ST", st), ("CF", cf),
                      ("CV", cv), ("RQ", rq), ("EXP", exp)):
        if not re.fullmatch(r"0|[1-9][0-9]*", raw):
            errs.append(("TYPE", name))
        else:
            n[name] = int(raw)
    for name, reg in (("F", ROLES), ("T", ROLES), ("A", ACTS),
                      ("ST", STATES), ("RQ", RQS)):
        if name in n and n[name] not in reg:
            errs.append(("CODE", "%s=%d" % (name, n[name])))
    for name in ("CF", "CV"):
        if n.get(name, 0) > 100:
            errs.append(("RANGE", name))
    if n.get("F") in (0, OPERATOR, SWARM):
        errs.append(("ROLE", "F=%d" % n["F"]))
    if n.get("T") in (0, OPERATOR):
        errs.append(("ROLE", "T=%d" % n["T"]))
    if n.get("A") == 0:
        errs.append(("CODE", "A=0"))
    if re.search(r"\( | \)|  |^ | $", body):
        errs.append(("CANON", "BODY spacing"))
    hub = {k: [] for k in HUB_KEYS.values()}
    if body:
        exprs, perr = parse_all(body)
        if perr:
            errs.append(("BODY", perr))
            exprs = []
        core = []
        for e in exprs:
            if not (isinstance(e[0], str) and e[0].isdigit()):
                errs.append(("BODY", "head"))
            elif int(e[0]) in HUB_OPS:
                herr = check_hub_op(e)
                if herr:
                    errs.append(("BODY", herr))
                elif int(e[0]) == 104:
                    hub["def"].append(e[1:])
                else:
                    hub[HUB_KEYS[int(e[0])]].extend(e[1:])
            else:
                cerr = check_expr(e)
                if cerr:
                    errs.append(("BODY", cerr))
                else:
                    core.append(e)
        if not any(c == "BODY" for c, _ in errs):
            serr = check_scope(core)
            if serr:
                errs.append(("SCOPE", serr))
    if len(fields) == 14 and (not SUM.match(fields[13])
                              or fields[13] != rcp_sum("|".join(bare))):
        errs.append(("RCP", "SUM"))
    if errs:
        return None, errs
    pkt = {"id": pid, "tk": tk, "f": n["F"], "t": n["T"], "a": n["A"],
           "st": n["ST"], "cf": n["CF"], "cv": n["CV"], "body": body,
           "rq": n["RQ"], "base": base, "exp": n["EXP"],
           "raw": "|".join(bare)}
    pkt.update(hub)
    return pkt, []


def parse_log(agent, text, where):
    pkts, errs, last = [], [], None
    lines = text.split("\n")
    for i, line in enumerate(lines, 1):
        if not line and i == len(lines):
            continue
        loc = "%s:%s:%d" % (where, agent, i)
        pkt, perrs = parse_line(line)
        if perrs:
            errs.extend(err(c, loc, m) for c, m in perrs)
            continue
        key = pid_key(pkt["id"])
        if last is not None and key <= last:
            errs.append(err("ORDER", loc, "ID not increasing"))
            continue
        if not pkts and not (pkt["a"] == 10 and pkt["cap"]):
            errs.append(err("JOIN", loc, "log[0] wants A=10 (102 cap+)"))
            continue
        if pkt["a"] in REPLY_ACTS and not pkt["re"]:
            errs.append(err("RE", loc, "A=%d wants (100 addr)" % pkt["a"]))
            continue
        last = key
        pkt["agent"] = agent
        pkt["addr"] = "%s/%s" % (agent, pkt["id"])
        pkt["key"] = key
        pkts.append(pkt)
    if text and not text.endswith("\n"):
        errs.append(err("CANON", "%s:%s" % (where, agent), "no final newline"))
    return pkts, errs


def git(root, *args, data=None):
    try:
        r = subprocess.run(["git", "-C", root] + list(args), input=data,
                           capture_output=True)
    except OSError:
        return None
    return r.stdout if r.returncode == 0 else None


def read_sources(root, refs):
    logs, objs = [], {}
    ld, od = os.path.join(root, "log"), os.path.join(root, "obj")
    for name in sorted(os.listdir(ld)) if os.path.isdir(ld) else []:
        with open(os.path.join(ld, name), "rb") as fh:
            logs.append((".", name, fh.read()))
    for name in sorted(os.listdir(od)) if os.path.isdir(od) else []:
        objs.setdefault(name, (".", os.path.join(od, name)))
    if not refs or git(root, "rev-parse", "--git-dir") is None:
        return logs, objs
    out = git(root, "for-each-ref", "--format=%(refname)", "refs/remotes")
    blobs = []
    for ref in (out or b"").decode().split():
        if ref.endswith("/HEAD"):
            continue
        tree = git(root, "ls-tree", "-r", ref, "--", "log", "obj") or b""
        for row in tree.decode().splitlines():
            meta, path = row.split("\t", 1)
            kind, name = path.split("/", 1)
            sha = meta.split()[2]
            if kind == "obj":
                objs.setdefault(name, (ref, sha))
            elif "/" not in name:
                blobs.append((ref, name, sha))
    if blobs:
        batch = git(root, "cat-file", "--batch",
                    data="".join(b[2] + "\n" for b in blobs).encode()) or b""
        pos = 0
        for ref, name, sha in blobs:
            head_end = batch.index(b"\n", pos)
            size = int(batch[pos:head_end].split()[2])
            logs.append((ref, name, batch[head_end + 1:head_end + 1 + size]))
            pos = head_end + 1 + size + 1
    return logs, objs


def load(root, refs):
    logs, objs = read_sources(root, refs)
    flags, seen, bad = [], {}, set()
    for where, name, data in logs:
        m = LOGFILE.match(name)
        if not m:
            flags.append(err("PATH", where, "log/" + name))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            flags.append(err("SYN", where, "log/" + name + " utf-8"))
            continue
        pkts, errs = parse_log(m.group(1), text, where)
        flags.extend(errs)
        for p in pkts:
            prior = seen.get(p["addr"])
            if prior is None:
                seen[p["addr"]] = p
            elif prior["raw"] != p["raw"]:
                bad.add(p["addr"])
    for addr in sorted(bad):
        flags.append(err("EQUIV", addr, "same addr, different line"))
        del seen[addr]
    for name in sorted(objs):
        if not OFILE.match(name):
            flags.append(err("PATH", objs[name][0], "obj/" + name))
    pkts = sorted(seen.values(), key=lambda p: (p["key"], p["agent"]))
    return pkts, objs, flags


def obj_index(objs):
    idx = {}
    for name, src in objs.items():
        m = OFILE.match(name)
        if m:
            idx.setdefault(m.group(1), (name,) + src)
    return idx


def obj_bytes(root, entry):
    name, where, loc = entry
    if where == ".":
        with open(loc, "rb") as fh:
            return fh.read()
    return git(root, "cat-file", "blob", loc)


def oid_of(data):
    return "o" + hashlib.sha256(data).hexdigest()[:16]


def fold(pkts, now):
    agents, items, flags, lex = {}, {}, [], {}
    byaddr = {p["addr"]: p for p in pkts}
    for p in pkts:
        me, t = p["agent"], p["key"][0]
        if me not in agents:
            agents[me] = {"role": p["f"], "cap": p["cap"], "join": p["addr"]}
        agents[me]["last"] = p["addr"]
        for sym, oid in p["def"]:
            if sym not in lex:
                lex[sym] = {"oid": oid, "by": p["addr"]}
            elif lex[sym]["oid"] != oid:
                flags.append(err("LEX", p["addr"], sym))
        for ref in p["re"]:
            if ref not in byaddr:
                flags.append(err("REF", p["addr"], ref))
                continue
            it = items.get(ref)
            if it is None:
                continue
            it["n"] += 1
            it["last"] = p["key"]
            it["lastby"] = me
            it["obj"] = sorted(set(it["obj"]) | set(p["obj"]))
            transition(it, p, me, t, flags)
        if p["a"] in ITEM_ACTS:
            items[p["addr"]] = {
                "addr": p["addr"], "a": p["a"], "tk": p["tk"], "by": me,
                "own": None, "until": None, "st": p["st"] or 5, "n": 0,
                "obj": list(p["obj"]), "last": p["key"], "lastby": me,
            }
    for it in items.values():
        if it["st"] == 2 and it["until"] is not None and it["until"] < now:
            it["st"], it["own"] = 8, None
    return agents, items, lex, flags


def transition(it, p, me, t, flags):
    st, by, own = p["st"], it["by"], it["own"]
    if not st:
        return
    if it["st"] in TERMINAL and not (st == 5 and me == by):
        flags.append(err("TERM", p["addr"], it["addr"]))
        return
    if st == 2:
        live = own is not None and (it["until"] is None or it["until"] >= t)
        if live and own != me:
            flags.append(err("LEASE", p["addr"], it["addr"]))
            return
        it["own"] = me
        it["until"] = t + p["exp"] if p["exp"] else None
    elif st in (3, 4):
        if me == own:
            flags.append(err("AUTH", p["addr"], "self-verify"))
            return
    elif me not in (by, own):
        flags.append(err("AUTH", p["addr"], it["addr"]))
        return
    if st == 5:
        it["own"], it["until"] = None, None
    it["st"] = st


def addressed(p, me, role):
    if p["to"]:
        return me in p["to"]
    return p["t"] in (role, SWARM)


def views(pkts, agents, items, me):
    role = agents.get(me, {}).get("role")
    inbox, watch = [], []
    mine = {}
    for p in pkts:
        for ref in p["re"]:
            if p["agent"] == me:
                mine[ref] = p["key"]
    for p in pkts:
        if p["agent"] == me or not addressed(p, me, role):
            continue
        it = items.get(p["addr"])
        seen = mine.get(p["addr"])
        if it is not None:
            if it["st"] in TERMINAL or it["own"] not in (None, me):
                continue
            if seen is not None and seen >= it["last"]:
                continue
            if it["lastby"] == me:
                continue
        elif not p["rq"] or seen is not None or any(
                items.get(r, {}).get("st") in TERMINAL for r in p["re"]):
            continue
        inbox.append(p["addr"])
    for it in items.values():
        if me in (it["by"], it["own"]) and it["lastby"] != me \
                and it["st"] not in TERMINAL:
            watch.append(it["addr"])
    return inbox, watch


def self_id(root, opts):
    if opts.get("as"):
        return opts["as"]
    if os.environ.get("HUB_SELF"):
        return os.environ["HUB_SELF"]
    path = os.path.join(root, ".hub-self")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip() or None
    return None


def show(it):
    out = {k: it[k] for k in ("addr", "a", "tk", "by", "own", "st", "n")}
    if it["until"] is not None:
        out["until"] = it["until"]
    if it["obj"]:
        out["obj"] = it["obj"]
    return out


def state(root, opts):
    pkts, objs, flags = load(root, opts["refs"])
    agents, items, lex, fflags = fold(pkts, opts["now"])
    me = self_id(root, opts)
    byaddr = {p["addr"]: p for p in pkts}
    out = {"profile": PROFILE, "now": opts["now"], "self": me,
           "agents": agents}
    shown = [show(it) for it in items.values()
             if opts.get("all") or it["st"] not in TERMINAL]
    out["items"] = shown
    if me in agents:
        inbox, watch = views(pkts, agents, items, me)
        out["inbox"] = [[a, byaddr[a]["raw"]] for a in inbox]
        out["watch"] = watch
    out["lex"] = lex
    out["obj"] = len(obj_index(objs))
    out["flags"] = flags + fflags
    out["next"] = next_steps(me, agents, out)
    return out


def next_steps(me, agents, out):
    cmd = "python3 hub.py"
    if me is None or me not in agents:
        return ["%s --root ex --as kc --now 1760000500 state" % cmd,
                "%s sync" % cmd,
                "%s join <%s> <cap>+" % (cmd, "|".join(map(str, AGENT_ROLES)))]
    steps = ["%s sync" % cmd]
    if out.get("inbox") or out.get("watch"):
        steps.append("%s thread <addr>" % cmd)
    steps += ["%s put '2|_|<TK>|%d|<T>|<A>|<ST>|<CF>|<CV>|<BODY>|<RQ>||<EXP>'"
              % (cmd, agents[me]["role"]),
              "%s push" % cmd]
    return steps


def primer(root, opts):
    out = {
        "profile": PROFILE, "wire": WIRE, "src": SRC,
        "line": "V|ID|TK|F|T|A|ST|CF|CV|BODY|RQ|BASE|EXP[|SUM]",
        "field": {"V": "version", "ID": "time", "TK": "thread",
                  "F": "from.role", "T": "to.role", "A": "act",
                  "ST": "state", "CF": "confidence", "CV": "coverage",
                  "BODY": "sexpr*", "RQ": "request", "BASE": "object:version",
                  "EXP": "lease.s", "SUM": "checksum"},
        "V": 2, "ID": PID.pattern, "TK": TOKEN.pattern + " len<=64",
        "CF": "0-100", "CV": "0-100", "EXP": "s", "BASE": "''|id:ver",
        "SUM": "sha256(line[0:13])[:16]",
        "F": AGENT_ROLES, "T": AGENT_ROLES + [SWARM],
        "role": {k: v for k, v in ROLES.items() if k},
        "A": {k: v for k, v in ACTS.items() if k},
        "ST": STATES, "RQ": RQS,
        "op": {**CORE_OPS, **HUB_OPS},
        "agent": AGENT.pattern, "addr": ADDR.pattern, "oid": OID.pattern,
        "log": "log/<agent>.s2", "objdir": "obj/<oid>[.ext]",
        "fold": FOLD,
        "cmd": {
            "": "primer",
            "join": "<role> <cap>+ [--as agent] ; no --as -> a<8hex>",
            "put": "<line>+ ; ID=_ -> max(now, last+.1) ; [--rcp]",
            "state": "[--all]",
            "thread": "<addr>",
            "log": "[TK]",
            "obj": "<file|-> [.ext]",
            "get": "<oid>",
            "check": "",
            "sync": "",
            "push": "",
            "*": "[--root dir -> --local] [--as agent] [--now s] [--local]",
        },
        "ex": "ex/log/*.s2 ex/obj/* ; fixture ; --root <copy> to write",
        "test": "python3 -m unittest -q test_hub",
    }
    s = state(root, opts)
    out["self"] = s["self"]
    out["next"] = s["next"]
    return out


def write_line(root, me, line, rcp, now):
    path = os.path.join(root, "log", me + ".s2")
    prior = ""
    if os.path.exists(path):
        with open(path) as fh:
            prior = fh.read()
    fields = line.split("|")
    if len(fields) >= 2 and fields[1] == "_":
        lines = [x for x in prior.split("\n") if x]
        last = pid_key(lines[-1].split("|")[1]) if lines else (0, 0)
        key = (now, 0) if now > last[0] else (last[0], last[1] + 1)
        fields[1] = pid_str(key)
    if rcp and len(fields) == 13:
        fields.append(rcp_sum("|".join(fields)))
    line = "|".join(fields)
    pkts, errs = parse_log(me, prior + line + "\n", ".")
    if errs:
        return None, errs
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as fh:
        fh.write(line + "\n")
    return line, []


def cmd_join(root, opts, args):
    if not args or not args[0].isdigit() or int(args[0]) not in AGENT_ROLES \
            or len(args) < 2:
        return fail(2, ["usage", "join <role> <cap>+"])
    me = self_id(root, opts) or "a" + os.urandom(4).hex()
    if not AGENT.match(me):
        return fail(2, ["agent", AGENT.pattern])
    if os.path.exists(os.path.join(root, "log", me + ".s2")):
        return fail(1, err("JOIN", me, "exists"))
    line, errs = write_line(
        root, me, "2|_|hub|%s|7|10|5|100|100|(102 %s)|0||0"
        % (args[0], " ".join(args[1:])), False, opts["now"])
    if errs:
        return fail(1, *errs)
    with open(os.path.join(root, ".hub-self"), "w") as fh:
        fh.write(me + "\n")
    emit({"self": me, "line": line, "next": ["python3 hub.py push",
                                             "python3 hub.py state"]})
    return 0


def cmd_put(root, opts, args):
    me = self_id(root, opts)
    if not me:
        return fail(2, ["self", "join"])
    if not os.path.exists(os.path.join(root, "log", me + ".s2")):
        return fail(1, err("JOIN", me, "missing"))
    out = []
    for line in args:
        done, errs = write_line(root, me, line, opts.get("rcp"), opts["now"])
        if errs:
            return fail(1, *errs)
        out.append(done)
    emit({"put": out})
    return 0


def cmd_thread(root, opts, args):
    if len(args) != 1:
        return fail(2, ["usage", "thread <addr>"])
    pkts, _, _ = load(root, opts["refs"])
    want = {args[0]}
    rows = []
    for p in pkts:
        if p["addr"] in want or want & set(p["re"]):
            want.add(p["addr"])
            rows.append(p["addr"] + " " + p["raw"])
    print("\n".join(rows))
    return 0 if rows else 1


def cmd_log(root, opts, args):
    pkts, _, _ = load(root, opts["refs"])
    for p in pkts:
        if not args or p["tk"] in args:
            print(p["addr"] + " " + p["raw"])
    return 0


def cmd_obj(root, opts, args):
    if len(args) not in (1, 2):
        return fail(2, ["usage", "obj <file|-> [.ext]"])
    if args[0] == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args[0], "rb") as fh:
            data = fh.read()
    oid = oid_of(data)
    ext = (args[1] if len(args) == 2 else os.path.splitext(args[0])[1]).lower()
    name = oid + (ext if re.fullmatch(r"\.[a-z0-9]{1,8}", ext) else "")
    os.makedirs(os.path.join(root, "obj"), exist_ok=True)
    path = os.path.join(root, "obj", name)
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(data)
    emit({"oid": oid, "path": "obj/" + name, "op": "(103 %s)" % oid})
    return 0


def cmd_get(root, opts, args):
    if len(args) != 1 or not OID.match(args[0]):
        return fail(2, ["usage", "get <oid>"])
    _, objs, _ = load(root, opts["refs"])
    entry = obj_index(objs).get(args[0])
    data = obj_bytes(root, entry) if entry else None
    if data is None or oid_of(data) != args[0]:
        return fail(1, err("OBJ", args[0], "missing or hash"))
    sys.stdout.buffer.write(data)
    return 0


def cmd_check(root, opts, args):
    pkts, objs, flags = load(root, opts["refs"])
    _, _, _, fflags = fold(pkts, opts["now"])
    flags += [f for f in fflags if f[0] == "ERR:LEX"]
    warn = [f for f in fflags if f[0] != "ERR:LEX"]
    idx = obj_index(objs)
    for oid, entry in sorted(idx.items()):
        data = obj_bytes(root, entry)
        if data is None or oid_of(data) != oid:
            flags.append(err("OBJ", entry[1], oid))
    for p in pkts:
        for oid in p["obj"] + [d[1] for d in p["def"]]:
            if oid not in idx:
                warn.append(err("OBJ", p["addr"], oid))
    emit({"packets": len(pkts), "obj": len(idx), "flags": flags,
          "warn": warn})
    return 1 if flags else 0


def cmd_sync(root, opts, args):
    out = git(root, "fetch", "-q", "--prune", "origin",
              "+refs/heads/*:refs/remotes/origin/*")
    if out is None:
        return fail(2, ["git", "fetch"])
    refs = git(root, "for-each-ref", "--format=%(refname)", "refs/remotes")
    emit({"sync": len((refs or b"").split())})
    return 0


def cmd_push(root, opts, args):
    dirs = [d for d in ("log", "obj") if os.path.isdir(os.path.join(root, d))]
    if dirs and git(root, "add", "--", *dirs) is None:
        return fail(2, ["git", "add"])
    diff = (git(root, "diff", "--cached", "--unified=0", "--", "log") or b"")
    added = [x[1:] for x in diff.decode().splitlines()
             if x.startswith("+") and not x.startswith("+++")]
    staged = git(root, "diff", "--cached", "--name-only") or b""
    if staged.strip():
        msg = "\n".join(added) or "obj"
        if git(root, "commit", "-q", "-m", msg) is None:
            return fail(2, ["git", "commit"])
    branch = (git(root, "rev-parse", "--abbrev-ref", "HEAD") or b"").strip()
    if not branch:
        return fail(2, ["git", "branch"])
    branch = branch.decode()
    if git(root, "ls-remote", "--exit-code", "--heads", "origin", branch):
        if git(root, "pull", "-q", "--rebase", "origin", branch) is None:
            return fail(2, ["git", "pull --rebase"])
    for delay in (0, 2, 4, 8, 16):
        time.sleep(delay)
        if git(root, "push", "-q", "-u", "origin", branch) is not None:
            emit({"push": branch, "lines": added})
            return 0
    return fail(2, ["git", "push"])


def emit(obj):
    print(json.dumps(obj, separators=(",", ":"), sort_keys=False))


def fail(code, *rows):
    print(json.dumps({"exit": code, "err": list(rows)},
                     separators=(",", ":")), file=sys.stderr)
    return code


COMMANDS = {
    "join": cmd_join, "put": cmd_put, "thread": cmd_thread, "log": cmd_log,
    "obj": cmd_obj, "get": cmd_get, "check": cmd_check, "sync": cmd_sync,
    "push": cmd_push,
}


def main(argv):
    opts = {"root": HERE, "now": int(time.time()), "refs": True}
    args = []
    it = iter(argv)
    for a in it:
        if a in ("--root", "--as", "--now"):
            v = next(it, None)
            if v is None:
                return fail(2, ["usage", a])
            opts[a[2:]] = v
        elif a in ("--all", "--rcp", "--local"):
            opts[a[2:]] = True
        else:
            args.append(a)
    try:
        opts["now"] = int(opts["now"])
    except ValueError:
        return fail(2, ["usage", "--now"])
    if opts["root"] != HERE:
        cand = os.path.abspath(opts["root"])
        opts["root"] = cand if os.path.isdir(cand) else os.path.join(
            HERE, opts["root"])
        opts["refs"] = False
    if opts.get("local"):
        opts["refs"] = False
    root = opts["root"]
    if not args or args[0] in ("-h", "--help", "help"):
        emit(primer(root, opts))
        return 0
    if args[0] == "state":
        emit(state(root, opts))
        return 0
    if args[0] not in COMMANDS:
        return fail(2, ["usage", sorted(["state"] + list(COMMANDS))])
    return COMMANDS[args[0]](root, opts, args[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
