#!/usr/bin/env python3
"""Shared parsing for SYM-2P v2 dense packets. stdlib only.

Both sym2-render.py and sym2-validate.py import from here so the wire
grammar lives in exactly one place. Covers the base task language
(opcodes 10-22) and the v2.1 reasoning extension (opcodes 30-40).
"""
import hashlib
import re

TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
BASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*:[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
SYM = re.compile(r"^(?:\*|[A-Za-z][A-Za-z0-9_./-]*)$")
REF = re.compile(r"^\$[A-Za-z][A-Za-z0-9_./-]*$")
SUM = re.compile(r"^[0-9a-f]{16}$")

ROLES = {0: "reserved", 1: "coordinator", 2: "builder", 3: "verifier",
         4: "scout", 5: "critic", 6: "operator", 7: "swarm"}
ACTS = {0: "none", 1: "assign", 2: "acknowledge", 3: "assert", 4: "update",
        5: "receipt", 6: "challenge", 7: "dispute", 8: "authorize",
        9: "query", 10: "inform", 11: "delegate", 12: "report"}
STATES = {0: "none", 1: "proposed", 2: "accepted", 3: "rejected",
          4: "verified", 5: "open", 6: "closed", 7: "superseded",
          8: "expired"}
RQS = {0: "none", 1: "acknowledgement required", 2: "verification required"}
UNITS = {"sec": "sections"}

FIELD_NAMES = ["V", "ID", "TK", "F", "T", "A", "ST", "CF", "CV",
               "BODY", "RQ", "BASE", "EXP"]
FIELD_NAMES_RCP = FIELD_NAMES + ["SUM"]


def tokenize(text):
    tokens, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "()":
            tokens.append(c)
            i += 1
        elif c.isspace():
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "()":
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def parse_all(text):
    """Parse concatenated s-expressions. Returns (exprs, error)."""

    def parse(pos):
        pos += 1  # consume '('
        items = []
        while pos < len(tokens) and tokens[pos] != ")":
            if tokens[pos] == "(":
                sub, pos = parse(pos)
                items.append(sub)
            else:
                items.append(tokens[pos])
                pos += 1
        if pos >= len(tokens):
            raise ValueError("unbalanced parentheses")
        return items, pos + 1

    tokens = tokenize(text)
    try:
        exprs, pos = [], 0
        while pos < len(tokens):
            if tokens[pos] != "(":
                raise ValueError("top-level atom outside expression")
            expr, pos = parse(pos)
            exprs.append(expr)
    except ValueError as ex:
        return None, str(ex)
    return exprs, None


def is_num(t):
    return isinstance(t, str) and t.isdigit()


def is_sym(t):
    return isinstance(t, str) and bool(SYM.match(t))


def is_ref(t):
    """A $name reference to a bound variable."""
    return isinstance(t, str) and bool(REF.match(t))


def is_atom(t):
    return is_num(t) or is_sym(t) or is_ref(t)


def as_op(e, want):
    if not isinstance(e, list) or not e or e[0] != str(want):
        return "want (%d ...)" % want
    return check_expr(e)


def check_expr(e):
    """Check one s-expression against the opcode grammar. None means ok."""
    if not isinstance(e, list) or not e:
        return "empty expression"
    if not (isinstance(e[0], str) and e[0].isdigit()):
        return "expression head is not an opcode"
    op, args = int(e[0]), e[1:]
    if op == 10:
        if len(args) != 2 or not is_sym(args[0]):
            return "scope wants (10 target impl)"
        return as_op(args[1], 20)
    if op == 11:
        if len(args) != 1:
            return "constraint wants (11 constraint)"
        return as_op(args[0], 21)
    if op == 12:
        if len(args) != 1:
            return "accept wants (12 accept)"
        return as_op(args[0], 22)
    if op == 20:
        if len(args) != 2 or not is_sym(args[0]):
            return "impl wants (20 unit range)"
        r = args[1]
        if isinstance(r, list):
            if not (len(r) == 2 and all(is_atom(x) for x in r)):
                return "range wants (lo hi)"
        elif not is_atom(r):
            return "range wants (lo hi) or a single atom"
        return None
    if op == 21:
        if len(args) != 1 or not is_sym(args[0]):
            return "nomod wants (21 paths)"
        return None
    if op == 22:
        if len(args) != 3 or not is_sym(args[0]) \
                or not is_num(args[1]) or not is_num(args[2]):
            return "exit wants (22 prog ok bad)"
        return None
    if op == 30:
        if len(args) != 2 or not is_sym(args[0]):
            return "bind wants (30 name expr)"
        v = args[1]
        if isinstance(v, list):
            return check_expr(v)
        if not is_atom(v):
            return "bind value must be an atom or expression"
        return None
    if op == 31:
        if len(args) != 3:
            return "if wants (31 test then else)"
        for i, a in enumerate(args):
            if isinstance(a, list):
                if not a:
                    if i != 2:
                        return "only the else branch may be ()"
                    continue
                err = check_expr(a)
                if err:
                    return err
            elif not is_atom(a):
                return "if branches must be atoms or expressions"
        return None
    if op == 32:
        if len(args) != 3 or not is_sym(args[0]):
            return "each wants (32 var items body)"
        items = args[1]
        if isinstance(items, list):
            if not items or items[0] != "33":
                return "each iterates a (33 ...) list"
            err = check_expr(items)
            if err:
                return err
        elif not is_ref(items):
            return "each iterates a (33 ...) list or a $reference"
        body = args[2]
        if isinstance(body, list):
            return check_expr(body)
        if not is_atom(body):
            return "each body must be an atom or expression"
        return None
    if op == 33:
        for a in args:
            if not is_atom(a):
                return "list items must be atoms"
        return None
    if op in (34, 35):
        name = "lt" if op == 34 else "eq"
        if len(args) != 2 or not all(is_atom(a) for a in args):
            return "%s wants (%d a b)" % (name, op)
        return None
    if op == 40:
        if len(args) != 3 or not is_num(args[0]) \
                or int(args[0]) not in ROLES:
            return "spawn wants (40 role thread task)"
        if not TOKEN.match(args[1]):
            return "spawn thread must be a token"
        task = args[2]
        if isinstance(task, list):
            return check_expr(task)
        if not is_atom(task):
            return "spawn task must be an atom or expression"
        return None
    return "unknown opcode %d" % op


def check_scope(exprs):
    """Check that every $reference resolves to a visible bind.

    bind names are visible to the top-level expressions that follow
    them. Inside if branches and each bodies, bindings are local and
    do not leak outward. None means ok. Assumes check_expr passed.
    """
    bound = set()
    for e in exprs:
        err = _scan_one(e, bound)
        if err:
            return err
        if isinstance(e, list) and e and e[0] == "30":
            bound.add(e[1])
    return None


def _scan_one(e, bound):
    if isinstance(e, str):
        if is_ref(e) and e[1:] not in bound:
            return "unbound reference %s" % e
        return None
    if not e:
        return None
    if not (isinstance(e[0], str) and e[0].isdigit()):
        # not an expression (e.g. a range pair): scan the atoms
        for x in e:
            err = _scan_one(x, bound)
            if err:
                return err
        return None
    op, args = int(e[0]), e[1:]
    if op == 30:
        return _scan_one(args[1], bound)
    if op == 31:
        for a in args:
            err = _scan_one(a, set(bound))
            if err:
                return err
        return None
    if op == 32:
        err = _scan_one(args[1], set(bound))
        if err:
            return err
        return _scan_one(args[2], set(bound) | {args[0]})
    for a in args:
        err = _scan_one(a, set(bound))
        if err:
            return err
    return None


def rcp_sum(bare_line):
    """Checksum for a v2-rcp line: first 16 hex chars of the sha256
    of the canonical 13-field line, encoded UTF-8."""
    return hashlib.sha256(bare_line.encode("utf-8")).hexdigest()[:16]


def add_rcp(bare_line):
    """Append the checksum field to a canonical bare v2 line."""
    return bare_line + "|" + rcp_sum(bare_line)


def split_fields(line):
    """Split a v2 line into fields. Bare v2 has 13 fields; v2-rcp has
    14 (the 14th is the SUM checksum). Returns (fields, error)."""
    fields = line.split("|")
    if len(fields) not in (13, 14):
        return None, "want 13 fields (bare) or 14 (rcp), have %d" % len(
            fields)
    if fields[0] != "2":
        return None, "want wire version 2"
    return fields, None
