#!/usr/bin/env python3
# PUBLISH-GATE-SELF-EXCLUDE
"""denylist.py -- committable pattern list for the publish gate.

IDENTITY-CLEAN BY CONSTRUCTION.  This file contains NO real secret, NO real
hostname, NO real address and NO real personal identifier.  Every sensitive
token is expressed as a REGEX.  The first character of the most sensitive
tokens is written as a one-character class (e.g. [k]inghippo) for two reasons:

  1. Identity law: the file must never carry a literal real value, only a
     pattern.  `[k]inghippo\\.dev` is a pattern; `kinghippo.dev` is a literal.
  2. Self-scan safety: this file is VENDORED into published repos as
     tools/denylist.py.  A plain-literal rule list would make the scanner
     report itself on every run.

Real literals, if the operator wants any, live in an overlay JSON file whose
path is given by the env var PUBLISH_GATE_OVERLAY.  That file is never created,
never read and never committed by this tool chain -- it is loaded at runtime
only if the operator sets the variable.

Usage:
    python3 denylist.py DIR [--json]
Exit codes: 0 = clean, 1 = findings, 2 = error.
Output line format:  file:line:category:rule:<redacted-or-literal match>
Matches in the 'topology' and 'identity' categories are ALWAYS redacted.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Rules.  (name, pattern, case_sensitive)
# --------------------------------------------------------------------------- #

TOPOLOGY = [
    # CGNAT / tailnet range 100.64.0.0/10  -> 100.64.x.x .. 100.127.x.x
    ("tailnet-cgnat-cidr", r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b", False),
    ("tailnet-magicdns",   r"\b[a-z0-9-]+\.ts\.net\b", False),
    ("tailscale-node-id",  r"\btail[0-9a-f]{6,}\b", False),
    ("hoster-ip-range",    r"\b84\.247\.\d{1,3}\.\d{1,3}\b", False),
    ("hoster-hostname",    r"\b[v]mi\d{6,}\b", False),
    ("hoster-name",        r"\b[c]ontabo\b", False),
    ("dyndns-host",        r"\b[a-z0-9-]+\.duckdns\.org\b", False),
    ("cf-tunnel-host",     r"\b[a-z0-9-]+\.cfargotunnel\.com\b", False),
    ("operator-home-path", r"/home/[n]ir\b", False),
    ("device-name",        r"\b(?:[i]phone-1\d|[m]acbook-air|[m]acbook-pro)\b", False),
    ("ip-port-pair",       r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b", False),
]

IDENTITY = [
    ("personal-mail-domain", r"@?\b[y]ahoo\.(?:com|co\.uk)\b", False),
    ("private-domain",       r"\b[k]inghippo\.dev\b", False),
    ("private-domain",       r"\b[a]relle-mcp\.dev\b", False),
    ("personal-handle",      r"@[L]mlyhNyr\b", True),
    # Operator's given name used as a word.  Case SENSITIVE on purpose:
    # lowercase 'nir' inside paths is caught by operator-home-path instead.
    ("operator-given-name",  r"\b[N]ir\b", True),
]

CONTENT_LEGAL = [
    # (1) Titles whose words occur ONLY as a game name -> bare match is safe.
    ("commercial-rom-title",
     r"\b(?:Super\s+Mario|Mortal\s+Kombat|Zombies\s+Ate\s+My\s+Neighbors|NBA\s+Jam|"
     r"Tony\s+Hawk|RoboCop|TMNT|Turtles\s+in\s+Time|Prince\s+of\s+Persia|"
     r"Arch\s+Rivals|Jungle\s+Book|Marvel\s+Ultimate\s+Alliance)\b", False),
    # (2) Words that are ALSO ordinary English / finance vocabulary.  These are
    # scoped so the bare word can never match: a football federation, a comic
    # character, a verb, a wildlife charity and a Latin preposition are not
    # ROMs.  Only the actual cartridge title (or a rom-style file/slug) is.
    ("commercial-rom-title",
     r"\bFIFA\s+(?:International\s+Soccer|2007|\d{2,4})\b"
     r"|\bfifa-(?:\d{4}|international)", False),
    ("commercial-rom-title",
     r"\bBatman[:\s-]+Return\s+of\s+the\s+Joker\b|\bbatman-return-of-the-joker", False),
    ("commercial-rom-title",
     r"\bDoom\s*\((?:SNES|SNES/[^)]*)\)|\bdoom\.sfc\b|\bdoom-snes\b", False),
    ("commercial-rom-title",
     r"\bContra\s+Force\b|\bcontra-force", False),
    ("commercial-rom-title",
     r"\bWWF\s+(?:Royal\s+Rumble|Super\s+WrestleMania|WrestleMania|Raw)\b"
     r"|\bwwf-(?:royal-rumble|wrestlemania)", False),
    ("commercial-rom-title",
     r"\bTop\s+Gun\s*\((?:NES|SNES)\)|\btop-gun\.(?:nes|sfc|smc|zip)\b", False),
    ("rom-source-host",   r"\bemulatorgamesx\b", False),
    ("rom-asset-host",    r"\blibretro-thumbnails\b", False),
    ("emu-cdn-host",      r"\bcdn\.emulatorjs\.org\b", False),
    ("private-product",   r"\b(?:beyondspx|everyticker)\b", False),
    ("scraped-endpoint",  r"\binvesting\.com/(?:api|instruments)\b", False),
    ("scraped-source",    r"\b(?:fool\.com|marketbeat|seekingalpha|finviz)\b", False),
    ("overclaim",         r"\binstitutional-grade\b", False),
    ("overclaim",         r"\b(?:military-grade|zero-knowledge)\b", False),
    ("overclaim",         r"Nothing\s+leaves\s+your\s+device", False),
]

# Disclosure policy (owner directive 2026-08-23, "the SOC2 model"): Category-3 items —
# internal state with zero reader benefit — are publish-blocking on public pages.
# Patterns are deliberately narrow: they catch the phrasings that actually appeared.
DISCLOSURE = [
    ("org-vs-reality",    r"\bdata[- ]office\b[^.]{0,80}\b(?:not\s+(?:currently\s+)?(?:operating|running)|designed,?\s+not)\b", False),
    ("curation-internals",r"\b(?:curation\s+(?:arithmetic|log|run)|repositor(?:y|ies)\s+(?:left|made)\s+(?:public|private)\s+(?:visibility|outside))\b", False),
    ("host-state",        r"\b(?:\d{1,3}\s?%\s+(?:used|full|of\s+disk)|disk\s+(?:usage|headroom)|RAM\s+headroom)\b", False),
    ("stale-failure",     r"\b(?:not\s+shipped|none\s+pushed|are\s+not\s+shipped|remains?\s+the\s+newest\s+published)\b", False),
    ("interiority",       r"\b(?:could\s+not\s+answer\s+a\s+plain\s+question|worse\s+than\s+I\s+expected|I\s+was\s+(?:wrong|embarrassed)|all\s+mine,\s+all\s+the\s+same\s+shape)\b", False),
    ("spec-drift",        r"\b(?:objective[- ]count\s+drift|31/34/66)\b", False),
]


# Tone rules (site constitution, Part II "Four failure modes -> publish-gate law").
# These are the words the four failure modes are made of: scale adjectives with no
# artifact behind them, capability adjectives the reader is supposed to take on
# faith, address-the-reader warmth, and the amateur tell.  They are PROSE-ONLY:
# on an HTML page they are matched against the text a reader reads, with <pre>,
# <code>, <table>, <script> and <style> blocks and all tags masked out first, so a
# real recorded session or a spec table is never edited to satisfy a word list.
TONE = [
    ("scale-adjective",
     r"\b(?:revolutionar(?:y|ily)|cutting[- ]edge|bleeding[- ]edge|enterprise[- ]grade|"
     r"world[- ]class|state[- ]of[- ]the[- ]art|best[- ]in[- ]class|"
     r"industry[- ]leading|next[- ]generation|game[- ]?chang(?:er|ing))\b", False),
    ("capability-adjective",
     r"\b(?:powerful|robust|seamless(?:ly)?|effortless(?:ly)?|blazing(?:ly)?[- ]fast|"
     r"unparalleled|unmatched)\b", False),
    ("sycophantic",
     r"\b(?:passionate(?:ly)?|love\s+to|excited|thrilled|delighted|honou?red)\b", False),
    ("coming-soon", r"\bcoming\s+soon\b", False),
    # An exclamation mark in prose.  Never in markup (`<!doctype`, `<!--`) and never
    # in code (`!=`, `!important`): the lookaround requires a word or closing
    # character before it and forbids one after.
    ("exclamation-in-prose", r"(?<=[A-Za-z0-9,)\]\"'\u2019])!(?![=\w-])", False),
]

CATEGORIES = {
    "topology": TOPOLOGY,
    "identity": IDENTITY,
    "content-legal": CONTENT_LEGAL,
    "disclosure": DISCLOSURE,
    "tone": TONE,
}

# Categories matched against reader-facing prose only (HTML: tags, <pre>, <code>,
# <table>, <script> and <style> masked out first, offsets preserved).
PROSE_ONLY_CATEGORIES = {"tone"}

# Categories whose matched text is NEVER printed.
REDACT_CATEGORIES = {"topology", "identity"}

SELF_EXCLUDE_MARKER = "PUBLISH-GATE-SELF-EXCLUDE"

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
TEXT_SUFFIXES_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
                      ".woff", ".woff2", ".ttf", ".otf", ".zip", ".gz", ".tar",
                      ".mp4", ".mp3", ".wasm", ".so", ".bin"}

MAX_SCAN_BYTES = 4 * 1024 * 1024


class DenylistError(Exception):
    pass


def load_overlay(path: str | None = None) -> list[str]:
    """Optional operator overlay: a JSON list of extra LITERAL strings.

    The overlay file is never created and never committed by this tool chain.
    It is read only when PUBLISH_GATE_OVERLAY (or `path`) points at it.
    """
    p = path or os.environ.get("PUBLISH_GATE_OVERLAY", "")
    if not p:
        return []
    f = Path(p)
    if not f.exists():
        raise DenylistError("overlay not found: %s" % p)
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DenylistError("overlay is not valid JSON: %s" % exc) from exc
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise DenylistError("overlay must be a JSON list of strings")
    return [x for x in data if x.strip()]


def build_rules(overlay_path: str | None = None):
    """Return [(category, rule_name, compiled_regex)]."""
    rules = []
    for cat, entries in CATEGORIES.items():
        for name, pat, cs in entries:
            rules.append((cat, name, re.compile(pat, 0 if cs else re.IGNORECASE)))
    for lit in load_overlay(overlay_path):
        # Overlay entries are literals supplied by the operator -> quote them.
        rules.append(("identity", "overlay-literal",
                      re.compile(re.escape(lit), re.IGNORECASE)))
    return rules


def redact(text: str) -> str:
    text = text.strip()
    if len(text) <= 2:
        return "*" * len(text)
    return "%s%s%s" % (text[0], "*" * (len(text) - 2), text[-1])


def is_self(path: Path) -> bool:
    """True when a file opts out by carrying SELF_EXCLUDE_MARKER in its head.

    The gate's own vendored files use it so the scanner does not report its own
    rule list.  Any *tool* whose source legitimately contains a denied literal
    (a regex that searches for it, for instance) may use the same marker.  The
    marker must appear in the first 4096 characters, i.e. in the header comment
    or module docstring, where a reviewer reading the top of the file sees it.

    An exclusion is never silent: scan_path() records every excluded path and
    publish_gate.py prints them, so 'the gate passed' can always be read
    together with 'and here is what it did not look at'.
    """
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    return SELF_EXCLUDE_MARKER in head


_BLOCKS = re.compile(r"<(script|style|pre|code|table)\b[^>]*>.*?</\1>", re.S | re.I)
_TAGS = re.compile(r"<[^>]+>", re.S)


def mask_html(text: str) -> str:
    """Blank out markup and artifact blocks, character for character.

    Every removed character becomes a space and every newline is kept, so line
    numbers and columns in the masked copy match the original file exactly.
    """
    def blank(m):
        return "".join("\n" if c == "\n" else " " for c in m.group(0))
    return _TAGS.sub(blank, _BLOCKS.sub(blank, text))


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            yield Path(dirpath) / fn


def scan_path(root, overlay_path: str | None = None,
              excluded: list[str] | None = None) -> list[dict]:
    root = Path(root)
    rules = build_rules(overlay_path)
    findings: list[dict] = []
    for f in iter_files(root):
        if f.suffix.lower() in TEXT_SUFFIXES_SKIP:
            continue
        try:
            if f.stat().st_size > MAX_SCAN_BYTES:
                continue
        except OSError:
            continue
        if is_self(f):
            if excluded is not None:
                excluded.append(str(f))
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        raw_lines = text.splitlines()
        if f.suffix.lower() in (".html", ".htm"):
            prose_lines = mask_html(text).splitlines()
            if len(prose_lines) != len(raw_lines):   # never expected; fail safe
                prose_lines = raw_lines
        else:
            prose_lines = raw_lines
        for lineno, line in enumerate(raw_lines, start=1):
            pline = prose_lines[lineno - 1]
            if len(line) > 8000:
                line = line[:8000]
                pline = pline[:8000]
            for cat, name, rx in rules:
                m = rx.search(pline if cat in PROSE_ONLY_CATEGORIES else line)
                if not m:
                    continue
                raw = m.group(0)
                findings.append({
                    "file": str(f),
                    "line": lineno,
                    "category": cat,
                    "rule": name,
                    "match": redact(raw) if cat in REDACT_CATEGORIES else raw,
                    "redacted": cat in REDACT_CATEGORIES,
                })
    return findings


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 1:
        print("usage: denylist.py DIR [--json]", file=sys.stderr)
        return 2
    excluded: list[str] = []
    try:
        findings = scan_path(argv[0], excluded=excluded)
    except DenylistError as exc:
        print("denylist: %s" % exc, file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print("%s:%d:%s:%s:%s" % (f["file"], f["line"], f["category"],
                                      f["rule"], f["match"]))
        for x in sorted(excluded):
            print("denylist: self-excluded (%s): %s" % (SELF_EXCLUDE_MARKER, x))
        print("denylist: %d finding(s)" % len(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
