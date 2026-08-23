#!/usr/bin/env python3
# PUBLISH-GATE-SELF-EXCLUDE
"""publish_gate.py -- the publish gate.

Six checks, in order:
  a) gitleaks        secret scan (directory scan in cleanroom mode, full git
                     history in prepush/ci mode when a .git tree exists)
  b) identity-guard  operator/host identity scan (external tool, optional)
  c) denylist        committable regex denylist (denylist.py, vendored)
  d) third-party     no absolute off-origin http(s) request in html/css/js/md
  e) filetypes       filename / extension / size / binary denylist
  f) evidence        audit/<project>/evidence.md with at least one 'verified'

Exit 0 only when every non-skipped check passes.

A MISSING gitleaks BINARY IS A FAIL, in every mode (cleanroom/prepush/ci): a
secret scan that did not run is a secret scan that failed.  identity-guard is
the ONE optional check -- when it is absent (CI, by design) it reports WARN,
loudly, and does not fail the run.

Same-origin hosts are discovered automatically from a `.publish-origin` file at
the repo root (one hostname per line, '#' comments allowed); --origin still
works and is added to whatever that file lists.  Extra hosts go in the repo's
`tools/external-allowlist.txt`.

The gate carries NO absolute host path.  Helper locations come from PATH, from
the env vars PUBLISH_GATE_GITLEAKS / PUBLISH_GATE_IDENTITY_GUARD, or from a
short list of HOME-RELATIVE paths resolved at runtime (see
IDENTITY_GUARD_RELPATHS) -- so the file stays safe to vendor into a public repo
as tools/publish_gate.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    import denylist as denylist_mod
except ImportError:  # pragma: no cover
    denylist_mod = None

PASS, FAIL, SKIP, WARN = "PASS", "FAIL", "SKIP", "WARN"

DEFAULT_EXTERNAL_ALLOWLIST = ["github.com", "api.github.com"]
DEFAULT_ALLOWED_BINARIES = ["png", "svg", "jpg", "jpeg", "webp", "ico", "woff2"]

# Where identity_guard.py is looked for when PUBLISH_GATE_IDENTITY_GUARD is
# unset and it is not on PATH.  RELATIVE to the invoking user's home directory,
# resolved at runtime -- this file must never carry an absolute host path.
IDENTITY_GUARD_RELPATHS = [
    "Apps/Finance/Manage/office-toolkit/identity-guard/identity_guard.py",
    "office-toolkit/identity-guard/identity_guard.py",
    ".local/share/office-toolkit/identity-guard/identity_guard.py",
]

ORIGIN_FILE = ".publish-origin"

# A file carrying this marker in its first 4096 characters declares itself a
# gate rule file or a stripping tool: it necessarily contains the very strings
# it hunts for.  denylist.py applies this rule to its own scan; the gate applies
# it to identity_guard.py's output too, because that tool has no notion of it.
SELF_EXCLUDE_MARKER = "PUBLISH-GATE-SELF-EXCLUDE"

MAX_FILE_BYTES = 5 * 1024 * 1024
AMBIGUOUS_ROM_MIN_BYTES = 100 * 1024

HARD_ROM_EXTS = {".sfc", ".smc", ".nes", ".gb", ".gbc", ".gba", ".n64", ".z64"}
AMBIGUOUS_ROM_EXTS = {".md", ".zip"}          # only when >100KB *and* binary

WEB_EXTS = {".html", ".htm", ".css", ".js", ".mjs", ".md"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}

DENY_DIR_NAMES = {".claude", "firefox-config"}
DENY_BASENAMES = {".mcp.json", "tailscaled.state"}

CONTEXT_PATTERNS = [
    ("src",      r"""(?:src|srcset|data-src|poster)\s*=\s*["']?\s*(https?://[^"'\s>)]+)"""),
    ("href",     r"""href\s*=\s*["']?\s*(https?://[^"'\s>)]+)"""),
    ("css-url",  r"""url\(\s*["']?\s*(https?://[^"')\s]+)"""),
    ("fetch",    r"""(?:fetch|importScripts|\.open)\s*\(\s*(?:["'`][A-Z]+["'`]\s*,\s*)?["'`]\s*(https?://[^"'`\s),]+)"""),
    ("import",   r"""(?:@import|\bimport)\s+(?:url\()?["'(]?\s*(https?://[^"'`\s);]+)"""),
    ("md-image", r"""!\[[^\]]*\]\(\s*(https?://[^)\s]+)"""),
]
COMPILED_CONTEXTS = [(n, re.compile(p, re.IGNORECASE)) for n, p in CONTEXT_PATTERNS]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def find_tool(env_var: str, *candidates: str) -> str | None:
    val = os.environ.get(env_var)
    if val and Path(val).exists():
        return val
    for cand in candidates:
        found = shutil.which(cand)
        if found:
            return found
        local = HERE / cand
        if local.exists():
            return str(local)
    return None


def find_identity_guard() -> str | None:
    """PUBLISH_GATE_IDENTITY_GUARD -> PATH -> a few home-relative locations."""
    exe = find_tool("PUBLISH_GATE_IDENTITY_GUARD", "identity_guard.py")
    if exe:
        return exe
    try:
        home = Path.home()
    except Exception:
        return None
    for relpath in IDENTITY_GUARD_RELPATHS:
        cand = home / relpath
        if cand.is_file():
            return str(cand)
    return None


def finding_self_excluded(repo: Path, item: dict) -> bool:
    """True when the file an external scanner flagged opts out via the marker."""
    raw = str(item.get("file", item.get("path", "")) or "")
    if not raw:
        return False
    p = Path(raw)
    if not p.is_absolute():
        p = repo / raw
    try:
        return SELF_EXCLUDE_MARKER in p.read_text(encoding="utf-8",
                                                  errors="replace")[:4096]
    except OSError:
        return False


def read_origins(repo: Path, cli_origin: str | None) -> list[str]:
    """Hosts treated as same-origin: --origin plus a committed .publish-origin."""
    raw: list[str] = []
    if cli_origin:
        raw.append(cli_origin)
    for cand in (repo / ORIGIN_FILE, repo / "tools" / ORIGIN_FILE):
        if cand.is_file():
            try:
                raw.extend(cand.read_text(encoding="utf-8").splitlines())
            except OSError:
                pass
            break
    hosts = []
    for line in raw:
        h = line.split("#", 1)[0].strip().lower()
        if not h:
            continue
        if "//" in h:
            h = urlparse(h).hostname or ""
        h = h.strip("/").split("/", 1)[0]
        if h:
            hosts.append(h)
    return sorted(set(hosts))


def read_list_file(repo: Path, name: str, default: list[str]) -> list[str]:
    for cand in (repo / "tools" / name, repo / name, HERE / name):
        if cand.is_file():
            out = []
            for line in cand.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line.lower())
            return out
    return [d.lower() for d in default]


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            yield Path(dirpath) / fn


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def looks_binary(p: Path) -> bool:
    try:
        with p.open("rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return False
    if b"\x00" in chunk:
        return True
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def result(cid, name, status, count=0, details=None):
    return {"id": cid, "name": name, "status": status,
            "count": count, "details": details or []}


# --------------------------------------------------------------------------- #
# (a) gitleaks
# --------------------------------------------------------------------------- #
def check_gitleaks(repo: Path, mode: str) -> dict:
    exe = find_tool("PUBLISH_GATE_GITLEAKS", "gitleaks")
    if not exe:
        # A skipped secret scan is a FAILED secret scan -- in every mode.
        # There is no configuration in which this gate passes unscanned.
        return result("gitleaks", "gitleaks secret scan", FAIL, 1,
                      ["gitleaks not found on PATH or PUBLISH_GATE_GITLEAKS",
                       "FATAL: the secret scan did not run, so it did not pass. "
                       "Install gitleaks or set PUBLISH_GATE_GITLEAKS=/path/to/gitleaks."])
    use_git = mode in ("prepush", "ci") and (repo / ".git").exists()
    sub = "git" if use_git else "dir"
    tmp = Path(tempfile.mkdtemp(prefix="pgate-")) / "gitleaks.json"
    cmd = [exe, sub, "--no-banner", "--redact", "--exit-code", "1",
           "--report-format", "json", "--report-path", str(tmp), str(repo)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except Exception as exc:
        return result("gitleaks", "gitleaks secret scan", FAIL,
                      details=["gitleaks failed to run: %s" % exc])
    findings = []
    if tmp.exists():
        try:
            findings = json.loads(tmp.read_text(encoding="utf-8") or "[]")
        except Exception:
            findings = []
        tmp.unlink(missing_ok=True)
    details = []
    for f in findings[:40]:
        details.append("%s:%s [%s] secret=REDACTED" % (
            rel(repo, Path(str(f.get("File", "?")))), f.get("StartLine", "?"),
            f.get("RuleID", "?")))
    if proc.returncode not in (0, 1):
        details.append("gitleaks exit=%d stderr=%s" % (
            proc.returncode, (proc.stderr or "").strip().splitlines()[-1:]))
        return result("gitleaks", "gitleaks (%s scan)" % sub, FAIL,
                      len(findings) or 1, details)
    status = FAIL if findings else PASS
    return result("gitleaks", "gitleaks (%s scan)" % sub, status, len(findings), details)


# --------------------------------------------------------------------------- #
# (b) identity-guard
# --------------------------------------------------------------------------- #
def check_identity_guard(repo: Path) -> dict:
    exe = find_identity_guard()
    if not exe:
        return result("identity-guard", "identity-guard scan", WARN, 0,
                      ["identity_guard.py not available: no host-specific "
                       "identity check ran (expected in CI; the generic "
                       "denylist still ran)",
                       "set PUBLISH_GATE_IDENTITY_GUARD=/path/to/identity_guard.py "
                       "to run it"])
    cmd = [sys.executable, exe, "--path", str(repo), "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as exc:
        return result("identity-guard", "identity-guard scan", WARN, 0,
                      ["could not run: %s" % exc])
    if proc.returncode == 2:
        return result("identity-guard", "identity-guard scan", WARN, 0,
                      ["tool error (config/overlay absent): %s"
                       % (proc.stderr or "").strip()[:200]])
    n = 0
    details = []
    parsed = False
    excluded_n = 0
    try:
        data = json.loads(proc.stdout or "{}")
        items = data.get("findings", data) if isinstance(data, dict) else data
        if isinstance(items, list):
            parsed = True
            keep = []
            for it in items:
                if isinstance(it, dict) and finding_self_excluded(repo, it):
                    excluded_n += 1
                    continue
                keep.append(it)
            n = len(keep)
            for it in keep[:40]:
                if isinstance(it, dict):
                    details.append("%s:%s [%s] REDACTED" % (
                        rel(repo, Path(str(it.get("file", it.get("path", "?"))))),
                        it.get("line", "?"),
                        it.get("kind", it.get("rule", it.get("category", "?")))))
    except Exception:
        n = 0 if proc.returncode == 0 else 1
        if proc.returncode == 1:
            details.append("identity-guard reported findings (output redacted)")
    if excluded_n:
        details.append("%d finding(s) dropped: the flagged file carries %s "
                       "(a rule file contains the patterns it hunts for)"
                       % (excluded_n, SELF_EXCLUDE_MARKER))
    if proc.returncode == 1 and not parsed:
        n = max(n, 1)
    return result("identity-guard", "identity-guard scan",
                  FAIL if n else PASS, n, details)


# --------------------------------------------------------------------------- #
# (c) denylist
# --------------------------------------------------------------------------- #
def check_denylist(repo: Path) -> dict:
    if denylist_mod is None:
        return result("denylist", "denylist regex scan", FAIL,
                      details=["denylist.py not importable next to publish_gate.py"])
    excluded: list[str] = []
    try:
        findings = denylist_mod.scan_path(repo, excluded=excluded)
    except denylist_mod.DenylistError as exc:
        return result("denylist", "denylist regex scan", FAIL, 1, [str(exc)])
    except TypeError:  # older vendored denylist.py without `excluded`
        findings = denylist_mod.scan_path(repo)
    details = ["%s:%d:%s:%s:%s" % (rel(repo, Path(f["file"])), f["line"],
                                   f["category"], f["rule"], f["match"])
               for f in findings[:60]]
    # Self-exclusions are never silent: every skipped file is named.
    for x in sorted(excluded)[:20]:
        details.append("self-excluded (PUBLISH-GATE-SELF-EXCLUDE): %s"
                       % rel(repo, Path(x)))
    return result("denylist", "denylist regex scan",
                  FAIL if findings else PASS, len(findings), details)


# --------------------------------------------------------------------------- #
# (d) zero third-party requests
# --------------------------------------------------------------------------- #
def host_allowed(host: str, allowed: list[str], origins: list[str]) -> bool:
    host = host.lower()
    for o in origins:
        if host == o or (o.startswith(".") and host.endswith(o)):
            return True
    for a in allowed:
        if host == a or (a.startswith(".") and host.endswith(a)):
            return True
    return False


def check_third_party(repo: Path, origins: list[str]) -> dict:
    allowed = read_list_file(repo, "external-allowlist.txt",
                             DEFAULT_EXTERNAL_ALLOWLIST)
    hits = []
    for f in iter_files(repo):
        if f.suffix.lower() not in WEB_EXTS:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for ctx, rx in COMPILED_CONTEXTS:
                for m in rx.finditer(line):
                    url = m.group(1).rstrip(".,;'\"")
                    host = (urlparse(url).hostname or "").lower()
                    if not host or host_allowed(host, allowed, origins):
                        continue
                    hits.append("%s:%d [%s] %s" % (rel(repo, f), lineno, ctx, host))
    uniq = sorted(set(hits))
    notes = []
    if origins:
        notes.append("same-origin (%s / --origin): %s" % (ORIGIN_FILE, ", ".join(origins)))
    if allowed:
        notes.append("allowlisted hosts: %s" % ", ".join(allowed))
    return result("third-party", "zero third-party requests",
                  FAIL if uniq else PASS, len(uniq), uniq[:60] + notes)


# --------------------------------------------------------------------------- #
# (f) internal links resolve
# --------------------------------------------------------------------------- #
HTML_EXTS = {".html", ".htm"}
INTERNAL_HREF = re.compile(r'(?:href|src)="(/[^"]*)"')


def link_target(href: str) -> str | None:
    """The file an absolute internal reference must resolve to."""
    path = href.split("#", 1)[0].split("?", 1)[0]
    if not path.startswith("/"):
        return None
    if path in ("", "/"):
        return "index.html"
    if path.endswith("/"):
        return path.lstrip("/") + "index.html"
    if "." in path.rsplit("/", 1)[-1]:
        return path.lstrip("/")
    return path.lstrip("/") + "/index.html"


def check_links(repo: Path) -> dict:
    """A dead link is the amateur tell the site constitution names by that word.

    Every absolute internal reference in the built output must resolve to a file
    that was actually built.  Relative and external references are out of scope:
    the third-party check owns external hosts, and a static site of this shape
    emits absolute paths only.
    """
    pages = [f for f in iter_files(repo) if f.suffix.lower() in HTML_EXTS]
    if not pages:
        return result("links", "internal links resolve", SKIP, 0,
                      ["no HTML in the scanned tree"])
    hits, checked = [], 0
    for f in pages:
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in INTERNAL_HREF.finditer(line):
                href = m.group(1)
                target = link_target(href)
                if target is None:
                    continue
                checked += 1
                if not (repo / target).is_file():
                    hits.append("%s:%d -> %s (no file at %s)"
                                % (rel(repo, f), lineno, href, target))
    uniq = sorted(set(hits))
    notes = ["%d internal reference(s) checked across %d page(s)"
             % (checked, len(pages))]
    return result("links", "internal links resolve",
                  FAIL if uniq else PASS, len(uniq), uniq[:60] + notes)


# --------------------------------------------------------------------------- #
# (e) filename / type denylist
# --------------------------------------------------------------------------- #
def check_filetypes(repo: Path) -> dict:
    allowed_bin = set(read_list_file(repo, "allowed-binaries.txt",
                                     DEFAULT_ALLOWED_BINARIES))
    hits = []
    for dirpath, dirnames, filenames in os.walk(repo):
        for d in list(dirnames):
            if d in DENY_DIR_NAMES:
                hits.append("%s/ [denied directory]" % rel(repo, Path(dirpath) / d))
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and d not in DENY_DIR_NAMES)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            r = rel(repo, p)
            low = fn.lower()
            ext = p.suffix.lower()
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if low.startswith(".env"):
                hits.append("%s [dotenv file]" % r); continue
            if low in DENY_BASENAMES:
                hits.append("%s [denied filename]" % r); continue
            if low.endswith(".state"):
                hits.append("%s [state file]" % r); continue
            if low.endswith(".local.json"):
                hits.append("%s [local config]" % r); continue
            if ".bak" in low:
                hits.append("%s [backup file]" % r); continue
            if ext in HARD_ROM_EXTS:
                hits.append("%s [ROM extension]" % r); continue
            if (ext in AMBIGUOUS_ROM_EXTS and size > AMBIGUOUS_ROM_MIN_BYTES
                    and looks_binary(p)):
                hits.append("%s [binary payload with %s extension, %dB]"
                            % (r, ext, size)); continue
            if size > MAX_FILE_BYTES:
                hits.append("%s [%dB > 5MB limit]" % (r, size)); continue
            if looks_binary(p) and ext.lstrip(".") not in allowed_bin:
                hits.append("%s [binary type '%s' not in allowed-binaries.txt]"
                            % (r, ext.lstrip(".") or "none"))
    uniq = sorted(set(hits))
    return result("filetypes", "filename / type denylist",
                  FAIL if uniq else PASS, len(uniq), uniq[:60])


# --------------------------------------------------------------------------- #
# (f) evidence
# --------------------------------------------------------------------------- #
def check_evidence(repo: Path, evidence: str | None) -> dict:
    candidates: list[Path] = []
    if evidence:
        candidates.append(Path(evidence))
    else:
        candidates.extend(sorted((repo / "audit").glob("*/evidence.md")))
        p = repo / "audit" / "evidence.md"
        if p.is_file():
            candidates.append(p)
    found = [c for c in candidates if c.is_file()]
    if not found:
        return result("evidence", "evidence of verification", FAIL, 1,
                      ["no audit/<project>/evidence.md and no --evidence PATH"])
    ok, details = [], []
    for c in found:
        try:
            lines = c.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            details.append("%s: unreadable (%s)" % (rel(repo, c), exc)); continue
        n = sum(1 for ln in lines if "verified" in ln.lower())
        if n:
            ok.append(c); details.append("%s: %d verified line(s)" % (rel(repo, c), n))
        else:
            details.append("%s: no line marked 'verified'" % rel(repo, c))
    return result("evidence", "evidence of verification",
                  PASS if ok else FAIL, 0 if ok else 1, details)


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def run_gate(repo: Path, mode: str, evidence: str | None,
             no_evidence: bool, origins: list[str]) -> list[dict]:
    checks = [
        check_gitleaks(repo, mode),
        check_identity_guard(repo),
        check_denylist(repo),
        check_third_party(repo, origins),
        check_filetypes(repo),
        check_links(repo),
    ]
    if no_evidence:
        checks.append(result("evidence", "evidence of verification", SKIP,
                             details=["skipped via --no-evidence"]))
    else:
        checks.append(check_evidence(repo, evidence))
    return checks


def print_summary(repo: Path, mode: str, checks: list[dict]) -> None:
    mark = {PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP", WARN: "WARN"}
    print("=" * 72)
    print("PUBLISH GATE  mode=%s  repo=%s" % (mode, repo))
    print("=" * 72)
    for c in checks:
        print("  %-4s  %-34s %s" % (mark[c["status"]], c["name"],
                                    ("%d finding(s)" % c["count"]) if c["count"] else ""))
        for d in c["details"]:
            print("          - %s" % d)
    n_fail = sum(1 for c in checks if c["status"] == FAIL)
    n_skip = sum(1 for c in checks if c["status"] == SKIP)
    n_warn = sum(1 for c in checks if c["status"] == WARN)
    for c in checks:
        if c["status"] != WARN:
            continue
        print("!" * 72)
        print("!! WARNING: %s DID NOT RUN. The run is not blocked, but this" % c["name"])
        print("!! check produced NO evidence. Do not read the result as coverage.")
        for d in c["details"]:
            print("!!   %s" % d)
        print("!" * 72)
    print("-" * 72)
    print("RESULT: %s   (%d pass / %d fail / %d warn / %d skip)" % (
        "FAIL" if n_fail else "PASS",
        sum(1 for c in checks if c["status"] == PASS), n_fail, n_warn, n_skip))
    print("=" * 72)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="publish_gate.py",
                                 description="publish gate: seven checks, exit 0 only if all pass")
    ap.add_argument("--mode", choices=["cleanroom", "prepush", "ci"], required=True)
    ap.add_argument("--repo", default=".", help="directory to gate")
    ap.add_argument("--evidence", default=None, help="explicit evidence.md path")
    ap.add_argument("--no-evidence", action="store_true",
                    help="skip the evidence check (batch audits)")
    ap.add_argument("--origin", default=None,
                    help="the site's own host, treated as same-origin; added to "
                         "whatever the repo's .publish-origin file lists")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print("publish_gate: not a directory: %s" % repo, file=sys.stderr)
        return 2

    origins = read_origins(repo, args.origin)
    checks = run_gate(repo, args.mode, args.evidence, args.no_evidence, origins)
    failed = [c for c in checks if c["status"] == FAIL]
    if args.json:
        print(json.dumps({"mode": args.mode, "repo": str(repo),
                          "result": "FAIL" if failed else "PASS",
                          "checks": checks}, indent=2))
    else:
        print_summary(repo, args.mode, checks)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
