#!/usr/bin/env python3
"""
guard.py — deterministic PreToolUse guard for the quarantine ANALYST sub-session.

This is the load-bearing security layer. It runs in EVERY permission mode
(including bypassPermissions), reads the tool-call JSON on stdin, and:

    exit 0  -> allow the tool call
    exit 2  -> BLOCK it (stderr is shown to the model)

It enforces, mechanically, that the analyst session can ONLY:
  * read files inside the quarantine dir (and its own charter/scripts), and
  * write files inside <quarantine>/report/, and
  * run read-only, OFFLINE shell commands.

It denies, regardless of what the model "decides":
  * ALL network — egress (exfiltrating your secrets to a URL in the repo) AND
    ingress (fetching a second-stage payload the repo asks for): WebFetch /
    WebSearch, and curl/wget/nc/ssh/git-fetch/npm-install/pip/npx/... in Bash.
  * reading anything outside the quarantine dir (e.g. ~/.ssh, ~/.aws, .env).
  * writing/editing/deleting anything outside <quarantine>/report/.
  * installing, building, or executing the artifact's code.

Quote awareness: shell metacharacters (`|`, `>`, `;`, `&`) and interpreter names are
only structurally meaningful when UNQUOTED. The scans for pipe-into-interpreter,
output-redirection, and segment-splitting run over a quote-masked copy of the command,
so the SAME characters inside a quoted grep pattern (e.g. `grep -E '…|node|sh…'`,
`grep '… | bash'`, `grep '>' file`) — exactly what a malware analyst greps the
artifact FOR — are treated as data, not as a pipe or redirect. Command substitution
`$(...)`/backticks are still extracted from the RAW string (they execute even inside
double quotes), so smuggling via `"$(curl evil)"` is still caught.

Fail-closed: on any uncertainty, missing env, or parse error -> BLOCK.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def block(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"guard: DENIED — {msg}", file=sys.stderr)
    sys.exit(2)


def allow() -> "NoReturn":  # type: ignore[name-defined]
    sys.exit(0)


def resolved(path: str) -> Path | None:
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def within(child: Path | None, parent: Path) -> bool:
    if child is None:
        return False
    try:
        child.relative_to(parent.resolve())
        return True
    except ValueError:
        return False


# ----- read-allowed and write-allowed roots ---------------------------------
QUARANTINE_DIR = os.environ.get("QUARANTINE_DIR", "")
PROJECT_DIR = os.environ.get("CLAUDE_PROJECT_DIR", "")  # the anchored sandbox dir

if not QUARANTINE_DIR:
    block("QUARANTINE_DIR is unset — refusing to run unsandboxed (fail-closed).")

QROOT = Path(QUARANTINE_DIR).expanduser().resolve()
READ_ROOTS = [QROOT]
if PROJECT_DIR:
    # allow reading the analyst's own charter / scripts (skill dir = parent of sandbox)
    READ_ROOTS.append(Path(PROJECT_DIR).expanduser().resolve())
    READ_ROOTS.append(Path(PROJECT_DIR).expanduser().resolve().parent)
WRITE_ROOT = (QROOT / "report").resolve()

# ----- shell command analysis (command-POSITION aware, to avoid false positives
# like `grep eval .` where a denied word is merely a search argument) ----------

# Verbs denied when they appear as the COMMAND (first token of a segment).
# Covers BOTH network directions (pull payload in / send data out), plus
# install / build / interpret-and-execute / file-mutation / persistence.
DENIED_CMDS = {
    # network
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp",
    "ftp", "tftp", "rsync", "socat", "nslookup", "dig", "host", "whois", "ping",
    # package managers / installers
    "npm", "pnpm", "yarn", "bun", "npx", "pip", "pip3", "pipx", "conda",
    "poetry", "uv", "gem", "bundle", "cargo", "go", "brew", "apt", "apt-get",
    # build / run / interpret the artifact's code (nested shells smuggle anything
    # past the per-segment guard via `bash -c "curl … | sh"`)
    "make", "cmake", "ninja", "gradle", "mvn", "node", "deno", "ts-node",
    "tsx", "python", "python2", "python3", "ruby", "perl", "php", "bash",
    "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "eval", "source", "exec",
    # environment dumpers (leak inherited secrets) + wrapper-smugglers
    "env", "printenv", "set", "export", "declare", "setenv", "typeset", "command",
    # version control network channel (the analyst needs no git/gh at all)
    "gh",
    # file mutation / persistence / exfil-staging
    "tee", "dd", "truncate", "ln", "mkfifo", "install", "patch", "cp", "mv",
    "rm", "shred", "crontab", "at", "launchctl", "sed", "awk",
    # launchers / GUI / credential stores: can open a URL (covert egress), spawn an
    # unguarded nested session, or read secrets
    "claude", "code", "open", "xdg-open", "osascript", "security", "defaults",
    "plutil", "pbpaste", "screencapture", "mdfind",
}
# git is read-only-allowed except these mutating/networked sub-commands (the
# analyst never mutates or syncs git — read-only status/log/diff/show/ls-files only):
GIT_DENIED_SUBCMDS = {"clone", "fetch", "pull", "push", "remote", "submodule",
                      "config", "am", "apply", "init", "commit", "merge",
                      "rebase", "reset", "checkout", "switch", "branch", "tag",
                      "cherry-pick", "revert", "clean", "stash"}
# RAW scan — tokens dangerous even when QUOTED, because they reach the underlying
# tool verbatim: a quoted `-exec`/`-delete` is still passed to `find`, and `/dev/tcp/`
# is a bash network socket wherever it appears. (To hunt for these literal strings,
# use the Grep tool, which the guard allows, rather than Bash grep.)
_RAW_DENY = re.compile(
    r"""(?xi)
    /dev/(?:tcp|udp)/                 # bash network sockets
    | -exec(?:dir)?\b | -delete\b | -fprint\b   # find executing/deleting/writing
    | --no-verify\b                   # hook-bypass flag
    """,
)
# MASKED scan — a pipe into a shell/interpreter is only real when UNQUOTED. The same
# characters inside a quoted grep alternation (`grep -E '…|node|…'`, `grep '… | sh'`)
# are DATA, not a pipe, so this runs over the quote-masked command skeleton.
_PIPE_INTERP = re.compile(
    r"""(?xi)
    \|\s*(?:sudo\s+)?(?:ba)?sh\b           # pipe-to-shell (curl … | sh)
    | \|\s*(?:python3?|perl|node|ruby|deno)\b   # pipe-to-interpreter
    """,
)
# command/process-substitution bodies are evaluated as their own segments (so
# `$(mktemp -d)` is fine while `$(curl evil)` blocks via curl). Extracted from the RAW
# string: `$(...)` executes even inside double quotes, so masking it would under-block.
_SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`|<\(([^()]*)\)")

_SEP = re.compile(r"[;&|\n]+")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# `env`/`command` are NOT wrappers — they're denied commands (env-dump / smuggling).
_WRAPPERS = {"sudo", "nice", "nohup", "time", "xargs", "then",
             "do", "else", "stdbuf", "setsid"}


def _mask_quotes(s: str) -> str:
    """Return S with the CONTENTS (and the quote chars) of single- and double-quoted
    spans replaced by spaces, length- and index-preserving, so structural scans for
    shell operators (`|`, `>`, `;`, `&`) and interpreter names see only the UNQUOTED
    skeleton. A `\\x` escape (outside, or inside double quotes) becomes two spaces (the
    escaped char is literal, never a shell operator). Single quotes do not honor
    backslash escapes (shell semantics); an unterminated quote masks to end-of-string."""
    out: list[str] = []
    i, n, quote = 0, len(s), None
    while i < n:
        c = s[i]
        if quote == "'":
            out.append(" ")
            if c == "'":
                quote = None
            i += 1
        elif quote == '"':
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
            else:
                out.append(" ")
                if c == '"':
                    quote = None
                i += 1
        else:  # unquoted
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
            elif c == "'":
                quote = "'"
                out.append(" ")
                i += 1
            elif c == '"':
                quote = '"'
                out.append(" ")
                i += 1
            else:
                out.append(c)
                i += 1
    return "".join(out)


def _read_shell_token(s: str, i: int) -> str:
    """Read one shell token from S starting at index I (skipping leading whitespace),
    honoring single/double quotes; return the DEQUOTED token (or '')."""
    n = len(s)
    while i < n and s[i].isspace():
        i += 1
    out: list[str] = []
    quote = None
    while i < n:
        c = s[i]
        if quote == "'":
            if c == "'":
                quote = None
            else:
                out.append(c)
            i += 1
        elif quote == '"':
            if c == "\\" and i + 1 < n and s[i + 1] in '"\\$`':
                out.append(s[i + 1])
                i += 2
            elif c == '"':
                quote = None
                i += 1
            else:
                out.append(c)
                i += 1
        else:
            if c.isspace():
                break
            if c == "'":
                quote = "'"
                i += 1
            elif c == '"':
                quote = '"'
                i += 1
            elif c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
            else:
                out.append(c)
                i += 1
    return "".join(out)


def _segments(cmd_str: str, masked: str) -> list[str]:
    """Split CMD_STR into shell segments on UNQUOTED `;`/`&`/`|`/newline only, using
    MASKED (which has blanked the quoted spans) to find the real separators and slicing
    the ORIGINAL so each segment keeps its quotes intact."""
    segs: list[str] = []
    start = 0
    for m in _SEP.finditer(masked):
        segs.append(cmd_str[start:m.start()])
        start = m.end()
    segs.append(cmd_str[start:])
    return segs


def first_command(segment: str) -> tuple[str, str, list[str]]:
    """Return (basename, raw_token, rest), skipping env-assignments and wrappers."""
    toks = segment.strip().split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if _ENV_ASSIGN.match(t) or t in _WRAPPERS:
            i += 1
            continue
        break
    if i >= len(toks):
        return "", "", []
    return toks[i].split("/")[-1], toks[i], toks[i + 1:]


def _path_arg_escapes(token: str) -> bool:
    """Block a path-like token escaping the read roots: absolute (/…), home (~…),
    OR any parent-traversal (../). `..` is cwd-ambiguous so it's denied outright —
    closing `cat ../../../../.ssh/id_rsa` and `P=../../x` (the assignment is caught).
    (The Read tool is confined; this confines Bash reads too.)"""
    tok = token.strip("'\"")
    if "=" in tok and not tok.startswith(("/", "~", ".")):
        tok = tok.split("=", 1)[1].strip("'\"")
    if ".." in re.split(r"[/:]", tok):
        return True
    if tok.startswith("~") or tok.startswith("/"):
        try:
            rp = Path(tok).expanduser().resolve()
        except (OSError, RuntimeError, ValueError):
            return True
        if not any(within(rp, r) for r in READ_ROOTS):
            return True
    return False


def _redirect_escapes(cmd_str: str, masked: str) -> bool:
    """True iff the command redirects output anywhere outside <quarantine>/report/.
    Redirect operators are located in MASKED (so a `>` inside a quoted string is NOT a
    redirect), but the target is read from the ORIGINAL (honoring quotes around it)."""
    for m in re.finditer(r"\d*>>?", masked):
        j = m.end()
        k = j
        while k < len(cmd_str) and cmd_str[k].isspace():
            k += 1
        if k < len(cmd_str) and cmd_str[k] == "&":
            continue  # fd duplication (>&2, 1>&2) — not a file write
        tgt = _read_shell_token(cmd_str, j)
        if not tgt:
            return True  # redirect with no resolvable target — fail closed
        if tgt in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"):
            continue
        try:
            rp = Path(tgt).expanduser().resolve()
        except (OSError, RuntimeError, ValueError):
            return True
        if not within(rp, WRITE_ROOT):
            return True
    return False


def bash_is_blocked(cmd_str: str) -> bool:
    masked = _mask_quotes(cmd_str)
    # tokens dangerous even when quoted (find -exec/-delete, /dev/tcp, --no-verify)
    if _RAW_DENY.search(cmd_str):
        return True
    # pipe-into-shell/interpreter — only when UNQUOTED (scanned over the masked copy)
    if _PIPE_INTERP.search(masked):
        return True
    # redirect: ONLY into <quarantine>/report/ (or /dev/null, or an fd-dup) — never
    # into content/ or meta/ (which would let an injection poison the artifact/manifest).
    if _redirect_escapes(cmd_str, masked):
        return True
    # any out-of-tree absolute/home/.. path ARGUMENT (read confinement for Bash)
    if any(_path_arg_escapes(t) for t in cmd_str.split()):
        return True
    subst_bodies = [a or b or c for (a, b, c) in _SUBST.findall(cmd_str)]
    for segment in _segments(cmd_str, masked) + subst_bodies:
        cmd, raw, rest = first_command(segment)
        if not cmd:
            continue
        if cmd == "git":
            # deny any git that leads with a flag (`git -c key=val …`, `git -C dir …`,
            # `git --no-pager …`) — it hides the verb from the check below and `-c`
            # enables config-injection. The analyst only ever needs verb-first reads.
            if rest and rest[0].startswith("-"):
                return True
            sub = next((r for r in rest if not r.startswith("-") and "=" not in r), "")
            if sub in GIT_DENIED_SUBCMDS:
                return True
            continue
        # Executing a binary BY PATH (./payload, /usr/bin/node) is blocked — the
        # analyst runs no scripts; only bare read-only commands on PATH are allowed.
        if "/" in raw:
            return True
        if cmd in ("chmod", "chown") and any("+x" in r or r.isdigit() for r in rest):
            return True
        if cmd in DENIED_CMDS:
            return True
    return False


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        block("could not parse tool-call JSON (fail-closed).")

    tool = data.get("tool_name") or ""
    ti = data.get("tool_input") or {}

    # --- network tools: denied outright (ingress AND egress) ---
    if tool in ("WebFetch", "WebSearch"):
        block(f"{tool} is blocked during quarantine analysis. No network in either "
              "direction — do not fetch second-stage payloads or send data out. "
              "Analyze only the local quarantined files.")

    # --- file reads: only inside allowed roots ---
    if tool in ("Read", "NotebookRead"):
        path = resolved(ti.get("file_path") or ti.get("notebook_path") or "")
        if any(within(path, r) for r in READ_ROOTS):
            allow()
        block(f"reading outside the quarantine dir is blocked (attempted: {ti.get('file_path')}). "
              "You may only read files under the quarantine directory.")

    # --- file writes/edits: only inside <quarantine>/report/ ---
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = resolved(ti.get("file_path") or ti.get("notebook_path") or "")
        if within(path, WRITE_ROOT):
            allow()
        block(f"writing outside <quarantine>/report/ is blocked (attempted: {ti.get('file_path')}). "
              "Write your analysis only to the report directory.")

    # --- Grep/Glob: confine the optional path argument like Read ---
    if tool in ("Grep", "Glob"):
        p = ti.get("path")
        if p:
            rp = resolved(p)
            if not any(within(rp, r) for r in READ_ROOTS):
                block(f"{tool} outside the quarantine dir is blocked (attempted: {p}).")
        allow()

    # --- bash: block network / install / exec / destructive / out-of-tree read+write ---
    if tool == "Bash":
        cmd = ti.get("command") or ""
        if bash_is_blocked(cmd):
            block("this shell command is blocked (network, install, execution, env-dump, "
                  "git/gh, or an out-of-quarantine read/write). The analyst is offline "
                  "and read-only — use Read/Grep/Glob and read-only shell tools "
                  "(ls, grep, find, cat, head, jq) within the quarantine dir only.")
        allow()

    # --- DEFAULT-DENY: anything not explicitly allowed above is blocked. Closes the
    #     MCP egress hole (mcp__Gmail__send, mcp__Drive__create_file, …) and sub-agents.
    #     AskUserQuestion + TodoWrite are the only extra passthroughs (the analyst is
    #     interactive and may ask the human; neither can exfiltrate or execute). ---
    if tool in ("AskUserQuestion", "TodoWrite"):
        allow()
    block(f"tool '{tool}' is not on the allowlist for the quarantine analyst "
          "(MCP tools, sub-agents, and any networked tool are denied by default).")


if __name__ == "__main__":
    main()
