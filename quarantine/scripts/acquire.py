#!/usr/bin/env python3
"""
acquire.py — safely bring an untrusted artifact into a quarantine directory.

This is the ONLY part of the quarantine skill that touches the network, and it
does so through hardened, non-executing subprocess calls (git / curl). It never
runs the artifact's code, never recurses submodules, never follows symlinks out
of the quarantine tree, and strips execute bits from everything it writes.

Supported inputs:
  * local path          ./thing  /abs/path/thing   (file OR directory)
  * git repo            https://github.com/u/r  https://gitlab.com/g/sg/proj
                        git@host:u/r.git  ssh://...  (any github/gitlab/bitbucket/
                        codeberg/sr.ht repo, incl. nested GitLab groups)
  * hosted single file  github /blob//raw/, gitlab /-/blob//-/raw/, *.githubusercontent.com
  * generic https URL   https://host/file[.zip|.tar.gz|...]  and release/source
                        archives (github /releases//archive/, gitlab /-/archive/,
                        codeload) -> downloaded; archives safely extracted

Output: a JSON manifest is printed to stdout. The human/agent never needs to
parse anything else. Diagnostics go to stderr.

Stdlib only (no third-party deps) — keeps the trusted computing base tiny.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

# ---- limits (defensive caps so a hostile artifact can't exhaust the machine) ----
DEFAULT_OUT_ROOT = Path.home() / ".quarantine"
MAX_TOTAL_BYTES = 750 * 1024 * 1024          # total bytes written to content/
MAX_FILES = 60_000                           # total files written to content/
MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024       # single download cap
MAX_SINGLE_FILE_BYTES = 150 * 1024 * 1024    # per-file cap when copying/extracting
GIT_CLONE_TIMEOUT_S = 180
DOWNLOAD_TIMEOUT_S = 180

GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


def log(msg: str) -> None:
    print(f"[acquire] {msg}", file=sys.stderr)


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(json.dumps({"ok": False, "error": msg}), flush=True)
    log(f"ERROR: {msg}")
    sys.exit(1)


def slugify(text: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-").lower()
    return (base or "artifact")[:60]


# --------------------------------------------------------------------------- #
# input classification
# --------------------------------------------------------------------------- #
def classify(source: str) -> str:
    """Return one of: local | git | github-blob | download.

    Intent buckets: clone a repo (`git`), fetch a single hosted file
    (`github-blob`), or download an arbitrary file/archive (`download`). Works for
    any github.com / *.githubusercontent.com URL and any other https file URL.
    """
    if source.startswith(("git@", "ssh://")) or source.endswith(".git"):
        return "git"
    if source.startswith(("http://", "https://")):
        u = urlparse(source)
        host = (u.hostname or "").lower()
        path = u.path or ""
        # raw.githubusercontent.com / *.githubusercontent.com -> a single raw file
        if host.endswith("githubusercontent.com"):
            return "github-blob"
        # codeload.github.com serves tarball/zipball archives -> download + extract
        if host == "codeload.github.com":
            return "download"
        githubish = host == "github.com" or host.endswith(".github.com")
        if host in GIT_HOSTS or githubish:
            # single-file views (GitHub /blob//raw/, GitLab /-/blob//-/raw/)
            if "/blob/" in path or "/raw/" in path or host.startswith("raw."):
                return "github-blob"
            # downloadable assets / source archives -> fetch the file, don't clone
            # (GitHub /releases/download//archive/, GitLab /-/archive/)
            if "/releases/download/" in path or "/releases/latest" in path or "/archive/" in path:
                return "download"
            # explicit subtree view (GitHub /tree/, GitLab /-/tree/) -> clone the repo
            if "/tree/" in path:
                return "git"
            parts = [p for p in path.split("/") if p]
            if githubish:
                # GitHub: exactly <owner>/<repo> is a repo; deeper paths are UI pages
                return "git" if len(parts) == 2 else "download"
            # GitLab/Bitbucket/Codeberg/sr.ht: nested groups mean a repo root can be
            # 2+ segments (e.g. group/subgroup/project) -> clone it.
            return "git" if len(parts) >= 2 else "download"
        return "download"
    # otherwise: a local filesystem path
    return "local"


def repo_root_url(source: str) -> str:
    """Reduce a web URL to the cloneable repo root.

    Cuts GitLab's `/-/…` and GitHub's `/tree|/blob|/raw/…` suffixes, keeping the
    FULL preceding path so nested GitLab groups (group/subgroup/project) survive.
    """
    u = urlparse(source)
    path = u.path or ""
    for marker in ("/-/", "/tree/", "/blob/", "/raw/", "/pull/", "/issues/"):
        idx = path.find(marker)
        if idx != -1:
            path = path[:idx]
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2:
        return f"{u.scheme}://{u.hostname}/{path}.git"
    return source


def blob_to_raw(source: str) -> tuple[str, str]:
    """github .../blob/<ref>/<path> -> raw URL + suggested filename."""
    u = urlparse(source)
    parts = [p for p in (u.path or "").split("/") if p]
    fname = parts[-1] if parts else "file"
    if u.hostname and u.hostname.startswith("raw."):
        return source, fname
    if "/blob/" in u.path:
        # owner/repo/blob/ref/...path... -> raw.githubusercontent.com/owner/repo/ref/...path...
        idx = parts.index("blob")
        owner, repo = parts[0], parts[1]
        rest = "/".join(parts[idx + 1:])
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{rest}", fname
    if "/raw/" in u.path:
        return source, fname
    return source, fname


# --------------------------------------------------------------------------- #
# safe acquisition primitives
# --------------------------------------------------------------------------- #
def hardened_git_env() -> dict[str, str]:
    env = dict(os.environ)
    # Ignore user/system git config so an attacker-independent surface holds, and
    # so our -c flags below are fully authoritative (no insteadOf / hooksPath surprises).
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"   # never block on credential prompts
    env["GIT_LFS_SKIP_SMUDGE"] = "1"   # do not fetch LFS payloads
    env["GIT_ASKPASS"] = "true"
    return env


def clone_git(source: str, dest: Path) -> dict:
    url = repo_root_url(source) if source.startswith(("http://", "https://")) else source
    # Hardened clone: shallow, single branch, no tags, NO submodule recursion,
    # symlinks materialized as inert text (core.symlinks=false), hooks disabled,
    # dangerous transport protocols forbidden. git >= 2.45.1 also patches the
    # known clone-time RCEs (CVE-2024-32002 et al.).
    cmd = [
        "git",
        "-c", "core.symlinks=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.fd.allow=never",
        "-c", "submodule.recurse=false",
        "-c", "advice.detachedHead=false",
        "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--no-recurse-submodules", "--quiet", "--", url, str(dest),
    ]
    log(f"git clone (hardened, depth 1, no submodules): {url}")
    try:
        proc = subprocess.run(
            cmd, env=hardened_git_env(), capture_output=True, text=True,
            timeout=GIT_CLONE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        die(f"git clone timed out after {GIT_CLONE_TIMEOUT_S}s")
    if proc.returncode != 0:
        die(f"git clone failed: {proc.stderr.strip() or proc.stdout.strip()}")

    info: dict = {"clone_url": url}
    try:
        rev = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            env=hardened_git_env(), capture_output=True, text=True, timeout=20,
        )
        if rev.returncode == 0:
            info["commit"] = rev.stdout.strip()
    except Exception:
        pass
    # Remove the .git directory entirely: we have the worktree to analyze, and a
    # lingering .git (config, hooks, packed refs) is pure attack surface we don't need.
    gitdir = dest / ".git"
    if gitdir.exists():
        shutil.rmtree(gitdir, ignore_errors=True)
    return info


def curl_download(url: str, out_file: Path) -> None:
    # https only (including across redirects), bounded redirects/time/size, fail on
    # HTTP errors, ignore curl config files (-q). Output goes to a file — NEVER a pipe.
    cmd = [
        "curl", "-q", "--proto", "=https", "--proto-redir", "=https",
        "--location", "--max-redirs", "5", "--max-time", str(DOWNLOAD_TIMEOUT_S),
        "--max-filesize", str(MAX_DOWNLOAD_BYTES), "--fail", "--silent",
        "--show-error", "--no-progress-meter", "--output", str(out_file),
        "--url", url,
    ]
    log(f"download (https-only, bounded): {url}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT_S + 10)
    except subprocess.TimeoutExpired:
        die(f"download timed out after {DOWNLOAD_TIMEOUT_S}s")
    if proc.returncode != 0:
        die(f"download failed: {proc.stderr.strip() or f'curl exit {proc.returncode}'}")
    if not out_file.exists():
        die("download produced no file")
    if out_file.stat().st_size > MAX_DOWNLOAD_BYTES:
        out_file.unlink(missing_ok=True)
        die(f"download exceeded {MAX_DOWNLOAD_BYTES} bytes")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def safe_extract_zip(archive: Path, dest: Path, notes: list[str]) -> None:
    skipped_symlinks: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        if len(zf.infolist()) > MAX_FILES:
            die(f"archive has too many entries (> {MAX_FILES})")
        for zi in zf.infolist():
            name = zi.filename
            if name.startswith("/") or ".." in Path(name).parts:
                notes.append(f"skipped unsafe zip path: {name}")
                continue
            target = dest / name
            if not is_within(target, dest):
                notes.append(f"skipped zip path escaping dest: {name}")
                continue
            mode = zi.external_attr >> 16
            if stat.S_ISLNK(mode):
                skipped_symlinks.append(name)
                continue  # never materialize symlinks from an archive
            if zi.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if zi.file_size > MAX_SINGLE_FILE_BYTES:
                notes.append(f"skipped oversize zip entry: {name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(zi) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1 << 20)
    if skipped_symlinks:
        notes.append(f"skipped {len(skipped_symlinks)} symlink entr(y/ies) in archive")


def safe_extract_tar(archive: Path, dest: Path, notes: list[str]) -> None:
    # PEP 706 'data' filter (Python 3.12+): rejects absolute paths, traversal,
    # symlinks/hardlinks pointing outside, device/special files. Fail-closed.
    with tarfile.open(archive) as tf:
        try:
            tf.extractall(path=dest, filter="data")  # type: ignore[arg-type]
        except TypeError:
            die("this Python is too old for safe tar extraction (need 3.12+ data filter)")
        except Exception as e:
            die(f"tar extraction blocked by safety filter: {e}")
    notes.append("tar extracted with PEP 706 'data' safety filter")


def looks_like_archive(path: Path) -> str | None:
    low = path.name.lower()
    for suf in ARCHIVE_SUFFIXES:
        if low.endswith(suf):
            return "zip" if suf == ".zip" else "tar"
    # magic-byte sniff as a fallback
    try:
        head = path.read_bytes()[:6]
    except OSError:
        return None
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if head[:2] in (b"\x1f\x8b",) or head[:6] == b"\xfd7zXZ\x00":
        return "tar"
    return None


def copy_local(source: Path, dest: Path, notes: list[str]) -> None:
    """Copy a local file/dir into quarantine WITHOUT following symlinks out."""
    if source.is_file():
        if source.stat().st_size > MAX_SINGLE_FILE_BYTES:
            die("local file exceeds size cap")
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest / source.name, follow_symlinks=False)
        return
    # directory: walk without following symlinks; record (but never recreate) links
    symlinks: list[str] = []
    written = 0
    for root, dirs, files in os.walk(source, followlinks=False):
        rel_root = Path(root).relative_to(source)
        # do not descend into a .git directory of a local repo (pure attack surface)
        dirs[:] = [d for d in dirs if d != ".git"]
        (dest / rel_root).mkdir(parents=True, exist_ok=True)
        for fn in files:
            spath = Path(root) / fn
            rel = rel_root / fn
            if spath.is_symlink():
                try:
                    symlinks.append(f"{rel} -> {os.readlink(spath)}")
                except OSError:
                    symlinks.append(f"{rel} -> <unreadable>")
                continue  # never recreate symlinks
            try:
                if spath.stat().st_size > MAX_SINGLE_FILE_BYTES:
                    notes.append(f"skipped oversize file: {rel}")
                    continue
                shutil.copyfile(spath, dest / rel, follow_symlinks=False)
                written += 1
                if written > MAX_FILES:
                    die(f"too many files (> {MAX_FILES})")
            except OSError as e:
                notes.append(f"skipped unreadable file {rel}: {e}")
    if symlinks:
        notes.append(f"recorded (NOT copied) {len(symlinks)} symlink(s): " + "; ".join(symlinks[:20]))


# --------------------------------------------------------------------------- #
# post-processing: neutralize execution + measure
# --------------------------------------------------------------------------- #
def strip_exec_and_measure(content: Path) -> tuple[int, int]:
    """Remove execute bits from regular files (defense in depth) and tally size."""
    total_bytes = 0
    file_count = 0
    for root, dirs, files in os.walk(content, followlinks=False):
        for fn in files:
            p = Path(root) / fn
            try:
                if p.is_symlink():
                    continue
                st = p.stat()
                total_bytes += st.st_size
                file_count += 1
                p.chmod(st.st_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                if total_bytes > MAX_TOTAL_BYTES:
                    die(f"content exceeds total size cap ({MAX_TOTAL_BYTES} bytes)")
            except OSError:
                continue
    return file_count, total_bytes


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Safely acquire an untrusted artifact into quarantine.")
    ap.add_argument("source", help="local path, git URL, or https URL")
    ap.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    args = ap.parse_args()

    source = args.source
    kind = classify(source)

    if kind == "local":
        src_path = Path(source).expanduser()
        if not src_path.exists():
            die(f"path not found: {source}")

    out_root = Path(args.out_root).expanduser()
    out_root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name_hint = Path(urlparse(source).path or source).name or source
    qdir = out_root / f"{stamp}-{slugify(name_hint)}"
    suffix = 0
    while qdir.exists():
        suffix += 1
        qdir = out_root / f"{stamp}-{slugify(name_hint)}-{suffix}"
    content = qdir / "content"
    meta = qdir / "meta"
    content.mkdir(parents=True)
    meta.mkdir(parents=True)

    notes: list[str] = []
    extra: dict = {}

    if kind == "git":
        extra.update(clone_git(source, content))

    elif kind == "github-blob":
        raw_url, fname = blob_to_raw(source)
        tmp = meta / "download.bin"
        curl_download(raw_url, tmp)
        extra["sha256"] = sha256_of(tmp)
        shutil.move(str(tmp), str(content / slugify(fname or "file")))

    elif kind == "download":
        tmp = meta / "download.bin"
        curl_download(source, tmp)
        extra["sha256"] = sha256_of(tmp)
        arch = looks_like_archive(tmp)
        if arch == "zip":
            safe_extract_zip(tmp, content, notes)
            tmp.unlink(missing_ok=True)
        elif arch == "tar":
            safe_extract_tar(tmp, content, notes)
            tmp.unlink(missing_ok=True)
        else:
            fname = Path(urlparse(source).path).name or "download"
            shutil.move(str(tmp), str(content / slugify(fname)))

    elif kind == "local":
        copy_local(Path(source).expanduser(), content, notes)

    else:  # unreachable
        die(f"unknown input kind: {kind}")

    file_count, total_bytes = strip_exec_and_measure(content)
    if file_count == 0:
        notes.append("WARNING: no files were acquired into content/")

    manifest = {
        "ok": True,
        "source": source,
        "source_type": kind,
        "acquired_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "quarantine_dir": str(qdir),
        "content_dir": str(content),
        "meta_dir": str(meta),
        "report_dir": str(qdir / "report"),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "notes": notes,
        **extra,
    }
    (meta / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (qdir / "report").mkdir(exist_ok=True)
    print(json.dumps(manifest, indent=2), flush=True)
    log(f"acquired {file_count} files ({total_bytes} bytes) -> {content}")


if __name__ == "__main__":
    main()
