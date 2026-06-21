#!/usr/bin/env python3
"""
acquire.test.py — unit tests for scripts/acquire.py's pure logic and its safe
acquisition primitives (classification, URL rewriting, archive-type sniffing,
zip-slip/symlink-safe extraction, symlink-safe local copy, exec-bit stripping).

Network paths (git clone / curl download) are NOT exercised here — only the
offline, security-critical helpers. Run:
    python3 ~/.claude/skills/quarantine/tests/acquire.test.py
Exits non-zero on any failure. Stdlib only (no pytest).
"""

from __future__ import annotations

import io
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import acquire  # noqa: E402

passed = 0
failed = 0


def check(cond: bool, label: str) -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok    {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}")


def mktmp() -> Path:
    import tempfile
    return Path(tempfile.mkdtemp())


# ---------------- classify ----------------
print("== classify ==")
cases = {
    "https://github.com/user/repo": "git",
    "https://github.com/user/repo.git": "git",
    "git@github.com:user/repo.git": "git",
    "ssh://git@host/u/r": "git",
    "https://github.com/user/repo/tree/main/sub": "git",
    "https://github.com/user/repo/blob/main/app/index.js": "github-blob",
    "https://github.com/user/repo/raw/main/app/index.js": "github-blob",
    "https://raw.githubusercontent.com/u/r/main/x.js": "github-blob",
    "https://gist.githubusercontent.com/u/abc/raw/x.py": "github-blob",
    # release assets / source archives on github.com -> download (not clone)
    "https://github.com/user/repo/releases/download/v1.0/app.zip": "download",
    "https://github.com/user/repo/archive/refs/heads/main.zip": "download",
    "https://codeload.github.com/user/repo/tar.gz/refs/heads/main": "download",
    # other github.com pages -> download the page, don't clone
    "https://github.com/user/repo/issues/42": "download",
    # GitLab — repos (incl. nested groups), files, archives
    "https://gitlab.com/group/project": "git",
    "https://gitlab.com/group/subgroup/project": "git",
    "https://gitlab.com/group/project/-/blob/main/src/x.py": "github-blob",
    "https://gitlab.com/group/project/-/raw/main/src/x.py": "github-blob",
    "https://gitlab.com/group/project/-/tree/main/src": "git",
    "https://gitlab.com/group/project/-/archive/main/project-main.zip": "download",
    "git@gitlab.com:group/subgroup/project.git": "git",
    # Codeberg / Bitbucket repos
    "https://codeberg.org/user/repo": "git",
    "https://bitbucket.org/user/repo": "git",
    # arbitrary file URLs
    "https://example.com/archive.zip": "download",
    "https://example.com/file.tar.gz": "download",
    "https://cdn.example.org/path/to/script.js": "download",
    "./my-project": "local",
    "/abs/path/thing": "local",
}
for src, want in cases.items():
    got = acquire.classify(src)
    check(got == want, f"classify({src!r}) == {want} (got {got})")

# ---------------- repo_root_url / blob_to_raw ----------------
print("== url rewriting ==")
check(acquire.repo_root_url("https://github.com/u/r/tree/main/sub").endswith("/u/r.git"),
      "repo_root_url strips /tree/…")
check(acquire.repo_root_url("https://github.com/u/r.git").endswith("/u/r.git"),
      "repo_root_url keeps .git")
check(acquire.repo_root_url("https://gitlab.com/g/sg/proj/-/blob/main/x.py")
      == "https://gitlab.com/g/sg/proj.git",
      "repo_root_url keeps nested GitLab group path")
check(acquire.repo_root_url("https://gitlab.com/g/sg/proj/-/tree/main")
      == "https://gitlab.com/g/sg/proj.git",
      "repo_root_url nested group + /-/tree/")
raw, fname = acquire.blob_to_raw("https://github.com/u/r/blob/main/app/x.js")
check("raw.githubusercontent.com/u/r/main/app/x.js" in raw and fname == "x.js",
      f"blob_to_raw -> {raw}")

# ---------------- looks_like_archive ----------------
print("== archive sniffing ==")
t = mktmp()
zf = t / "a.zip"
with zipfile.ZipFile(zf, "w") as z:
    z.writestr("f.txt", "hi")
check(acquire.looks_like_archive(zf) == "zip", "looks_like_archive(.zip) == zip")
gz = t / "a.tar.gz"
with tarfile.open(gz, "w:gz") as tar:
    info = tarfile.TarInfo("f.txt"); data = b"hi"; info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
check(acquire.looks_like_archive(gz) == "tar", "looks_like_archive(.tar.gz) == tar")
plain = t / "notes.txt"
plain.write_text("hello")
check(acquire.looks_like_archive(plain) is None, "looks_like_archive(.txt) is None")
# extension-less zip detected by magic bytes
noext = t / "blob"
noext.write_bytes(zf.read_bytes())
check(acquire.looks_like_archive(noext) == "zip", "magic-byte zip detection")

# ---------------- safe_extract_zip: zip-slip + symlink + normal ----------------
print("== safe_extract_zip (zip-slip / symlink / absolute rejected) ==")
mal = t / "mal.zip"
with zipfile.ZipFile(mal, "w") as z:
    z.writestr("good/file.txt", "ok")
    z.writestr("../escape.txt", "evil")          # zip-slip
    z.writestr("/abs.txt", "evil")               # absolute
    # a symlink entry pointing outside
    zi = zipfile.ZipInfo("link")
    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
    z.writestr(zi, "/etc/passwd")
dest = mktmp()
notes: list[str] = []
acquire.safe_extract_zip(mal, dest, notes)
check((dest / "good" / "file.txt").read_text() == "ok", "normal entry extracted")
check(not (dest / "escape.txt").exists() and not (dest.parent / "escape.txt").exists(),
      "zip-slip entry NOT written")
check(not (dest / "link").exists() or not (dest / "link").is_symlink(),
      "symlink entry NOT materialized")
# nothing escaped the dest
for root, _dirs, files in os.walk(dest):
    for f in files:
        check(acquire.is_within(Path(root) / f, dest), f"stays within dest: {f}")

# ---------------- safe_extract_tar: traversal blocked by data filter ----------------
print("== safe_extract_tar (PEP 706 data filter blocks traversal) ==")
mtar = t / "mal.tar"
with tarfile.open(mtar, "w") as tar:
    info = tarfile.TarInfo("../evil.txt"); payload = b"x"; info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))
dest2 = mktmp()
raised = False
try:
    acquire.safe_extract_tar(mtar, dest2, [])
except SystemExit:
    raised = True
check(raised, "malicious tar triggers fail-closed (SystemExit via die)")
check(not (dest2.parent / "evil.txt").exists(), "traversal file did not escape")

# ---------------- copy_local: symlink not followed, .git skipped, exec stripped ----------------
print("== copy_local (no symlink follow, .git skipped) + strip_exec_and_measure ==")
src = mktmp()
(src / "sub").mkdir()
(src / "sub" / "code.js").write_text("console.log(1)")
exe = src / "run.sh"
exe.write_text("#!/bin/sh\necho hi")
exe.chmod(0o755)
(src / ".git").mkdir()
(src / ".git" / "config").write_text("[core]")
os.symlink("/etc/passwd", src / "evil-link")
dest3 = mktmp() / "content"
dest3.mkdir(parents=True)
notes3: list[str] = []
acquire.copy_local(src, dest3, notes3)
check((dest3 / "sub" / "code.js").exists(), "normal file copied")
check(not (dest3 / "evil-link").exists(), "symlink NOT copied")
check(any("symlink" in n for n in notes3), "symlink recorded in notes")
check(not (dest3 / ".git").exists(), ".git dir skipped")
fc, tb = acquire.strip_exec_and_measure(dest3)
check(fc >= 2 and tb > 0, f"measured files ({fc}) and bytes ({tb})")
copied_exe = dest3 / "run.sh"
if copied_exe.exists():
    mode = copied_exe.stat().st_mode
    check(not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)), "exec bits stripped")

# ---------------- slugify / is_within ----------------
print("== misc helpers ==")
check(acquire.slugify("Weird Name!/v2") == "weird-name-v2", "slugify")
base = mktmp()
check(acquire.is_within(base / "a" / "b", base), "is_within true for child")
check(not acquire.is_within(Path("/etc/passwd"), base), "is_within false for outside")

print()
print(f"RESULT: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
