# `/quarantine` skill — tests

Offline suite for the skill's three moving parts. Run all:

```bash
bash ~/.claude/skills/quarantine/tests/run-all.sh
```

Or individually:

```bash
bash   ~/.claude/skills/quarantine/tests/guards.test.sh    # sandbox PreToolUse guard
bash   ~/.claude/skills/quarantine/tests/scan.test.sh      # scripts/scan.py vs fixtures
python3 ~/.claude/skills/quarantine/tests/acquire.test.py  # scripts/acquire.py pure logic
```

Requirements: `python3` (3.12+), `jq`, `git`. No network is used.

## `guards.test.sh`

Pipes tool-call JSON to `sandbox/.claude/hooks/guard.py` and asserts exit codes
(0 allow / 2 block) with a fake `QUARANTINE_DIR`:
- network tools (`WebFetch`/`WebSearch`) blocked — ingress and egress;
- Bash network / install / exec / mutating-git / out-of-tree-write blocked (incl.
  pipe-to-shell, `/dev/tcp`, `find -exec/-delete`, redirects outside quarantine,
  and command-substitution bodies — `$(curl evil)` blocks while `$(mktemp -d)` is
  allowed);
- read-only Bash within quarantine allowed; **false positives avoided** (a denied
  word as a mere argument/quoted string, e.g. `grep "curl" content`, is allowed);
- reads confined to the quarantine + skill dirs; writes confined to
  `<quarantine>/report/`; malformed JSON and unset `QUARANTINE_DIR` fail closed.

## `scan.test.sh`

Runs `scan.py` end-to-end on fixtures: CLEAN→`SAFE`, lone network-call or lone
lifecycle hook→`SUSPICIOUS`, full backdoor→`DANGEROUS`; asserts each detector
fires, that snippets are **sanitized** (hidden RLO surfaces as `<U+202E>`, the raw
byte never reaches the report), that **spotlight fences** use the run nonce, and
that empty/binary inputs don't crash.

## `acquire.test.py`

Unit-tests `acquire.py`'s offline logic: input `classify()`, GitHub URL rewriting,
archive sniffing, **zip-slip / absolute-path / symlink** rejection in
`safe_extract_zip`, traversal blocked by the PEP 706 `data` filter in
`safe_extract_tar`, symlink-safe + `.git`-skipping `copy_local`, and exec-bit
stripping. (The networked git-clone / curl paths are not exercised here.)

## Notes

The skill's guard shares its design with `agents/quarantine-reviewer/.claude/hooks/
guard.py` (same command-position tokenizer + substitution-body evaluation), but is
tuned to a different boundary: the skill confines to the **quarantine dir** (and
allows the analyst to `AskUserQuestion`), while the agent confines to the **repo
tree** and blocks `AskUserQuestion`. Keep the shared Bash-parsing logic in sync
when editing either.
