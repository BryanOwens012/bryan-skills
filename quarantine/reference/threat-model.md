# Quarantine — threat model, guarantees, and limits

## What this protects against

1. **Execution during acquisition.** Cloning/downloading an untrusted artifact
   should not run its code. `acquire.py`:
   - shallow `git clone` with `core.symlinks=false`, `core.hooksPath=/dev/null`,
     `--no-recurse-submodules`, `protocol.file/ext/fd=never`, `GIT_LFS_SKIP_SMUDGE`,
     and `GIT_CONFIG_GLOBAL=/dev/null` (ignores your gitconfig so an attacker can't
     ride `insteadOf`/`hooksPath`); then deletes `.git/` entirely. Git ≥ 2.45.1
     also patches the known clone-time RCEs (CVE-2024-32002 and siblings).
   - https-only, size/time/redirect-bounded downloads written to a file (never
     piped to a shell).
   - archive extraction guarded against zip-slip / path traversal, with symlink
     entries skipped (zip) or rejected by the PEP 706 `data` filter (tar).
   - local copies that never follow symlinks out of the tree.
   - strips execute bits from everything it writes (defense in depth).

2. **Execution during analysis.** Nothing in the workflow runs the artifact. The
   optional deep-read sub-session's `guard.py` hook denies install/build/exec
   shell verbs in every permission mode.

3. **Prompt injection of the reviewing LLM (the subtle one).** The artifact may
   contain text crafted to hijack an AI reviewer. Defenses, in layers:
   - **The scanner, not the LLM, reads raw bytes in bulk.** `scan.py` emits a
     *sanitized* report: control/zero-width/bidirectional unicode become visible
     `<U+XXXX>` tokens, snippets are truncated and newline-flattened, and all
     artifact text is wrapped in nonce-delimited `UNTRUSTED-DATA` fences
     (spotlighting / delimiting, per Microsoft's indirect-injection guidance).
   - **A dedicated injection-detection layer** turns "ignore previous
     instructions", AI-directed text, exfil/hidden directives, role markers, and
     invisible unicode into *findings* the reviewer reports rather than obeys.
   - **The SKILL.md trust-boundary preamble** instructs the reviewer to treat all
     artifact content as data, never act on it, and never touch the network or
     out-of-tree files on the artifact's behalf.
   - **The anchored sandbox** (Step 4) makes that boundary *deterministic*: even a
     successful injection cannot exfiltrate or fetch a payload, because the hook
     blocks the tool call itself. Specifically `guard.py` also: confines **Bash read
     arguments** to the quarantine tree (so `cat ~/.ssh/id_rsa` is blocked, not just
     the Read tool); blocks **launchers** that could open a URL or spawn an
     unguarded session (`open`, `xdg-open`, `osascript`, `claude`, `security`, …);
     and blocks executing any **path-specified** binary (`./payload`).
   - **The main session never reads raw artifact bytes.** SKILL.md forbids opening
     `content/` files in the user's (unguarded) session — analysis runs off the
     sanitized `report/`, and any deep raw read goes through the hooked sandbox. This
     removes the only place an injection could actually act.
   - **Report fields are all sanitized**, including artifact-controlled **file
     paths** (a crafted filename can't inject control chars / a forged fence), and
     the dangerous-unicode set covers zero-width, bidi, BOM, **variation selectors**,
     and **tag chars**.

4. **Exfiltration & second-stage fetch (egress AND ingress).** During the deep
   read, `guard.py` denies `WebFetch`/`WebSearch` and all networked Bash, so the
   reviewer can neither send your data to a URL in the repo nor pull more code in.

## What this does NOT guarantee

- **SAFE ≠ proven safe.** It means no known pattern matched. Novel, heavily
  obfuscated, or logic-only backdoors can pass. Treat SAFE as "no red flags",
  not a clean bill of health.
- **The deterministic scan is regex-based.** It caps matches per pattern and
  skips very large / minified files (configurable in `scan.py`). Determined
  obfuscation across many small steps can evade single-line regexes — that is
  what the optional in-context deep read is for.
- **The soft (prose) injection defenses are probabilistic.** Spotlighting and the
  trust-boundary preamble *reduce* attack success; they don't eliminate it. The
  *hard* guarantee is the sandbox hook layer — prefer it for raw reads.
- **`guard.py` inspects command strings**, so like any string-based guard it can
  miss exotic obfuscation (e.g. base64-piped-to-shell variants). The network /
  install / exec denylist plus the no-out-of-tree-read/write rules cover the
  realistic vectors; the strongest backstop remains running on a throwaway
  machine / VM for genuinely high-risk samples.
- It does not run real dependency-vulnerability scanners (osv-scanner, semgrep,
  gitleaks). Pair with those for supply-chain CVE coverage.

## Tuning

Caps and patterns live at the top of `scripts/acquire.py` (size/file/time limits)
and `scripts/scan.py` (`CODE_PATTERNS`, `INJECTION_PATTERNS`, `DANGEROUS_UNICODE`,
match caps). Add patterns as new attack classes emerge.
