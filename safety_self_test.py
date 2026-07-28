#!/usr/bin/env python3
"""
safety_self_test.py — MoltCops leak-scanning pipeline

Executable assertions for the project's safety invariants (CLAUDE.md
non-negotiables 1-2). Before this file existed they were prose-only: a
future edit could drop `--no-verification` from scan_repo.sh — re-enabling
trufflehog's default mode, which calls providers with other people's found
credentials — and every other test command would still pass green.

These are deliberately simple source-level assertions. They are not a
substitute for the behavioral tests; they are tripwires for the rules that
behavioral tests can't see.

Exit 0 = all invariants hold. Exit 1 = at least one is broken.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        _failures.append(name)
    return ok


def main() -> int:
    scan_sh = (ROOT / "scan_repo.sh").read_text()
    gitignore = (ROOT / ".gitignore").read_text()
    github_search = (ROOT / "github_search.py").read_text()
    wallet_check = (ROOT / "wallet_check.py").read_text()

    print("safety invariants:")

    # --- Rule 1: verification stays OFF -----------------------------------
    # Invocation lines = trufflehog in command position (start of line) —
    # echoes and loops merely mention it.
    trufflehog_lines = [l for l in scan_sh.splitlines()
                        if re.match(r"^\s*trufflehog\s", l)]
    check("scan_repo.sh invokes trufflehog", len(trufflehog_lines) >= 1)
    check("every trufflehog invocation passes --no-verification",
          all("--no-verification" in l for l in trufflehog_lines),
          "a trufflehog call without --no-verification calls providers "
          "with found credentials")
    check("no scanner invocation swallows failures with '|| true'",
          "|| true" not in scan_sh,
          "failure-swallowing produces fake 'clean' results")

    # --- Rule 2: secrets never persist in the workspace -------------------
    check("scan output defaults outside the repo ($HOME/moltcops-secure)",
          "moltcops-secure" in scan_sh
          and bool(re.search(r'OUT_ROOT=.*\$\{?MOLTCOPS_OUTPUT_DIR', scan_sh))
          and bool(re.search(r'OUT="\$OUT_ROOT/scan-', scan_sh)),
          "expected OUT_ROOT=${MOLTCOPS_OUTPUT_DIR:-$HOME/moltcops-secure}")
    check("no CWD-relative scan output dir is created",
          not re.search(r'^\s*OUT="scan-', scan_sh, re.M))
    check(".gitignore covers any sqlite database filename",
          "*.db" in gitignore)
    check(".gitignore covers scan output dirs",
          "scan-*/" in gitignore)

    # --- Read-only network behavior ---------------------------------------
    # The RPC method allowlist IS the transmission guard: you cannot
    # exfiltrate a key through eth_getBalance / eth_call to public RPCs,
    # and derivation happens offline by construction.
    rpc_methods = set(re.findall(r'"(eth_[a-zA-Z]+)"', wallet_check))
    check("wallet_check.py only uses read-only RPC methods",
          rpc_methods <= {"eth_getBalance", "eth_call"},
          f"unexpected RPC methods: {sorted(rpc_methods)}")
    check("github_search.py never fetches file contents",
          "raw.githubusercontent" not in github_search
          and "/contents" not in github_search,
          "pointers-only design: the DB stores locations, never content")

    # --- Key-handling ------------------------------------------------------
    check("wallet_check.py warns on argv keys (shell history)",
          "WARNING: key passed via argv" in wallet_check)
    check("wallet_check.py supports hidden/stdin key input",
          "getpass.getpass" in wallet_check)

    if _failures:
        print(f"\n{len(_failures)} invariant(s) BROKEN — do not run real scans "
              f"until fixed.")
        return 1
    print("\nsafety_self_test: all invariants hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
