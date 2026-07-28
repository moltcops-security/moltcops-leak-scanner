#!/usr/bin/env python3
"""
safety_self_test.py — MoltCops leak-scanning pipeline

Executable assertions for the project's safety invariants (CLAUDE.md
non-negotiables 1-2). Before this file existed they were prose-only: a
future edit could drop `--no-verification` from scan_repo.sh — re-enabling
trufflehog's default mode, which calls providers with other people's found
credentials — and every other test command would still pass green.

These combine source-level tripwires with offline behavioral tests driven by
fake scanners in a temporary checkout. No test makes a network request or
writes a scan report into this workspace.

Exit 0 = all invariants hold. Exit 1 = at least one is broken.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        _failures.append(name)
    return ok


def scan_repo_behavior() -> tuple[bool, bool, bool, bool]:
    """Exercise scan_repo.sh with offline fake scanners in a temporary copy."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        copied_root = tmp / "checkout"
        copied_root.mkdir()
        script = copied_root / "scan_repo.sh"
        shutil.copy2(ROOT / "scan_repo.sh", script)
        shutil.copy2(ROOT / "moltcops-rules.toml", copied_root / "moltcops-rules.toml")

        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        invoked = tmp / "invoked"
        (bin_dir / "date").write_text("#!/bin/sh\nprintf '%s\\n' fixed-stamp\n")
        (bin_dir / "trufflehog").write_text(
            "#!/bin/sh\nprintf '%s\\n' trufflehog >> \"$FAKE_INVOKED\"\n"
            "printf '%s\\n' '{\"offline_fake\":true}'\nexit 7\n"
        )
        (bin_dir / "gitleaks").write_text(
            "#!/bin/sh\nprintf '%s\\n' gitleaks >> \"$FAKE_INVOKED\"\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = --report-path ]; then shift; printf '%s\\n' '[]' > \"$1\"; fi\n"
            "  shift\n"
            "done\nexit 0\n"
        )
        for fake in bin_dir.iterdir():
            fake.chmod(0o755)
        env = os.environ.copy()
        home = tmp / "home"
        home.mkdir()
        redirected = tmp / "attacker-writable"
        redirected.mkdir(mode=0o777)
        env.update({
            "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
            "FAKE_INVOKED": str(invoked),
            "HOME": str(home),
            "MOLTCOPS_OUTPUT_DIR": str(redirected),
        })
        failed = subprocess.run(
            ["bash", str(script), "https://example.invalid/offline-fixture"],
            env=env, capture_output=True, text=True, check=False,
        )
        output_root = home / "moltcops-secure"
        reports = list(output_root.glob("scan-*/trufflehog.json"))
        failure_propagates = (
            failed.returncode != 0
            and len(reports) == 1
            and '\"offline_fake\":true' in reports[0].read_text()
        )
        fixed_root = (
            not any(redirected.iterdir())
            and output_root.exists()
            and (output_root.stat().st_mode & 0o777) == 0o700
        )

        # An attacker must not be able to pre-create the predictable run
        # directory and point either raw report back into the checkout.
        invoked.unlink(missing_ok=True)
        if output_root.exists():
            shutil.rmtree(output_root)
        output_root.mkdir(mode=0o700)
        run_dir = output_root / "scan-fixed-stamp"
        run_dir.mkdir(parents=True)
        truffle_target = copied_root / "trufflehog-leak.json"
        gitleaks_target = copied_root / "gitleaks-leak.json"
        (run_dir / "trufflehog.json").symlink_to(truffle_target)
        (run_dir / "gitleaks.json").symlink_to(gitleaks_target)
        symlinked = subprocess.run(
            ["bash", str(script), "https://example.invalid/offline-fixture"],
            env=env, capture_output=True, text=True, check=False,
        )
        report_symlink_guard = (
            symlinked.returncode != 0
            and not truffle_target.exists()
            and not gitleaks_target.exists()
            and not invoked.exists()
        )

        # The fixed root itself must never be followed if pre-planted as a
        # symlink, and an existing group/world-accessible root must be refused.
        shutil.rmtree(output_root)
        output_root.symlink_to(copied_root, target_is_directory=True)
        invoked.unlink(missing_ok=True)
        root_symlinked = subprocess.run(
            ["bash", str(script), "https://example.invalid/offline-fixture"],
            env=env, capture_output=True, text=True, check=False,
        )
        root_symlink_guard = root_symlinked.returncode != 0 and not invoked.exists()
        output_root.unlink()
        output_root.mkdir(mode=0o755)
        root_permissive = subprocess.run(
            ["bash", str(script), "https://example.invalid/offline-fixture"],
            env=env, capture_output=True, text=True, check=False,
        )
        root_permissions_guard = root_permissive.returncode != 0 and not invoked.exists()
        secure_root_guard = root_symlink_guard and root_permissions_guard
        if not (fixed_root and report_symlink_guard and secure_root_guard):
            print(f"output diagnostics: fixed_root={fixed_root}, "
                  f"report_symlinks={report_symlink_guard}, "
                  f"root_symlink={root_symlink_guard}, root_mode={root_permissions_guard}; "
                  f"symlink_rc={symlinked.returncode}, root_symlink_rc={root_symlinked.returncode}, "
                  f"root_mode_rc={root_permissive.returncode}")
            print(f"symlink stderr: {symlinked.stderr.strip()}")
            print(f"root symlink stderr: {root_symlinked.stderr.strip()}")
            print(f"root mode stderr: {root_permissive.stderr.strip()}")
        return failure_propagates, fixed_root, report_symlink_guard, secure_root_guard


def main() -> int:
    scan_sh = (ROOT / "scan_repo.sh").read_text()
    gitignore = (ROOT / ".gitignore").read_text()
    github_search = (ROOT / "github_search.py").read_text()
    wallet_check = (ROOT / "wallet_check.py").read_text()

    print("safety invariants:")
    failure_propagates, fixed_root, report_symlink_guard, secure_root_guard = scan_repo_behavior()

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
    check("real scanner failure exits nonzero and retains its incomplete report",
          failure_propagates,
          "a scanner error must not become a successful/clean scan")

    # --- Rule 2: secrets never persist in the workspace -------------------
    check("scan output is fixed at $HOME/moltcops-secure and ignores overrides",
          fixed_root
          and "MOLTCOPS_OUTPUT_DIR" not in scan_sh
          and 'OUT_ROOT="$HOME/moltcops-secure"' in scan_sh,
          "MOLTCOPS_OUTPUT_DIR must not redirect raw reports")
    check("no CWD-relative scan output dir is created",
          not re.search(r'^\s*OUT="scan-', scan_sh, re.M))
    check("output root rejects symlinks, foreign owners, and permissive modes",
          secure_root_guard
          and "os.getuid()" in scan_sh
          and "st_uid" in scan_sh,
          "the canonical root must be owned by this UID with mode 0700")
    check("pre-existing run/report symlinks cannot write raw output into checkout",
          report_symlink_guard,
          "the timestamp run directory must be created exclusively")
    check(".gitignore anchors any sqlite database filename",
          bool(re.search(r'^\*\.db$', gitignore, re.M)))
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
    check("github_search.py forbids text-match/cloak-preview fragments",
          "text-match" not in github_search.lower()
          and "cloak-preview" not in github_search.lower(),
          "preview fragments can place matched secret text in memory/output")

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
