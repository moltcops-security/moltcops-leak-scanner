# CLAUDE.md — MoltCops workspace operating rules

You are working in the MoltCops security-research workspace. These rules are
not style preferences; they are the project's safety and credibility
constraints. They override any "helpful" instinct.

## Non-negotiables (the project's five rules, applied to you)

1. **Never re-enable credential verification.** trufflehog always runs with
   `--no-verification`. Do not add, suggest, or "fix" code that calls a
   provider with a found credential. There is no flag to turn it on by design.
2. **Never write secrets into files, logs, tests, commits, or prompts.**
   - Real found credentials are NEVER pasted into this chat, even partially.
   - Scan outputs (trufflehog/gitleaks JSON contain raw `Secret` values) live
     OUTSIDE this repo in `~/moltcops-secure/`. Do not move, copy, or read
     them into this workspace. Do not commit them.
   - `moltcops-leaks.db` is gitignored. Keep it that way.
3. **Fixtures stay fabricated.** Test credentials in `fixtures/` must be
   obviously fake (or vendors' own published example keys). Never generate a
   realistic-looking key with a live prefix pattern beyond the fixture suite.
4. **Notifications are human-sent.** You may draft notification email text
   (with placeholders, never real secrets). You never send anything, and you
   never open public GitHub issues about a leak.
5. **Public data only.** Do not add scraping of authenticated sources,
   Discord/Telegram, or anything requiring a found credential to access.
6. **No network calls in tests or fixtures.** Live-RPC checks in self-tests
   must skip gracefully offline (see wallet_check.py). Never add a test that
   requires API keys, tokens, or authenticated endpoints: the suite must pass
   on a machine with no credentials and no network.
7. **The disclosure policy is canonical.** moltcops.com/disclosure-policy is
   the public contract for what MoltCops does and doesn't do. Code, READMEs,
   and configs must not contradict it. If a change would require a policy
   change, flag it for human review — never implement it unilaterally.

## Commands (all verified — run them before and after changes)

```bash
python3 bip39_filter.py --self-test       # seed-phrase detection + checksum
python3 wallet_check.py --self-test       # derivation + live read-only RPC
python3 github_search.py --self-test      # pacing/backoff/dedup (offline)
python3 safety_self_test.py               # rules 1-2 source + offline behavior checks
gitleaks dir fixtures --config moltcops-rules.toml --exit-code 0
# expected: exactly 10 findings, 0 in fixtures/should_ignore or hardhat.config.ts
# (10 positive detections + 4 silent files = the README's "14 assertions")
```

A change is not done until all five pass. If you change detection logic,
ADD a regression test/fixture proving the new behavior — the bip39
two-seeds-in-one-message case exists in bip39_filter._self_test because
"unlikely" inputs are the norm in chat transcripts.

## Architecture (don't regress these)

- `github_search.py` stores POINTERS ONLY (repo/path/URL + metadata). It
  never fetches file contents. Keep it that way.
- `bip39_filter.py` never skips ahead in the token stream and records every
  checksum-valid window, including overlapping boundary phantoms (triaged
  downstream by wallet_check.py, which shows phantoms derive empty wallets).
- `wallet_check.py` derives addresses OFFLINE (self-contained secp256k1) and
  only ever calls public, unauthenticated, read-only JSON-RPC endpoints. The
  private key is never transmitted. Custom User-Agent is required (default
  python-urllib gets 403'd).
- `KNOWN_TEST_VECTORS` exists because doc examples (Hardhat `test...junk`,
  Ganache, BIP39 spec vectors) are checksum-valid and WILL false-alarm.
  Verify a phrase is checksum-valid before adding it to the set.

## Style

Python 3.10+, stdlib-first (only dependency: pycryptodome for keccak).
Type hints, docstrings that explain WHY (the ethics constraints are the
design), redaction in any output layer that could touch a real secret.
