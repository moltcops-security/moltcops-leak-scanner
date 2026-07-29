# MoltCops Leak-Scanning Toolkit

Pipeline for finding exposed credentials in **public** places (GitHub repos,
gists, Hugging Face Spaces, published packages, indexed chat transcripts),
classifying them **without ever using them**, and notifying owners — the data
foundation for the monthly *State of Agent Leaks* report.

## The five absolute rules

Everything in this toolkit is built around these. They are what makes this
research instead of intrusion.

1. **Public data only.** Public repos, gists, paste sites, published packages,
   search-engine-indexed pages. Nothing behind a login. No Discord/Telegram
   scraping. No access gained with a found credential — a leaked `ghp_` token
   that would unlock private repos stays unused, no exceptions.
2. **Never use a credential.** No API calls, no logins, no signing.
   `wallet_check.py` derives addresses *offline* (pure math) and reads only
   public chain data; trufflehog always runs with `--no-verification`.
3. **Never move funds.** Not even "to safety." Find → notify → document.
4. **Notify before you publish.** Owner and/or platform first; publish only
   redacted, anonymized, aggregate statistics. Never the key, the full seed
   phrase, or a live link to the leak.
5. **Log everything.** Dates, locations, notification times, response rates.
   The dataset is the moat — and your paper trail.

## Components

| File | What it does | Verified |
|---|---|---|
| `github_search.py` | Runs the MoltCops query set against GitHub code search. Paced at ≤10 req/min with Retry-After backoff and transport retries; paginates to the API cap. Stores **pointers only** (repo/path/URL) + scan-run metadata in sqlite — never file contents. Queries are represented only by deterministic SHA-256 labels in storage, output, and errors; GitHub `incomplete_results` is recorded and surfaced. | offline self-test: pacing, backoff, dedup, redaction, completeness, pointers-only |
| `moltcops-rules.toml` | gitleaks config: LLM keys, MCP-config secrets, keyword-gated ETH keys, GH/AWS/Slack/Discord tokens. Allowlists public dev keys (Hardhat/Ganache) and uint256 math constants (MAX_UINT256/zero word). BIP39 deliberately excluded — regex can't validate checksums. | exactly 10 findings + 5 intentionally silent files = 15 fixture assertions |
| `bip39_filter.py` | Finds seed phrases in text and **validates the BIP39 checksum** — kills the prose false-positives that make wordlist-only matching unusable. Redacts phrases in output, filters known doc test vectors, and finds multiple/overlapping valid windows. | self-test, including two seeds in one message |
| `wallet_check.py` | Given an exposed private key: derives the address **offline** (self-contained secp256k1 — no deps beyond keccak), then reads native + major stablecoin balances across 5 EVM chains via public unauthenticated RPC. The key never leaves your machine. Reads the key from a hidden prompt or stdin by default — argv is warned against (shell history + `ps`). | 3 exact derivation vectors + malformed-key rejection; read-only RPC/token-table checks skip gracefully offline |
| `scan_repo.sh` | One-command deep scan of a repo's full history (trufflehog + gitleaks, both verification-off). Reports land only in `~/moltcops-secure/`, per rule 2. The root must be a current-user-owned, mode-0700 real directory. Scanner failures exit nonzero while retaining reports for incomplete-result triage. | behavior enforced by the offline safety test |
| `safety_self_test.py` | Executable safety assertions: verification-off, real scanner failure propagation/report retention, fixed secure output root, anchored DB ignore, preview-fragment prohibition, pointers-only storage, read-only RPC, and safe key input. | exits nonzero on any violation; fake scanners only, no network |
| `fixtures/` | Fabricated-credential test suite for the gitleaks config. | exactly 10 findings; 5 silent files; 15 assertions total |

## Setup

Requires **Python 3.10+**.

```bash
pip install -r requirements.txt

# gitleaks (Go binary):  https://github.com/gitleaks/gitleaks/releases
# trufflehog (Go binary — NOT pip, the PyPI package is the abandoned 2017 v2):
brew install trufflesecurity/trufflehog/trufflehog        # macOS
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin   # Linux
```

Also: dedicated research identity **before the first notification** — separate
email, PGP key, consistent handle, and a `security.txt` on moltcops.com so
recipients can verify you're not a phishing attempt. Sign notification emails.

## Workflow

```bash
# 1. Discover — paced GitHub search, pointers into sqlite
export GITHUB_TOKEN=<dedicated research token>
python3 github_search.py                  # ~90s for the default 12-query set
python3 github_search.py --stats          # review unreviewed pointers

# 2. Deep-scan specific repos (full history — removed-from-HEAD keys are
#    invisible to the search API but live in git history)
./scan_repo.sh https://github.com/owner/repo

# 3. Classify (offline, read-only)
cat transcript.txt | python3 bip39_filter.py
python3 wallet_check.py            # hidden prompt; or: python3 wallet_check.py < key.txt
                                   # (never pass the key as argv — shell history keeps it)

# 4. Notify (template below), then log notified_at in the DB:
sqlite3 moltcops-leaks.db \
  "UPDATE findings SET notified_at=datetime('now'), status='notified'
   WHERE repo='owner/repo' AND path='.env';"
```

Beyond GitHub: public Hugging Face Spaces (`trufflehog huggingface --space <id>
--no-verification` — v3.88+), public npm/PyPI tarballs (`npm pack <pkg>`, then
`gitleaks dir`), public gists, and publicly indexed paste pages. Do not add
authenticated scraping or sources behind a login. Indexed shared-chat links are a shallow well
since providers de-indexed them — transcripts pasted directly into gists,
issues, and pastes are the richer vein.

## Notification template

> **Subject:** Security: exposed credential in [repo-name]
>
> Hi [name],
>
> I'm a security researcher with MoltCops (moltcops.com — our security.txt
> and PGP key are on the site if you want to verify this message). During a
> scan of public GitHub repositories, I identified what appears to be a live
> [OpenAI API key / Ethereum private key / etc.] in this public file:
>
> Repository: [url] · File: [path] · Commit: [hash, if in history]
>
> I have not used or tested this credential. I'm notifying you so you can
> revoke/rotate it and scrub the repository history (BFG Repo-Cleaner or
> git filter-repo — deleting the file in a new commit is not enough).
>
> I publish anonymized, aggregate statistics from this work and will not
> identify you or your repository publicly.
>
> [Research handle], MoltCops

Rules of engagement: official channel first (SECURITY.md, private
vulnerability reporting, security@), email second, **never a public issue**.
One follow-up after 7 days, then stop. No money talk — ever — outside a
formal bug bounty program. For unresponsive owners of crypto projects with
funds at risk, escalate to SEAL 911 (Security Alliance).

## The monthly report

The `scan_runs` and `findings` tables give you the time series: findings by
key type, platform, and sector; % still live at notification; time-to-fix
after notification; response rates. One reporting subtlety: `findings`
deduplicates on `(repo, path)` while `scan_runs.fetched` counts duplicates —
so compute *unique* findings from the `findings` table, never by summing
`fetched`. Publish the methodology post first
("how we scan without touching anyone's systems" — it's your trust anchor),
then the monthly stats. Case studies: pattern and lesson only, never
identifiers, and only after the notification window.

## Re-running the tests

The release gate is exactly these **five commands**:

```bash
python3 bip39_filter.py --self-test
python3 wallet_check.py --self-test      # live RPC checks skip gracefully offline
python3 github_search.py --self-test
python3 safety_self_test.py              # rules 1-2 as executable assertions
gitleaks dir fixtures --config moltcops-rules.toml --exit-code 0
```

The final command must report exactly **10 findings**, with zero findings in
`fixtures/should_ignore/` and `fixtures/should_find/hardhat.config.ts`: 10
positive detections plus 5 intentionally silent files = **15 assertions**
(the 5 are the `should_ignore/` suite; `should_find/hardhat.config.ts` is a
sixth zero-finding file, counted with the positives it lives among).

`fixtures/` contains **fabricated** credentials only (plus AWS's and
Hardhat's own published example/dev keys, which the rules are configured to
handle correctly). Expect GitHub's secret scanning to flag the fixture files
if you push them — that's the scanners doing their job on a test suite. If
the noise bothers you, exclude the fixture paths via
`.github/secret_scanning.yml` (`paths-excluded:`).
