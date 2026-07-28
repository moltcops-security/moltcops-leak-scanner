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
| `github_search.py` | Runs the MoltCops query set against GitHub code search. Paced at ≤10 req/min with Retry-After backoff. Stores **pointers only** (repo/path/URL) + scan-run metadata in sqlite — never file contents. | self-test: pacing, backoff, dedup, pointers-only |
| `moltcops-rules.toml` | gitleaks config: LLM keys, MCP-config secrets, keyword-gated ETH keys, GH/AWS/Slack/Discord tokens. Allowlists public dev keys (Hardhat/Ganache). BIP39 deliberately excluded — regex can't validate checksums. | 14/14 fixture assertions |
| `bip39_filter.py` | Finds seed phrases in text and **validates the BIP39 checksum** — kills the prose false-positives that make wordlist-only matching unusable. Redacts phrases in output. Filters known doc test vectors. | 200/200 reference mnemonics accepted; mutations rejected at theoretical rate |
| `wallet_check.py` | Given an exposed private key: derives the address **offline** (self-contained secp256k1 — no deps beyond keccak), then reads native + major stablecoin balances across 5 EVM chains via public unauthenticated RPC. The key never leaves your machine. Reads the key from a hidden prompt or stdin by default — argv is warned against (shell history + `ps`). | derivation matches libsecp256k1 on 300 random keys; all 10 token contracts verified on-chain |
| `scan_repo.sh` | One-command deep scan of a repo's full history (trufflehog + gitleaks, both verification-off). Reports land OUTSIDE the repo (`~/moltcops-secure/` by default; `MOLTCOPS_OUTPUT_DIR` to override), per rule 2. Preflights both binaries and warns on empty reports — never a silent fake "clean". | commands verified against gitleaks 8.30 / trufflehog v3 flags |
| `safety_self_test.py` | Rules 1-2 as executable assertions: `--no-verification` on every trufflehog call, wallet_check RPC methods read-only, scan outputs outside the repo, DB filenames gitignored, no content-fetching Accept header. | exits nonzero on any violation |
| `fixtures/` | Fabricated-credential test suite for the gitleaks config. | 14/14 assertions |

## Setup

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

Beyond GitHub: Hugging Face Spaces (`trufflehog huggingface --space <id>
--no-verification` — v3.88+), npm/PyPI tarballs (`npm pack <pkg>`, then
`gitleaks dir`), public gists, and paste sites (Pastebin scraping needs a paid
PRO account + IP whitelisting). Indexed shared-chat links are a shallow well
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

```bash
python3 bip39_filter.py --self-test
python3 wallet_check.py --self-test      # live RPC checks skip gracefully offline
python3 github_search.py --self-test
python3 safety_self_test.py              # rules 1-2 as executable assertions
gitleaks dir fixtures --config moltcops-rules.toml --exit-code 0
```

`fixtures/` contains **fabricated** credentials only (plus AWS's and
Hardhat's own published example/dev keys, which the rules are configured to
handle correctly). Expect GitHub's secret scanning to flag the fixture files
if you push them — that's the scanners doing their job on a test suite. If
the noise bothers you, exclude the fixture paths via
`.github/secret_scanning.yml` (`paths-excluded:`).
