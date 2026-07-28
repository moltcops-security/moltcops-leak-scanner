#!/usr/bin/env python3
"""
github_search.py — MoltCops leak-scanning pipeline

Runs the MoltCops query set against GitHub's code search API and records
findings in a local sqlite database.

Design rules baked in (they are not options, on purpose):
  * Pacing: the search API allows 10 requests/minute authenticated. This
    script waits >= 6.5s between requests and backs off on 403/429 using
    the Retry-After header (falling back to exponential backoff).
  * Pointers, not secrets: the database stores repo/path/URL locations and
    query metadata ONLY. File contents are never fetched or stored. Manual
    review happens in the browser, by a human, at notification time.
  * Read-only: a plain token on public data; no write scopes needed.

Usage:
    export GITHUB_TOKEN=github_pat_...   # dedicated research-identity token
    python3 github_search.py                      # run default query set
    python3 github_search.py --query '"sk-proj-" language:python'
    python3 github_search.py --dry-run            # show safe query labels, no API calls
    python3 github_search.py --stats              # summarize the database
    python3 github_search.py --self-test          # offline test, no token needed
"""

import argparse
import hashlib
import json
import os
import random
import sqlite3
import sys
import time
import urllib.parse
import urllib.request

API = "https://api.github.com/search/code"
MIN_INTERVAL = 6.5        # seconds between requests (10/min limit + margin)
MAX_RETRIES = 5
USER_AGENT = "moltcops-leak-scanner/1.0 (security research; read-only)"

# MoltCops default query set — agent ecosystem first (the differentiator),
# crypto-adjacent second. Narrow queries beat broad ones: code search
# returns at most 1000 results per query, so prefer many precise queries.
DEFAULT_QUERIES = [
    # Tier 1 — agent ecosystem
    '"sk-proj-" language:python',
    '"sk-proj-" extension:env',
    '"sk-ant-" language:python',
    '"sk-ant-" extension:env',
    '"OPENAI_API_KEY" extension:env',
    '"ANTHROPIC_API_KEY" extension:env',
    '"mcpServers" "apiKey" extension:json',
    '"mcpServers" "token" extension:json',
    '"claude_desktop_config" "secret"',
    # Tier 2 — crypto-adjacent
    '"PRIVATE_KEY" "0x" extension:env',
    '"MNEMONIC" extension:env',
    '"seed phrase" "wallet" extension:txt',
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    query       TEXT NOT NULL,
    repo        TEXT NOT NULL,
    path        TEXT NOT NULL,
    html_url    TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    notified_at TEXT,
    status      TEXT NOT NULL DEFAULT 'new',
    UNIQUE(repo, path)
);
CREATE TABLE IF NOT EXISTS scan_runs (
    id          INTEGER PRIMARY KEY,
    ran_at      TEXT NOT NULL,
    query       TEXT NOT NULL,
    total_count INTEGER,
    fetched     INTEGER,
    incomplete  INTEGER NOT NULL DEFAULT 0
);
"""
DB_VERSION = 1


def query_label(query: str) -> str:
    """Return a deterministic opaque identifier without retaining fragments."""
    digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
    return f"query-sha256:{digest}"


# --- transport (module-level so tests can stub it) -------------------------
def http_get(url: str, token: str) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read() or b""


# --- rate limiting ----------------------------------------------------------
class Pacer:
    """Enforces MIN_INTERVAL between API calls and handles backoff."""

    def __init__(self, sleep=time.sleep, now=time.monotonic):
        self._sleep, self._now = sleep, now
        self._last = 0.0
        self.slept = []   # observability hook for tests

    def wait(self):
        gap = self._now() - self._last
        if gap < MIN_INTERVAL:
            self._do_sleep(MIN_INTERVAL - gap + random.uniform(0, 0.5))
        self._last = self._now()

    def backoff(self, attempt: int, retry_after: str | None):
        if retry_after and retry_after.isdigit():
            delay = int(retry_after)
        else:
            delay = min(60 * (2 ** attempt), 600)
        self._do_sleep(delay)

    def _do_sleep(self, seconds: float):
        self.slept.append(round(seconds, 2))
        self._sleep(seconds)


def search_code(query: str, token: str, pacer: Pacer, page: int = 1,
                per_page: int = 100) -> dict:
    """One search request with pacing and retries. Returns decoded JSON.

    Retries 403/429 via the pacer (Retry-After / exponential backoff) and
    transient transport failures (DNS blips, resets, timeouts) the same way —
    one bad moment should not kill a 12-query run.
    """
    params = urllib.parse.urlencode(
        {"q": query, "per_page": per_page, "page": page})
    url = f"{API}?{params}"
    for attempt in range(MAX_RETRIES):
        pacer.wait()
        try:
            status, headers, body = http_get(url, token)
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pacer.backoff(attempt, None)
            continue
        if status == 200:
            return json.loads(body.decode())
        if status in (403, 429):
            retry_after = headers.get("Retry-After") or headers.get("retry-after")
            pacer.backoff(attempt, retry_after)
            continue
        # Never embed the response body in the error — it lands in tracebacks
        # and logs, and error bodies can echo the query (which may carry a
        # secret prefix the operator typed).
        raise RuntimeError(
            f"GitHub API {status} for {query_label(query)} "
            f"({len(body)}-byte body not logged)")
    raise RuntimeError(
        f"GitHub API kept rejecting after {MAX_RETRIES} tries for {query_label(query)}")


# --- storage ----------------------------------------------------------------
def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > DB_VERSION:
        conn.close()
        raise RuntimeError(
            f"database version {version} is newer than supported {DB_VERSION}")
    if version == 0:
        # Version 0 persisted raw search strings. Hash every row exactly once,
        # including raw input that happens to look like an opaque label; only
        # user_version can distinguish migrated data from label-shaped input.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_runs)")}
        if "incomplete" not in columns:
            conn.execute(
                "ALTER TABLE scan_runs ADD COLUMN incomplete INTEGER NOT NULL DEFAULT 0")
        for table in ("findings", "scan_runs"):
            for row_id, query in conn.execute(f"SELECT id, query FROM {table}"):
                conn.execute(
                    f"UPDATE {table} SET query=? WHERE id=?",
                    (query_label(query), row_id))
        conn.execute(f"PRAGMA user_version = {DB_VERSION}")
    conn.commit()
    return conn


def store_results(conn: sqlite3.Connection, query: str, payload: dict) -> int:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    items = payload.get("items", [])
    label = query_label(query)
    for it in items:
        repo = it.get("repository", {}).get("full_name", "?")
        conn.execute(
            """INSERT INTO findings (query, repo, path, html_url, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(repo, path) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 html_url=excluded.html_url""",  # URLs rot (branch renames) — refresh
            (label, repo, it.get("path", "?"), it.get("html_url", "?"), now, now))
    conn.execute(
        """INSERT INTO scan_runs
           (ran_at, query, total_count, fetched, incomplete) VALUES (?,?,?,?,?)""",
        (now, label, payload.get("total_count"), len(items),
         int(bool(payload.get("incomplete_results", False)))))
    conn.commit()
    return len(items)


def run_query(conn: sqlite3.Connection, query: str, token: str,
              pacer: Pacer) -> tuple[int, int, bool, bool]:
    """Paginate one query to completion (API cap: 10 pages of 100).

    Returns (fetched, total_count, hit_api_cap, incomplete). Stopping at page 1
    would silently under-report — the monthly report's baseline depends on
    complete counts.
    """
    fetched = total_count = 0
    incomplete = False
    for page in range(1, 11):
        payload = search_code(query, token, pacer, page=page)
        items = payload.get("items", [])
        total_count = payload.get("total_count", 0)
        incomplete = incomplete or bool(payload.get("incomplete_results", False))
        store_results(conn, query, payload)
        fetched += len(items)
        if len(items) < 100 or page * 100 >= total_count:
            break
    return fetched, total_count, total_count > fetched, incomplete


def print_stats(conn: sqlite3.Connection) -> None:
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    new = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE status='new'").fetchone()[0]
    notified = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE notified_at IS NOT NULL").fetchone()[0]
    repos = conn.execute("SELECT COUNT(DISTINCT repo) FROM findings").fetchone()[0]
    runs = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
    incomplete_runs = conn.execute(
        "SELECT COUNT(*) FROM scan_runs WHERE incomplete != 0").fetchone()[0]
    print(f"findings: {total} ({new} new, {notified} notified) across {repos} repos")
    print(f"scan runs logged: {runs}")
    print(f"incomplete scan runs: {incomplete_runs}")
    print("\nnewest unreviewed pointers:")
    for repo, path, url in conn.execute(
            "SELECT repo, path, html_url FROM findings WHERE status='new' "
            "ORDER BY first_seen DESC LIMIT 15"):
        print(f"  {repo:40s} {path}\n      {url}")


# --- self-test (offline, no token) ------------------------------------------
def _self_test() -> int:
    import contextlib
    import io
    import tempfile

    calls = {"n": 0, "sleeps": []}
    canned = {
        "total_count": 2,
        "items": [
            {"path": "config.py", "html_url": "https://github.com/a/b/blob/main/config.py",
             "repository": {"full_name": "a/b"}},
            {"path": ".env", "html_url": "https://github.com/c/d/blob/main/.env",
             "repository": {"full_name": "c/d"}},
        ],
    }

    def fake_sleep(s):
        calls["sleeps"].append(s)

    def fake_get(url, token):
        calls["n"] += 1
        if calls["n"] == 2:
            return 403, {"Retry-After": "2"}, b'{"message":"secondary rate limit"}'
        return 200, {}, json.dumps(canned).encode()

    global http_get
    real_get = http_get
    http_get = fake_get
    try:
        pacer = Pacer(sleep=fake_sleep)
        with tempfile.TemporaryDirectory() as td:
            conn = init_db(os.path.join(td, "t.db"))
            assert conn.execute("PRAGMA user_version").fetchone()[0] == DB_VERSION, \
                "new database did not set current user_version"
            n1 = store_results(conn, "q1", search_code("q1", "tok", pacer))
            # second call: paces + survives a 403 with Retry-After
            n2 = store_results(conn, "q2", search_code("q2", "tok", pacer))
            # same items again -> dedup via UNIQUE(repo, path)
            n3 = store_results(conn, "q1", search_code("q1", "tok", pacer))

            rows = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            runs = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]

            assert (n1, n2, n3) == (2, 2, 2), (n1, n2, n3)
            assert rows == 2, f"dedup failed, rows={rows}"
            assert runs == 3, f"scan_runs not logged: {runs}"
            # pacing: gaps between the 4 API calls respected MIN_INTERVAL
            paces = [s for s in calls["sleeps"] if s >= MIN_INTERVAL]
            assert len(paces) >= 3, f"pacing sleeps missing: {calls['sleeps']}"
            assert 2 in calls["sleeps"], f"Retry-After not honored: {calls['sleeps']}"

            # nothing but pointers/metadata in the DB
            text = " ".join(str(r) for r in conn.execute(
                "SELECT query, repo, path, html_url FROM findings").fetchall())
            assert "sk-" not in text, "secret-like content leaked into DB"

            # --- pagination: 150 results across 2 pages, no third call ---
            calls["n"] = 0
            def paged_get(url, token):
                calls["n"] += 1
                page = int(urllib.parse.parse_qs(
                    urllib.parse.urlparse(url).query)["page"][0])
                assert page <= 2, f"requested unnecessary page {page}"
                n_items = 100 if page == 1 else 50
                return 200, {}, json.dumps({
                    "total_count": 150,
                    "items": [{"path": f"f{i}.py",
                               "html_url": f"https://github.com/r/s/blob/main/f{i}.py",
                               "repository": {"full_name": "r/s"}}
                              for i in range((page - 1) * 100, (page - 1) * 100 + n_items)],
                }).encode()
            http_get = paged_get
            pacer2 = Pacer(sleep=fake_sleep)
            fetched, total, capped, incomplete = run_query(
                conn, "paged-q", "tok", pacer2)
            assert (fetched, total, capped, incomplete) == (150, 150, False, False), \
                (fetched, total, capped, incomplete)
            rows = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE repo='r/s'").fetchone()[0]
            assert rows == 150, f"pagination stored {rows}/150"

            # --- transport failure: one URLError, then success ---
            calls["n"] = 0
            def flaky_get(url, token):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise urllib.error.URLError("dns blip")
                return 200, {}, json.dumps(
                    {"total_count": 0, "items": []}).encode()
            http_get = flaky_get
            pacer3 = Pacer(sleep=fake_sleep)
            search_code("retry-q", "tok", pacer3)
            assert calls["n"] == 2, f"no retry after URLError (calls={calls['n']})"

            # Operator-supplied queries can themselves contain sensitive text.
            # Only a deterministic opaque label may reach logs/errors/storage.
            sensitive_query = 'operator-private-marker-Z9Y8X7 filename:.env'
            http_get = lambda url, token: (200, {}, json.dumps({
                "total_count": 1,
                "incomplete_results": False,
                "items": [{"path": "safe-pointer.env",
                           "html_url": "https://github.com/x/y/blob/main/safe-pointer.env",
                           "repository": {"full_name": "x/y"}}],
            }).encode())
            run_query(conn, sensitive_query, "tok", Pacer(sleep=fake_sleep))
            db_text = "\n".join(conn.iterdump())
            assert sensitive_query not in db_text, "custom query stored verbatim"
            assert "operator-private-marker" not in db_text, "custom-query fragment stored"

            http_get = lambda url, token: (422, {}, b'{"message":"bad query"}')
            try:
                search_code(sensitive_query, "tok", Pacer(sleep=fake_sleep))
                assert False, "non-retryable API error did not raise"
            except RuntimeError as exc:
                error = str(exc)
                assert sensitive_query not in error, "API error echoed custom query"
                assert "operator-private-marker" not in error, "API error leaked query fragment"

            # GitHub explicitly says when search results are incomplete. Record
            # and return that state; never silently treat the response complete.
            http_get = lambda url, token: (200, {}, json.dumps({
                "total_count": 0, "incomplete_results": True, "items": [],
            }).encode())
            outcome = run_query(conn, sensitive_query, "tok", Pacer(sleep=fake_sleep))
            assert len(outcome) == 4 and outcome[3] is True, outcome
            incomplete = conn.execute(
                "SELECT incomplete FROM scan_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()[0]
            assert incomplete == 1, "incomplete_results not recorded"

            # A pre-hardening database contains raw query text and lacks the
            # incomplete column. Version-0 migration must scrub both
            # query-bearing tables unconditionally: label-shaped text may be
            # legacy raw input rather than an already-migrated value.
            old_db = os.path.join(td, "old-schema.db")
            old = sqlite3.connect(old_db)
            old.executescript("""
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY, query TEXT NOT NULL,
                    repo TEXT NOT NULL, path TEXT NOT NULL, html_url TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    notified_at TEXT, status TEXT NOT NULL DEFAULT 'new',
                    UNIQUE(repo, path));
                CREATE TABLE scan_runs (
                    id INTEGER PRIMARY KEY, ran_at TEXT NOT NULL,
                    query TEXT NOT NULL, total_count INTEGER, fetched INTEGER);
            """)
            legacy_query = "fabricated-sensitive-migration-marker-Q4W5E6"
            label_shaped_raw_query = "query-sha256:deadbeefdeadbeef"
            old.execute(
                "INSERT INTO findings (query, repo, path, html_url, first_seen, last_seen) "
                "VALUES (?, 'legacy/repo', 'pointer', 'https://example.invalid/p', 't', 't')",
                (legacy_query,))
            old.execute(
                "INSERT INTO findings (query, repo, path, html_url, first_seen, last_seen) "
                "VALUES (?, 'labeled/repo', 'pointer', 'https://example.invalid/q', 't', 't')",
                (label_shaped_raw_query,))
            old.execute(
                "INSERT INTO scan_runs (ran_at, query, total_count, fetched) "
                "VALUES ('t', ?, 1, 1)", (legacy_query,))
            old.execute(
                "INSERT INTO scan_runs (ran_at, query, total_count, fetched) "
                "VALUES ('t', ?, 1, 1)", (label_shaped_raw_query,))
            old.commit()
            old.close()

            migrated = init_db(old_db)
            assert migrated.execute("PRAGMA user_version").fetchone()[0] == 1, \
                "legacy migration did not set user_version"
            migrated_dump = "\n".join(migrated.iterdump())
            assert legacy_query not in migrated_dump, "migration retained raw legacy query"
            expected_label = query_label(legacy_query)
            finding_queries = [r[0] for r in migrated.execute(
                "SELECT query FROM findings ORDER BY id")]
            run_queries = [r[0] for r in migrated.execute(
                "SELECT query FROM scan_runs ORDER BY id")]
            expected_shaped_label = query_label(label_shaped_raw_query)
            assert finding_queries == [expected_label, expected_shaped_label], finding_queries
            assert run_queries == [expected_label, expected_shaped_label], run_queries

            # A later init is idempotent because the explicit schema version,
            # not label syntax, records that migration has completed.
            migrated.close()
            reopened = init_db(old_db)
            assert [r[0] for r in reopened.execute(
                "SELECT query FROM findings ORDER BY id")] == finding_queries
            assert [r[0] for r in reopened.execute(
                "SELECT query FROM scan_runs ORDER BY id")] == run_queries
            migrated = reopened

            migrated.execute("UPDATE scan_runs SET incomplete=1 WHERE id=1")
            migrated.commit()
            stats_output = io.StringIO()
            with contextlib.redirect_stdout(stats_output):
                print_stats(migrated)
            assert "incomplete scan runs: 1" in stats_output.getvalue(), \
                "--stats does not surface persisted incomplete scans"
            migrated.close()
    finally:
        http_get = real_get

    print("github_search self-test: pacing, Retry-After backoff, dedup, "
          "scan_runs logging, pointers-only/redacted storage, pagination, "
          "transport-error retry, redacted errors, incomplete-results "
          "recording/stats, legacy-query migration — all OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default="moltcops-leaks.db")
    parser.add_argument("--query", action="append",
                        help="override the default query set (repeatable)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print queries, make no API calls")
    parser.add_argument("--stats", action="store_true",
                        help="summarize the database and exit")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    queries = args.query or DEFAULT_QUERIES
    if args.dry_run:
        print(f"would run {len(queries)} queries "
              f"(~{len(queries) * 7 / 60:.0f} min at 10 req/min pacing):")
        for q in queries:
            print(f"  {query_label(q)}")
        return 0

    conn = init_db(args.db)
    if args.stats:
        print_stats(conn)
        return 0

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("set GITHUB_TOKEN (dedicated research-identity token)")

    pacer = Pacer()
    total_fetched = 0
    for q in queries:
        fetched, total_count, capped, incomplete = run_query(conn, q, token, pacer)
        total_fetched += fetched
        note = " (API 1000-result cap hit — narrow this query)" if capped else ""
        if incomplete:
            note += " (INCOMPLETE GitHub result set — do not treat as complete)"
        print(f"[{query_label(q)}] total_count={total_count} fetched={fetched}{note}")
    print(f"\ndone. {total_fetched} result pointers fetched "
          f"(deduplicated in {args.db}; run with --stats to review).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
