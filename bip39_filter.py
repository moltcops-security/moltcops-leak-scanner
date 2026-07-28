#!/usr/bin/env python3
"""
bip39_filter.py — MoltCops leak-scanning pipeline

Finds BIP39 seed phrases in text and validates their checksums.

Why checksum validation matters: wordlist-only matching false-positives on
ordinary English prose (many BIP39 words are common words). The BIP39
checksum (last 4-8 bits derived from SHA-256 of the entropy) rejects
~15/16 of random 12-word candidates and ~255/256 of random 24-word ones.

Read-only, offline, pure stdlib. No network calls. Nothing is verified
against any wallet, chain, or provider.

Usage:
    python3 bip39_filter.py <file>
    cat chatlog.txt | python3 bip39_filter.py
    python3 bip39_filter.py --self-test
"""

import hashlib
import re
import sys
import unicodedata
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent / "bip39_english.txt"

# Well-known public test vectors from BIP39 docs and wallet dev docs.
# These appear in documentation constantly and are NOT real leaks.
KNOWN_TEST_VECTORS = {
    # BIP39 documentation vectors
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    # Wallet/framework dev defaults (checksum-valid by design -> would
    # otherwise false-alarm as "CHECKSUM VALID" in every Hardhat/Ganache repo)
    "test test test test test test test test test test test junk",                      # Hardhat/Anvil
    "myth like bonus scare over problem client lizard pioneer submit female collect",    # Ganache
}

WORD_RE = re.compile(r"[a-z]+")
VALID_LENGTHS = (12, 15, 18, 21, 24)


def load_wordlist(path: Path = WORDLIST_PATH) -> list[str]:
    words = path.read_text(encoding="utf-8").split()
    if len(words) != 2048:
        raise ValueError(f"wordlist must contain 2048 words, got {len(words)}")
    return words


def validate_checksum(mnemonic_words: list[str], wordlist: list[str] | None = None,
                      index: dict | None = None) -> bool:
    """Return True iff the mnemonic has a valid BIP39 checksum."""
    if index is None:
        if wordlist is None:
            wordlist = load_wordlist()
        index = {w: i for i, w in enumerate(wordlist)}
    if len(mnemonic_words) not in VALID_LENGTHS:
        return False
    try:
        bits = "".join(format(index[w], "011b") for w in mnemonic_words)
    except KeyError:
        return False
    ent_len = len(bits) * 32 // 33          # entropy bits
    cs_len = len(bits) - ent_len            # checksum bits (ENT/32)
    ent_bytes = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    digest = hashlib.sha256(ent_bytes).digest()
    cs_expected = format(digest[0], "08b")[:cs_len]
    return bits[ent_len:] == cs_expected


def find_seed_phrases(text: str, wordlist: list[str] | None = None) -> list[dict]:
    """
    Scan text for candidate seed phrases.

    Returns a list of dicts: {phrase, words, checksum_valid, known_test_vector}.
    Only candidates made entirely of wordlist words are returned at all.

    Algorithm: at every token position, try all window lengths and record
    EVERY checksum-valid window. Never skip ahead — not on a match, and
    especially not on a checksum failure. Skipping misses real phrases
    embedded in longer wordlist runs (two seeds pasted back-to-back, or
    BIP39-words-as-prose like "old seed" gluing onto a phrase). Boundary
    windows spanning prose+phrase can validate by chance (~1/16); they are
    reported alongside the true phrase and triaged by wallet_check.py —
    a phantom boundary phrase derives an empty wallet, a real one doesn't.
    Checksum-invalid candidates are recorded only where they don't overlap
    a valid hit, so prose noise stays quiet.
    """
    if wordlist is None:
        wordlist = load_wordlist()
    wordset = set(wordlist)
    index = {w: i for i, w in enumerate(wordlist)}  # built once, not per window

    text = unicodedata.normalize("NFKD", text.lower())
    tokens = WORD_RE.findall(text)
    n = len(tokens)

    valid_hits = []      # (start, length, phrase)
    candidates = []      # (start, length, phrase) longest-consistent per position
    lengths = sorted(VALID_LENGTHS, reverse=True)

    for i in range(n):
        longest_consistent = None
        for length in lengths:
            window = tokens[i:i + length]
            if len(window) < length:
                continue  # tail of the token stream — try a shorter window
            if not all(t in wordset for t in window):
                continue
            if longest_consistent is None:
                longest_consistent = (i, length, " ".join(window))
            if validate_checksum(window, wordlist, index):
                valid_hits.append((i, length, " ".join(window)))
        if longest_consistent is not None:
            candidates.append(longest_consistent)

    def overlaps_valid(start: int, length: int) -> bool:
        return any(start < vs + vl and vs < start + length
                   for vs, vl, _ in valid_hits)

    results, seen = [], set()

    def record(phrase: str, length: int, valid: bool) -> None:
        if phrase in seen:
            return
        seen.add(phrase)
        results.append({
            "phrase": phrase,
            "words": length,
            "checksum_valid": valid,
            "known_test_vector": phrase in KNOWN_TEST_VECTORS,
        })

    for start, length, phrase in valid_hits:
        record(phrase, length, True)
    for start, length, phrase in candidates:
        if not overlaps_valid(start, length):
            record(phrase, length, False)
    return results


def report(text: str) -> str:
    findings = find_seed_phrases(text)
    if not findings:
        return "No BIP39 wordlist-consistent sequences found."
    lines = []
    for f in findings:
        if f["known_test_vector"]:
            verdict = "KNOWN TEST VECTOR (documentation example, not a leak)"
        elif f["checksum_valid"]:
            verdict = "CHECKSUM VALID — treat as a real leak, notify owner"
        else:
            verdict = "checksum invalid (likely prose or corrupted phrase)"
        # Show only the first 2 and last word — never echo the full phrase
        # into logs/screenshots/tickets.
        w = f["phrase"].split()
        redacted = f"{w[0]} {w[1]} ... {w[-1]}"
        lines.append(f"[{f['words']} words] {redacted}  ->  {verdict}")
    return "\n".join(lines)


def _self_test() -> int:
    wordlist = load_wordlist()

    # 1. The canonical BIP39 test vector must validate.
    v1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
    assert validate_checksum(v1, wordlist), "canonical test vector rejected"

    # 2. Same words, last word swapped to another list word -> checksum must fail.
    bad = v1[:-1] + ["zoo"]
    assert not validate_checksum(bad, wordlist), "corrupted phrase accepted"

    # 3. Ordinary English prose made of list words must NOT false-positive
    #    as a valid wallet (it may surface as a candidate, but checksum fails).
    prose = ("the agent can access the account and add an address to the list "
             "and then act on it")
    hits = [f for f in find_seed_phrases(prose, wordlist) if f["checksum_valid"]]
    assert not hits, f"prose false-positived: {hits}"

    # 4. Non-list words break sequences; short runs are ignored.
    assert find_seed_phrases("abandon " * 11, wordlist) == []

    # 5. Two seeds pasted back-to-back — "unlikely" inputs are the norm in
    #    chat transcripts. The never-skip-ahead loop must find BOTH real
    #    phrases in the glued token stream. (Boundary phantoms may also
    #    validate; wallet_check.py triages them — phantoms derive empty
    #    wallets.)
    two = ("abandon abandon abandon abandon abandon abandon abandon abandon "
           "abandon abandon abandon about "
           "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
    found = {f["phrase"] for f in find_seed_phrases(two, wordlist)
             if f["checksum_valid"]}
    assert ("abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about") in found, "first glued seed missed"
    assert ("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong") in found, \
        "second glued seed missed"

    print("bip39_filter self-test: all assertions passed")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return _self_test()
    if len(sys.argv) > 1 and sys.argv[1] not in ("-", "/dev/stdin"):
        text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()
    print(report(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
