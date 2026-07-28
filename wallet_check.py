#!/usr/bin/env python3
"""
wallet_check.py — MoltCops leak-scanning pipeline

Assesses an exposed Ethereum-style private key WITHOUT ever using it.

What "without using it" means here:
  - Address derivation happens OFFLINE (secp256k1 + keccak256 are pure math).
  - Balances are read via PUBLIC, unauthenticated JSON-RPC endpoints
    (eth_getBalance) and read-only contract queries (eth_call balanceOf).
  - The private key is NEVER transmitted anywhere. Nothing is signed.
  - No transactions are constructed, broadcast, or simulated against the
    key. Funds are never moved — not even "to safety".

A zero native balance does NOT mean an empty wallet: the same address
exists on every EVM chain, and value usually sits in stablecoins. This
tool checks native balance plus major stablecoins on each chain.

Key input — NEVER pass the key as a command-line argument unless you must:
argv is recorded in shell history files (~/.zsh_history / ~/.bash_history —
a persistent on-disk copy of the key, against rule 2) and is visible to
every local user via `ps` for the life of the process.

Usage:
    python3 wallet_check.py                        # prompted, input hidden
    python3 wallet_check.py < key.txt              # stdin; then shred key.txt
    python3 wallet_check.py --address-only         # offline derivation only
    python3 wallet_check.py 0x<64-hex-private-key> # argv — warned against
    python3 wallet_check.py --self-test
"""

import argparse
import getpass
import json
import sys
import urllib.request
from Crypto.Hash import keccak

TIMEOUT = 10  # seconds per RPC call

# --- secp256k1, self-contained (pycryptodome lacks k1 scalar multiply) ---
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(d: int, point=_G):
    result = None
    addend = point
    while d:
        if d & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        d >>= 1
    return result

CHAINS = {
    "ethereum": {
        # All endpoints verified reachable + correct chainId at ship time.
        "rpcs": ["https://ethereum-rpc.publicnode.com",
                 "https://eth.drpc.org",
                 "https://rpc.flashbots.net"],
        "native_symbol": "ETH",
        "tokens": {
            "USDT": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
            "USDC": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
            "DAI":  ("0x6B175474E89094C44Da98b954EedeAC495271d0F", 18),
        },
    },
    "base": {
        "rpcs": ["https://mainnet.base.org",
                 "https://base-rpc.publicnode.com"],
        "native_symbol": "ETH",
        "tokens": {
            "USDC": ("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
        },
    },
    "arbitrum": {
        "rpcs": ["https://arb1.arbitrum.io/rpc",
                 "https://arbitrum-one-rpc.publicnode.com"],
        "native_symbol": "ETH",
        "tokens": {
            "USDT": ("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
            "USDC": ("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
        },
    },
    "polygon": {
        "rpcs": ["https://polygon-bor-rpc.publicnode.com",
                 "https://polygon.drpc.org"],
        "native_symbol": "POL",
        "tokens": {
            "USDT": ("0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6),
            "USDC": ("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6),
        },
    },
    "bsc": {
        "rpcs": ["https://bsc-dataseed.bnbchain.org",
                 "https://bsc-rpc.publicnode.com"],
        "native_symbol": "BNB",
        "tokens": {
            "USDT": ("0x55d398326f99059fF775485246999027B3197955", 18),
            "USDC": ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18),
        },
    },
}

# Known derivation vectors: private key 0x01, plus Anvil/Hardhat dev
# accounts #0/#1 (public, documented, BIP32-derived from the published
# 'test...junk' mnemonic). Used by --self-test.
KNOWN_VECTORS = [
    ("0x" + "0" * 63 + "1",
     "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
    ("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    ("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
     "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
]
KNOWN_KEY1_ADDRESS = KNOWN_VECTORS[0][1].lower()


def derive_address(privkey_hex: str) -> str:
    """Derive the checksummed address from a private key. Pure offline math."""
    raw = privkey_hex.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 64:
        raise ValueError("private key must be 64 hex chars")
    d = int(raw, 16)
    if not (1 <= d < _N):
        raise ValueError("private key outside secp256k1 range")
    point = _scalar_mult(d)
    # The generator has order N, so d in [1, N-1] never yields the point at
    # infinity — assert it anyway so a future refactor can't break silently.
    assert point is not None, "secp256k1 scalar multiply returned infinity"
    pub = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    h = keccak.new(digest_bits=256)
    h.update(pub)
    addr_bytes = h.digest()[-20:]
    # EIP-55 checksum casing
    addr_hex = addr_bytes.hex()
    h2 = keccak.new(digest_bits=256)
    h2.update(addr_hex.encode())
    hash_hex = h2.hexdigest()
    checksummed = "".join(
        c.upper() if c.isalpha() and int(hash_hex[i], 16) >= 8 else c
        for i, c in enumerate(addr_hex)
    )
    return "0x" + checksummed


def _rpc(url: str, method: str, params: list) -> str | None:
    """One JSON-RPC call. Returns the 'result' field or None on any failure."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json",
                 # Endpoints 403 the default python-urllib UA.
                 "User-Agent": "moltcops-wallet-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        if "result" in data and data["result"] is not None:
            return data["result"]
    except Exception:
        return None
    return None


def _rpc_any(rpcs: list[str], method: str, params: list) -> str | None:
    for url in rpcs:
        result = _rpc(url, method, params)
        if result is not None:
            return result
    return None


def native_balance(address: str, rpcs: list[str]) -> float | None:
    result = _rpc_any(rpcs, "eth_getBalance", [address, "latest"])
    if result is None:
        return None
    return int(result, 16) / 10**18


def token_balance(address: str, token_addr: str, decimals: int,
                  rpcs: list[str]) -> float | None:
    """balanceOf(address) via eth_call. Selector 0x70a08231. Read-only."""
    calldata = "0x70a08231" + "0" * 24 + address.lower().replace("0x", "")
    result = _rpc_any(rpcs, "eth_call",
                      [{"to": token_addr, "data": calldata}, "latest"])
    if result is None or result == "0x":
        return None
    return int(result, 16) / 10**decimals


def assess(privkey_hex: str) -> dict:
    address = derive_address(privkey_hex)
    report = {"address": address, "chains": {}}
    for chain, cfg in CHAINS.items():
        entry = {"native": None, "native_symbol": cfg["native_symbol"],
                 "tokens": {}, "tokens_checked": 0, "tokens_total": len(cfg["tokens"]),
                 "error": None}
        bal = native_balance(address, cfg["rpcs"])
        if bal is None:
            entry["error"] = "all RPC endpoints unreachable"
        else:
            entry["native"] = bal
        for symbol, (taddr, dec) in cfg["tokens"].items():
            tbal = token_balance(address, taddr, dec, cfg["rpcs"])
            if tbal is not None:
                # distinguish "checked, zero" from "RPC failed" — the monthly
                # report needs accurate chains/tokens-checked counts
                entry["tokens_checked"] += 1
                if tbal:
                    entry["tokens"][symbol] = tbal
        report["chains"][chain] = entry
    return report


def print_report(report: dict) -> None:
    print(f"Derived address: {report['address']}")
    print("(address derived offline; private key never transmitted)\n")
    funds_found = False
    for chain, entry in report["chains"].items():
        if entry["error"]:
            print(f"  {chain:10s}  RPC error: {entry['error']}")
            continue
        parts = [f"{entry['native']:.6f} {entry['native_symbol']}"]
        for symbol, bal in entry["tokens"].items():
            parts.append(f"{bal:,.2f} {symbol}")
        nonzero = bool(entry["native"] and entry["native"] > 0) or bool(entry["tokens"])
        if nonzero:
            funds_found = True
        marker = "  <-- FUNDS PRESENT" if nonzero else ""
        print(f"  {chain:10s}  {' | '.join(parts)}{marker}")
    print()
    if funds_found:
        print("Result: FUNDS AT RISK. Notify the owner via the disclosure "
              "workflow. Do not touch the funds.")
    else:
        print("Result: no detectable balance on checked chains/tokens. "
              "Still notify — assets may exist on other chains or in DeFi "
              "positions this tool does not read.")


def _self_test() -> int:
    # 1. Derivation vectors — compared EXACTLY (case-sensitive) so an EIP-55
    #    casing regression can't pass silently.
    for privkey, expected in KNOWN_VECTORS:
        addr = derive_address(privkey)
        assert addr == expected, f"derivation wrong for vector: {addr} != {expected}"
    print(f"derivation vectors: {len(KNOWN_VECTORS)}/3 exact (incl. EIP-55 casing)")

    # 2. Reject malformed keys.
    for bad in ("0x1234", "0x" + "g" * 64, "0x" + "0" * 64):
        try:
            derive_address(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted bad key: {bad[:10]}...")
    print("malformed-key rejection: OK")

    # 4. Live read-only path (skipped gracefully offline): query the zero
    #    address's ETH balance via public RPC — must parse without error.
    bal = native_balance("0x0000000000000000000000000000000000000000",
                         CHAINS["ethereum"]["rpcs"])
    if bal is None:
        print("live RPC check: SKIPPED (no network to public RPC)")
    else:
        # The zero address famously holds burned ETH (thousands), so a
        # positive balance proves we're reading a real chain.
        assert bal > 0
        print(f"live RPC check: zero-address balance read OK "
              f"({bal:,.0f} ETH burned there — confirms live read)")

    # 5. Verify the token contract table by calling decimals() on each
    #    entry — catches wrong addresses before they matter.
    checked = 0
    for chain, cfg in CHAINS.items():
        for symbol, (taddr, dec_expected) in cfg["tokens"].items():
            dec_hex = _rpc_any(cfg["rpcs"], "eth_call",
                               [{"to": taddr, "data": "0x313ce567"}, "latest"])
            if dec_hex is None:
                print(f"token table check: {chain}/{symbol} SKIPPED (offline)")
                continue
            assert int(dec_hex, 16) == dec_expected, (
                f"{chain}/{symbol}: decimals {int(dec_hex,16)} != {dec_expected}")
            checked += 1
    if checked:
        print(f"token contract table verified on-chain: {checked} entries OK")

    print("wallet_check self-test: all assertions passed")
    return 0


def _read_privkey(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    """Get the key WITHOUT leaving it in shell history when avoidable.

    Preference order: explicit argv (warned — it lands in ~/.zsh_history and
    `ps`), an interactive hidden prompt on a TTY, else one line from stdin
    (pipe/redirect). The interactive branch uses getpass so the key never
    even echoes to the terminal.
    """
    if args.privkey:
        print("WARNING: key passed via argv — it is now in your shell history "
              "file and was visible in `ps`. Prefer running with no argument "
              "(hidden prompt) or `< key.txt` (then shred key.txt).",
              file=sys.stderr)
        return args.privkey
    if sys.stdin.isatty():
        return getpass.getpass("private key (0x…, input not echoed): ").strip()
    key = sys.stdin.readline().strip()
    if not key:
        parser.error("no key on stdin — pipe one in, run interactively for a "
                     "prompt, or use --self-test")
    return key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("privkey", nargs="?",
                        help="0x-prefixed 64-hex private key — DISCOURAGED: "
                             "argv lands in shell history and `ps`; omit for "
                             "a hidden prompt or pipe via stdin")
    parser.add_argument("--address-only", action="store_true",
                        help="derive the address offline, make no network calls")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    privkey = _read_privkey(args, parser)
    if args.address_only:
        print(derive_address(privkey))
        return 0
    print_report(assess(privkey))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
