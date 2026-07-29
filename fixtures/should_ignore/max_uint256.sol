// FIXTURE — not credentials. uint256 math constants that used to
// false-positive the eth-private-key rule (dogfood scan of moltshield
// flagged 5 identical matches in the scanner's own engine + tests).
// 64 f's / 64 zeros are valid hex; the keyword context below satisfies the
// file-scoped gate; the allowlist (^(0x)?f{64}$ / ^(0x)?0{64}$) must keep
// this file SILENT.
contract Limits {
    // wallet balance math masks to the max value on overflow
    uint256 public constant MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    bytes32 public constant EMPTY = 0x0000000000000000000000000000000000000000000000000000000000000000;
    // test_private_key_revert: unprefixed form, same constant
    uint256 public constant MASK = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
}
