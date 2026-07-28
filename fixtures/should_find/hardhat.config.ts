// FIXTURE — Hardhat's PUBLIC well-known dev key (account #1). Not a leak.
// The moltcops rules must ALLOWLIST this, not flag it.
module.exports = { networks: { hardhat: { accounts: [
  { privateKey: "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", balance: "10000" }
] } } };
