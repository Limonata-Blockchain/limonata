# Official Cosmos EVM security backports before mainnet genesis

The fresh `limonata_20777-1` chain must use the new release before any real gentx
signing or launch. No production mainnet state exists to migrate. All operators
must use the same binary and final genesis.

The following official Cosmos EVM commits were backported without replacing the
Limonata DKG, grant, gas, or supply modules:

| Commit | Correction |
| --- | --- |
| `c3ae9067a7eadcdea55a5192226916deb44c71c4` | Atomic StateDB commit and balance overflow checks, GHSA-367m-g444-9mg3 |
| `fac41147e89b65279deb8278c3cc321e5680c145` | Reject invalid CLI recipient addresses instead of sending to zero |
| `ac0febdc0acd48a7c36c3b1282a679b4bc6399b0` | Recover app-mempool insertion panics, GHSA-9xwc-4fgh-f64f |
| `93271360f1a4dfdb5fdb00a87d668d872842fec2` | Reject unsigned EIP-712 fields, GHSA-7xxp-gq2c-x47x |
| `4f50aab2e43458cdf8e4df9689e0e6a991025121` | Bound precompile counter before increment, GHSA-wm4f-qpxp-rch4 |
| `0d0a072d5466dab8d97bc5c054aca7c841a1846f` | Clamp dynamic fee arithmetic, GHSA-2m6r-q6x4-4w5g |
| `8214c816b2213443475781c0193d800c6c1c1e2d` | Refuse self-destruct while staking positions exist, GHSA-c6xv-pppp-rjw6 |
| `8a508b92a7548ae7b472434245f3abed3f200e84` | Charge internal EVM gas on commit/flush failure, GHSA-p8x8-4gg6-prcc |

These are the security changes released upstream through v0.7.4, including the
v0.7.3 atomicity fix. The earlier GHSA-7g4w-cg88-2cq2 subtraction-underflow guard
was already present in the candidate and its regression test was checked.

Official patch files and their hashes are retained in the local security review
bundle. Upstream changelog hunks were omitted. One integration-test import hunk
was adapted to the local test file; its upstream regression body is unchanged.
The SDK and geth dependency versions were not changed by these backports.

These fixes change transaction execution and are consensus breaking. The binary
must not be substituted into a running historical testnet for replay. Historical
source archives remain untouched. Any existing live chain would need a separately
coordinated upgrade; no automatic state migration is performed here.
