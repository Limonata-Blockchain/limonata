# How Limonata Works (Testnet, live today)

> This page describes what is actually running on the public testnet `limonata_10777-1` right now, in plain terms, so you can understand and use the chain today. For the mainnet plan, the token economics, and what is still being built, see [How it works: the mainnet plan](/how-it-works/mainnet).

Limonata is an independent EVM Layer 1 built on the Cosmos SDK and [cosmos/evm](https://github.com/cosmos/evm). It is its own chain, with its own validators and CometBFT consensus, not a rollup. The one thing that makes it different from an ordinary EVM chain: **the protocol pays your transaction gas.** `LIMO` is a pure network-utility coin (gas and staking only). Testnet tokens have no value.

### The facts

| | |
|---|---|
| EVM chain ID | `10777` (`0x2a19`) |
| Cosmos chain-id | `limonata_10777-1` |
| Coin | `LIMO` (base denom `aLIMO`, 18 decimals) |
| Finality | ~2s blocks, single-slot BFT, no reorg window |
| Tooling | Solidity, MetaMask, Hardhat, Foundry, Viem, Ethers, all unchanged |
| RPC | `https://rpc.limonata.xyz` |
| Explorer | `https://explorer.limonata.xyz` |
| Faucet | `https://faucet.limonata.xyz` |

---

## 1. Gas: you do not pay it (with one small catch)

On most chains you pay gas and must hold the native coin just to move. On Limonata the protocol pays the gas for you. This is built into consensus (the ante handler), not bolted on with a relayer or an ERC-4337 paymaster contract. When your transaction is sponsored, your balance is never debited.

**The one honest catch:** the chain checks that you *could* afford the gas before it decides to sponsor it. So an account with a literally zero balance is rejected with "insufficient funds," even though the gas would have been covered. The fix is one time:

> **Grab a little test LIMO from the faucet once. After that, everything you do is gasless and your balance never drops.** That small balance is a one-time proof-of-funds; it is never actually spent on sponsored gas.

Every account gets a protocol-paid daily gas allowance that is **history-scaled**: a small flat cold-start (0.1 LIMO/day) for any account, plus a bonus that grows with the LIMO you hold, up to a 10 LIMO/day cap. At the near-zero fees on the testnet, even the cold-start covers an effectively unlimited number of ordinary transactions. Tying the bonus to held LIMO is what bounds sybil farming of the free gas. **Developers can also fund gas for their own contract** (see `x/sponsorpool` below): deposit LIMO earmarked for a contract and its users transact free, paid from your deposit, until it runs dry.

**Be precise about "free":** free for the user means *the user does not pay; the protocol absorbs the cost.* Gasless never means nobody pays. How that subsidy is funded, and what it means for the coin supply, is covered in the [mainnet plan](/how-it-works/mainnet).

---

## 2. Build on it in five minutes

It is a normal EVM chain. Point your usual tools at `https://rpc.limonata.xyz` (chain `10777`) and deploy your Solidity unchanged.

- Quickstart (deploy a contract + send a gasless tx): https://github.com/Limonata-Blockchain/limonata-quickstart
- One-click gasless demo: https://limonata.xyz/demo

The flow: make a key, get a little test LIMO from the faucet (this also creates your account on-chain), deploy, and transact. Your balance does not move.

---

## 3. What is running (the live modules)

These are live on the testnet today:

| Module | What it does |
|---|---|
| `x/gassponsor` | The protocol pays EVM gas from an on-chain self-refilling pool: a history-scaled per-account daily allowance (a 0.1 LIMO/day cold-start + a bonus that grows with held LIMO, capped at 10 LIMO/day). |
| `x/sponsorpool` (precompile `0x901`) | Developer-funded gas: a dev deposits LIMO earmarked for their contract (`deposit(address,uint256)`); transactions to that contract are sponsored from the deposit until it runs dry. Permissionless, withdrawable, and non-inflationary (the dev funds it, not new mint). |
| `x/squeeze` | Every block, splits collected fees: 40% burned, 10% recycled into the gas pool, ~50% to validators. |
| `x/paymaster` | The same gasless idea for Cosmos-SDK transactions (one active sponsorship policy). |
| `x/encmempool` | Commit-reveal ordering today; a **threshold-encrypted (anti-MEV) mempool** - submit transactions encrypted, order fixed before anyone can read them, decrypted only when ≥2 of 3 keypers cooperate - activates at block 766558 via a governance upgrade. [Guide](/how-it-works/encrypted-mempool). |
| `x/contest` | An on-chain ecosystem leaderboard. |
| `x/netcap` | A net-seller cap: a rolling-window rate-limit on outbound transfers from the founder and foundation addresses, enforced on both Cosmos sends and native EVM transfers (an anti-dump guardrail on the premine). |
| Passkey / P-256 | On-chain secp256r1 (RIP-7212) signature support and a WebAuthn signing path, so wallets can sign with a passkey. |

---

## 4. Validating today

Limonata is a proof-of-stake chain and a healthy network needs independent operators. Today the testnet runs as an interim setup: a **single validator**, with the team delegating stake to new operators to give them voting power. That stake stays the team's, and validating pays **no yield or income** (inflation is off and fees are near zero). It is a technical contribution to running the network, not an investment.

The longer-term "apply for a locked grant, keep the rewards" validator model is part of the [mainnet plan](/how-it-works/mainnet). To run a node, see the [validator guide](https://limonata.xyz/VALIDATOR.md).

---

## 5. The coin, on testnet

`LIMO` is a pure network-utility coin: gas and staking only. No yield, no dividend, no promise of value. **Testnet tokens are valueless.** The mainnet supply, the cap table, vesting, and the full economics live in the [mainnet plan](/how-it-works/mainnet).

---

*What runs today is above. Where it is going next, and the honest economics behind "free gas," is in [How it works: the mainnet plan](/how-it-works/mainnet). Chain source (Apache-2.0): https://github.com/Limonata-Blockchain/limonata*
