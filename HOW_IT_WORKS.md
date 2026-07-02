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

Every account that holds a little LIMO gets the **same flat protocol-paid daily gas allowance: 1 LIMO/day of free gas** — the same for ordinary users and for apps. At the near-zero fees on the testnet, that covers an effectively unlimited number of ordinary transactions. A brand-new zero-balance wallet also gets a **one-shot onboarding grant** (a tiny 0.05 LIMO of lifetime free gas) so its very first transactions work with no faucet at all. Two things keep this from being farmed: you must **hold** a minimum of LIMO to earn the daily budget (so spinning up throwaway wallets costs real, locked-up capital per wallet), and a **hard daily mint cap** ceilings the total new LIMO the subsidy can ever create in a day. Beyond the free daily budget, you self-fund — and **apps can fund gas for their own contract** from a developer deposit (see `x/sponsorpool` below): earmark LIMO for a contract and its users transact free, paid from your deposit, until it runs dry.

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
| `x/gassponsor` | The protocol pays EVM gas from an on-chain self-refilling pool: a flat 1 LIMO/day free-gas budget for every account that holds a minimum of LIMO (users and apps alike), plus a one-shot 0.05 LIMO onboarding grant for a fresh zero-balance wallet. Anti-farm: the hold requirement makes each wallet cost locked capital, and a hard daily mint cap ceilings total new supply. |
| `x/sponsorpool` (precompile `0x901`) | Developer-funded gas: a dev deposits LIMO earmarked for their contract (`deposit(address,uint256)`); transactions to that contract are sponsored from the deposit until it runs dry. Permissionless, withdrawable, and non-inflationary (the dev funds it, not new mint). |
| `x/squeeze` | Every block, splits collected fees (governable params): 20% burned, 20% recycled into the gas pool, 60% to validators as compensation for operating a node. |
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
