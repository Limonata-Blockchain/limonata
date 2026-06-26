# How Limonata Works

> Single source of truth for how the Limonata chain actually behaves. Every capability below is tagged **LIVE** (running on the public testnet `limonata_10777-1` today) or **ROADMAP** (built but not activated, or not built yet). This document is deliberately conservative: where a feature is partially shipped, it is described by what is actually wired end-to-end, not by intent.

---

## 1. What Limonata is

Limonata is an independent EVM Layer 1 built on the Cosmos SDK + [cosmos/evm](https://github.com/cosmos/evm). It is its own chain with its own validator set and CometBFT consensus — not a rollup, not an L2. `LIMO` is a **pure network-utility coin**: it is used for gas and staking only. There is no yield, dividend, profit-share, governance vote, or equity attached to it. What makes Limonata distinct from a stock cosmos/evm chain is a small set of protocol-level modules that (a) let the protocol pay transaction gas so end users transact for free, (b) split and partly burn fees each block, and (c) add guardrails (a net-seller cap) and experimental UX (passkey signing). The headline UX — "your users don't pay gas" — is true, with one honest caveat covered in section 2: an account still needs a tiny non-zero balance on hand, which it never actually spends.

### Key facts

| | |
|---|---|
| EVM chain ID | `10777` (`0x2a19`) |
| Cosmos chain-id | `limonata_10777-1` |
| Native coin | `LIMO` (base denom `aLIMO`, 18 decimals; 1 LIMO = 10^18 aLIMO) |
| Finality | ~0.3s blocks, single-slot BFT (`timeout_commit=300ms`, `mempool.type=app`) — no reorg window |
| Block gas limit | 40,000,000 |
| Tooling | Solidity / MetaMask / Hardhat / Foundry / Viem / Ethers — unchanged |
| Base fee | effectively 0 (live `base_fee=1e-18 aLIMO` truncates to 0; `min_gas_price=0`; node `minimum-gas-prices=0aLIMO`) |
| Total supply | 1,000,000,000 LIMO (see section 4; not strictly fixed — see gas pool minting) |
| Public endpoints | RPC `https://rpc.limonata.xyz` · Explorer `https://explorer.limonata.xyz` · Faucet `https://faucet.limonata.xyz` · Site `https://limonata.xyz` |

---

## 2. The gas model — who actually pays

On most chains the user pays gas and must hold the native coin to move. On Limonata the **protocol** (or, later, a developer) pays the gas. This is enforced in consensus — in the ante handler — not by a relayer, an ERC-4337 bundler, or a paymaster smart contract.

**Be precise about "free":** *free for users* means *the user does not pay; the protocol or the developer absorbs the cost.* Gasless never means nobody pays. Section 3 explains where that cost lands.

### How the sponsorship decision is made (EVM)

For every EVM transaction the decision is made once, in the EVM ante handler:

1. **Affordability check runs FIRST** (`ante/evm/06_account_verification.go` → `x/vm/keeper/fees.go` `CheckSenderBalance`). The sender must already hold at least `gasLimit*gasFeeCap + value`. If not, the tx is rejected with `ErrInsufficientFunds: sender balance < tx cost`. This is unmodified upstream code.
2. **Sponsorship is decided LATER** (`ante/evm/mono_decorator.go` step 8, via `GasSponsorKeeper.IsSponsored`). If sponsored, the fee is moved from the gas-pool module account `paymaster_gas_pool` to `fee_collector` and **the user's balance is never debited**. Unused-gas refunds on a sponsored tx also go back to the pool, not the user.

**The honest truth, stated plainly:** because the affordability check runs *before* the sponsorship decision, a literally-zero-balance account that submits a transaction with a positive gas price is **rejected for insufficient funds — even though that gas would have been sponsored.** Sponsorship removes the *debit*, not the *proof-of-funds requirement*. So:

> **Grab a little test LIMO from the faucet once. After that everything is gasless and your balance never drops.** The small balance is a one-time prerequisite that proves you could pay; it is never actually spent on sponsored gas.

(Edge case: because the live base fee truncates to 0, a *zero-priced, zero-value* tx from a zero-balance account does pass — but that is "free because the price is zero," not sponsorship. The gas pool only actually pays when the user sets a positive gas price, which simultaneously re-imposes the proof-of-funds gate.)

### The three layers of who pays

**(a) Protocol baseline — per-account daily free allowance. LIVE.**
Every account gets a protocol-paid gas allowance per UTC day, debited from a per-(day, sender) counter and paid from the on-chain gas pool. Live allowance is **10 LIMO/day per account** (source default is 1 LIMO/day; live genesis raises it to 10). At near-zero fees this covers an effectively unlimited number of ordinary transactions. Past the allowance, the sender pays their own gas — fees remain the anti-spam bound.

**(b) Approved-dApp — uncapped from the pool. Code LIVE / actual sponsorship ROADMAP.**
If a transaction's `to` address is a registered, admin-approved showcase contract (x/contest), the gas is sponsored from the pool with **no per-account limit** and without touching the daily counter. This path is built and reachable in the live binary. **But:** approval is an admin-gated message (a single bech32 admin key — not on-chain governance, not a precompile), and the live genesis has **zero** approved dApps (`contest.showcase = []`). The website's "approve" button currently only writes a local JSON file; it does **not** send the on-chain `tx contest register-showcase`. So today every sponsored EVM tx flows through the baseline path (a), not the uncapped path. Because the uncapped path is funded entirely by the gas pool, it is **bounded by pool sustainability** (see section 3), not literally infinite.

**(c) Developer self-funded sponsorship. ROADMAP.**
The intended end state is that a developer funds and configures their own sponsorship policy (runtime registration, per-sponsor spend accounting, daily/total caps). This is not built: `x/paymaster` is a scaffold with no message server, policies can only be set via genesis/upgrade, and a policy carries only a per-tx cap (no cumulative cap). Today there is exactly one genesis policy on the Cosmos side, and its sponsor is the gas pool itself.

---

## 3. The value model — where demand for LIMO comes from

Limonata is honest that LIMO is utility-only, so the demand question deserves a straight answer. There is no yield and (on testnet) gas is free, so demand does **not** come from "buy to transact" today. It comes from three places, two live in spirit and one maturing:

1. **Staking / security.** The chain is proof-of-stake; securing it requires bonded LIMO. (Today rewards are ~0 because inflation is 0 and fees are ~0 — see section 6.)
2. **The small mandatory balance every account needs.** Because the affordability gate (section 2) requires a non-zero balance before gas can be sponsored, every active account must hold a little LIMO. On testnet the faucet provides it; **on mainnet there is no faucet, so users must acquire a small amount of LIMO once.** This is a structural, if modest, demand sink.
3. **Developer self-funded sponsorship as it matures (ROADMAP).** When the paymaster self-serve path ships (section 2c), developers buy LIMO to fund sponsorship for their users — converting end-user activity into developer demand for the coin.

No other value-accrual mechanism is claimed. There is no profit-share, buyback, or fee dividend to holders.

### Who bears the cost of "free" gas

The gas pool is a 200,000,000 LIMO module account (`paymaster_gas_pool`) that is **self-refilling**: each block, after the fee split, `x/gassponsor` mints the deficit needed to top the pool back to its 200M target (it holds a Minter permission; `refill_enabled=true`, `min_pool_balance=200M`). Combined with the 10% fee recycle (section 5), this makes the pool effectively inexhaustible — but the refill is funded by **newly minted LIMO**.

Net economics of one **sponsored** fee X: the pool pays X into the fee collector; next block 0.4X is burned, 0.1X is recycled to the pool, 0.5X goes to validators; the pool is then re-minted ~0.9X. Net supply change ≈ **+0.5X (mildly inflationary)**. For a **user-paid** fee X (past the allowance), 0.4X is burned (deflationary), 0.1X funds the pool, 0.5X goes to validators. So the cost of gasless UX is real and lands on **all holders via mild dilution and on the protocol/premine** — it is shifted, not eliminated.

---

## 4. The coin

`LIMO` is a **pure network-utility coin — gas and staking only.** No yield, dividend, profit-share, governance, or equity. Testnet tokens are valueless.

- **Total supply: 1,000,000,000 LIMO (10^27 aLIMO).** x/mint inflation is 0 (`inflation_min/max=0`, `max_supply=0`), and the genesis script hard-fails if supply ≠ 1e27. **Caveat:** supply is **not strictly fixed** — the gas-pool refill mint (section 3) can push total supply above 1B over time.

### Cap table (live genesis, sums to exactly 1,000,000,000 LIMO)

| Bucket | LIMO | % | Form |
|---|---:|---:|---|
| Airdrop reserve | 250,000,000 | 25% | liquid placeholder (ROADMAP distribution) |
| Gas pool (`paymaster_gas_pool`) | 200,000,000 | 20% | module account (= refill target) |
| Foundation / treasury | 150,000,000 | 15% | **PeriodicVesting** |
| Strategic reserve | 149,990,000 | ~15% | testnet → faucet treasury; mainnet → governed reserve key |
| Founder / core team | 100,000,000 | 10% | **PeriodicVesting** |
| Relayer / IBC float | 50,000,000 | 5% | liquid |
| Safety buffer | 50,000,000 | 5% | liquid |
| Valgrant bootstrap pool | 50,000,000 | 5% | module account |
| Genesis validator | 10,000 | ~0% | liquid (self-bonds 1,000) |

On the live **testnet**, the strategic reserve (149,990,000 LIMO) is routed **in full to the faucet treasury** so `faucet.limonata.xyz` can drip; on **mainnet** it routes to a freshly-generated governed `reserve` key with no faucet (ROADMAP).

### Vesting (founder + foundation only)

Founder (100M) and Foundation (150M) are `PeriodicVestingAccount`s — a cliff followed by 36 linear unlock periods. Nothing is spendable until the cliff elapses.

- **Mainnet (ROADMAP):** 12-month cliff + 36 monthly steps (~47 months to full unlock).
- **Testnet (LIVE):** compressed for observability — 90-second cliff + 36 × 10-second steps (end = start + 440s).

### Net-seller cap (anti-dump) — `x/netcap`. LIVE on testnet.

A rolling-window rate limit on **outbound** transfers from restricted addresses (founder + foundation), to prevent a fast dump of the premine. It is enforced on **both** paths — the bank `SendRestriction` (cosmos sends / ERC-20 precompiles) **and** a native-EVM ante decorator (because native EVM value transfers bypass `x/bank`). It exempts whitelisted destinations and all module accounts (so staking/gov/distribution are not counted as sales). It checks in every phase but only records spend at block delivery (no mempool double-count). It **fails open** on misconfiguration and **fails closed** on a real breach.

- **Testnet (LIVE):** window 300s, cap 1,000 LIMO per window, restricted = founder + foundation.
- **Mainnet (ROADMAP):** window 1 month; cap is a **placeholder** of 1,000,000 LIMO/month — the script explicitly says counsel must set the real number.

---

## 5. The modules (one line each)

| Module | What it does | Status |
|---|---|---|
| `x/squeeze` | Every block, splits `fee_collector`: **40% burned** (the only burn on-chain), **10% recycled to the gas pool**, **~50% to validators** (dust rounds to validators). Runs in BeginBlock before distribution. | **LIVE** |
| `x/gassponsor` | EVM protocol-paid gas: per-account 10 LIMO/day baseline + mint-backstop refill of the 200M pool. | **LIVE** |
| `x/gassponsor` (approved-dApp uncapped path) | Reachable in code, but no dApp registered on the live chain. | **ROADMAP** (no live registrations) |
| `x/paymaster` | Cosmos-SDK gasless via policy (one live policy: any sender / any msg, cap 1 LIMO/tx, sponsor = gas pool). | **LIVE** |
| `x/paymaster` (self-serve / per-dev policies) | Scaffold only; no message server; no per-sponsor spend accounting. | **ROADMAP** |
| `x/encmempool` | Commit-reveal delay/ordering primitive (commit hash → reveal after delay → deterministic execution + GC). | **LIVE** |
| `x/encmempool` (real encrypted mempool / MEV resistance) | No encryption, no threshold key, no MEV resistance; needs keypers (Shutter/Ferveo). | **ROADMAP** |
| `x/contest` | Ecosystem leaderboard: dev tx-volume points + tester UAW points, frozen at the Nov 11 2026 snapshot; budgets 150M (dev) / 100M (tester). Not a sale. | **LIVE** |
| `x/contest` (gas-sponsored dev sub-metric) | Only credits the genesis sponsor until self-serve paymaster ships. | **ROADMAP** |
| `x/netcap` | Net-seller cap on founder/foundation outbound transfers (two-hook: bank + EVM ante). | **LIVE** (testnet params; real mainnet cap ROADMAP) |
| Passkey / P-256 — `0x100` precompile | RIP-7212 secp256r1 precompile; sole entry in live `active_static_precompiles`. | **LIVE** |
| Passkey / P-256 — WebAuthn ante path | Verifies a P-256 WebAuthn assertion bound to SIGN_MODE_DIRECT sign bytes; `passkey_enabled=true`. Single-signer, ordered-tx only. | **LIVE** (testnet; audit-gated for mainnet) |
| `x/valgrant` (module logic) | Locked-grant validator bootstrap (issue / clawback / burn pool); compiled into the binary, proven 5/5 on staging. | **ROADMAP on live chain** (not in live genesis; default admin empty) |
| `0x900` valgrant admin precompile | issueGrant / clawback / burnPool; compiled in but **not** in live `active_static_precompiles`. | **ROADMAP on live chain** |

**BeginBlock order:** erc20 → feemarket → evm → **squeeze** → **gassponsor** → encmempool → distribution. So squeeze splits the prior block's fees, gassponsor then re-mints the pool to target, then distribution pays validators/delegators/community.

---

## 6. Validator model

The intended Limonata model is **apply, don't buy**. There is no public token sale, so you do not purchase a validator stake — you apply for one and receive a grant.

- **Apply-not-buy + locked, non-transferable grant.** An approved operator receives a `PermanentLockedAccount` grant (`x/valgrant`): locked principal you can **stake but never sell** (even after unbonding), plus a small liquid gas allowance from the reserve pool. **Status: built and proven on staging; NOT activated on the live testnet.** (ROADMAP on live chain.)
- **Keep the rewards.** The operator keeps the **liquid** staking rewards as compensation. **Honest caveat:** today x/mint inflation is 0 and fees are ~0, so those rewards are effectively **zero** right now; the reward stream becomes meaningful only with real fee volume or a future reward schedule. (Model property — LIVE in code; meaningful income — ROADMAP.)
- **Clawback-able.** Grants can be force-undelegated and swept by the admin (governance clawback is ROADMAP). (Admin-key clawback — LIVE in code, ROADMAP on live chain.)
- **Burn-at-taper.** As operators move to self-funding, bootstrap grants are meant to be **burned** (never returned to the foundation, so no one profits from capitalizing validators). Only a **manual** admin-gated `BurnPool` exists today; automatic taper-driven burn is **ROADMAP**.

**Current live reality:** the testnet runs a **single validator**. The "team delegates stake to your validator" flow is a **manual interim** and second-validator enablement/join automation is **not yet built**. Note: prior public copy described a "team keeps the stake, no yield" delegation model — that is the interim, and it conflicts with the built `x/valgrant` "you hold and keep the rewards" model. The repo and site should describe one model with its status.

---

## 7. Consolidated LIVE vs ROADMAP

### LIVE (on `limonata_10777-1` today)

| Capability | Evidence |
|---|---|
| ~0.3s single-slot BFT finality (`timeout_commit=300ms`, `mempool.type=app`) | regenesis script seds config.toml |
| Full EVM + 18-dp `aLIMO`, base fee effectively 0 | live feemarket params |
| EVM protocol-paid gas, 10 LIMO/day per-account baseline | `x/gassponsor` keeper; live genesis baseline_daily=1e19 |
| Self-refilling 200M gas pool (mint backstop, no withdraw path) | `x/gassponsor/abci.go`; pre-funded 200M |
| Squeeze fee split 40% burn / 10% pool / ~50% validators each block | `x/squeeze/keeper`; abci_test |
| Cosmos-SDK gasless via one paymaster policy (1 LIMO/tx, any sender/msg) | `x/paymaster/ante`; live genesis policy |
| 0-balance account can send a zero-priced EVM tx (free because base fee ≈ 0) | base_fee truncates to 0 |
| `x/encmempool` commit-reveal ordering primitive | wired in app.go; live genesis seeds it |
| `x/contest` leaderboard (Nov 11 2026 snapshot, 150M/100M budgets) | wired; live params |
| `x/netcap` net-seller cap (testnet params, two-hook) | live genesis netcap params |
| P-256 / RIP-7212 precompile at `0x100` | sole live `active_static_precompiles` entry |
| WebAuthn / passkey ante path (`passkey_enabled=true`) | wired ante/cosmos.go; live genesis |
| 1B cap table + founder/foundation compressed testnet vesting | live genesis balances + vesting accounts |

### ROADMAP (built-but-not-activated, or not built)

| Capability | Why not live |
|---|---|
| Any dApp actually sponsored **uncapped** | `contest.showcase=[]`; needs admin `MsgRegisterShowcase`; website approve writes only a local file |
| 0-balance account sending a **sponsored (positive-fee)** EVM tx | blocked by pre-sponsorship affordability gate; sender must hold ≥ `gasLimit*gasFeeCap+value` |
| Developer self-serve / self-funded sponsorship | `x/paymaster` scaffold; no MsgServer; no per-sponsor accounting/caps |
| `x/encmempool` real anti-MEV / encryption | no threshold key; needs keypers |
| `x/valgrant` activated on live chain + `0x900` precompile active | absent from live genesis; default admin empty; `0x900` not in active precompiles |
| valgrant burn-at-taper, governance clawback | only manual `BurnPool` + admin clawback exist |
| Second validator / join automation | not built; testnet runs one validator |
| Real mainnet net-seller cap number | placeholder 1M LIMO/month, counsel-gated |
| Mainnet genesis (real key custody, governed reserve, 12mo+36mo vesting) | only testnet (MODE default) is genesis'd live |
| 250M airdrop distribution + Mainnet Genesis | future |

---

### Footnotes on honesty

- **"Gasless" is a subsidy, not magic.** The protocol or a developer absorbs the cost; mint-backstop refill makes it mildly inflationary.
- **A zero-balance wallet cannot transact with a positive gas price.** It needs a one-time dust balance it never spends. This is why the faucet exists.
- **Total supply is ~1B but not hard-capped** while gas-pool minting is on.
- **The validator reward stream is ~0 today.** It is a property of the model, not current income.
