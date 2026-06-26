# How Limonata Works: The Mainnet Plan

> This page describes where Limonata is going: what is designed but not yet live, the token economics behind "free gas," and the decisions still open before a mainnet launch. For what is actually running today, see [How it works: testnet](/how-it-works). This page is intent, and it is conservative. Items are tagged **BUILT** (the code exists and is proven on staging, but is not activated on the live chain) or **PLANNED** (not built yet). Nothing here is a promise.

---

## 1. What is designed but not yet activated

| Capability | Status | Note |
|---|---|---|
| Uncapped sponsorship for featured dApps | **BUILT, not wired live** | The protocol path exists, but no dApp is registered on-chain and the approval is admin-gated. Today all sponsored gas flows through the per-account baseline. |
| Developer self-funded sponsorship | **LIVE (2026-06-26)** | `x/sponsorpool` + precompile `0x901`: a developer deposits LIMO earmarked for their contract; its transactions are sponsored from that deposit (permissionless, withdrawable, non-inflationary because the dev funds it). |
| `x/valgrant` validator grants + `0x900` admin precompile | **BUILT, not on live chain** | Locked-grant validator bootstrap, proven on staging, absent from the live genesis. See section 6. |
| Encrypted mempool / real anti-MEV | **PLANNED** | Today `x/encmempool` is a commit-reveal ordering primitive only, no encryption or threshold key. |
| Second validator / join automation | **PLANNED** | The live testnet runs a single validator. |
| History-scaled gas allowance | **LIVE (2026-06-26)** | The per-account daily allowance is now a 0.1 LIMO/day cold-start + a bonus that grows with held LIMO, capped at 10/day - the key anti-sybil and inflation-control mechanism (see section 3). |
| On-chain governance (replace the admin key) | **PLANNED** | Today one admin key gates dApp approval; decentralizing that is on the roadmap. |
| Mainnet genesis | **PLANNED** | Real key custody, a governed reserve, and a 12-month + 36-month vesting schedule. Only the testnet is genesis'd today. |
| 250M airdrop distribution | **PLANNED, method undecided** | The largest single allocation; its method is a deliberate decision, gated on counsel (see section 7). |

---

## 2. The coin and supply at mainnet

`LIMO` is a pure network-utility coin: gas and staking only. No yield, dividend, profit-share, governance vote, or equity.

- **Total supply: 1,000,000,000 LIMO.** `x/mint` staking inflation is 0. **Caveat:** the supply is not strictly hard-capped, because the gas pool refills by minting (see section 3).

### Cap table (planned mainnet genesis)

| Bucket | LIMO | % | Form |
|---|---:|---:|---|
| Airdrop reserve | 250,000,000 | 25% | distribution method undecided (section 7) |
| Gas pool | 200,000,000 | 20% | module account, refill target |
| Foundation / treasury | 150,000,000 | 15% | vesting |
| Strategic reserve | 149,990,000 | ~15% | governed reserve key |
| Founder / core team | 100,000,000 | 10% | vesting |
| Relayer / IBC float | 50,000,000 | 5% | liquid |
| Safety buffer | 50,000,000 | 5% | liquid |
| Valgrant bootstrap pool | 50,000,000 | 5% | module account |
| Genesis validator | 10,000 | ~0% | liquid |

### Vesting and anti-dump

- **Founder (100M) and Foundation (150M)** vest on a **12-month cliff + 36 monthly steps**. Nothing is spendable until the cliff elapses. (On the testnet this is compressed to seconds for observability.)
- **Net-seller cap (`x/netcap`, live on testnet):** a rolling-window rate-limit on outbound transfers from the founder and foundation, enforced on both Cosmos sends and native EVM transfers. The **mainnet window and cap are a placeholder** and must be set with counsel.

---

## 3. The economics: who pays for "free gas," and inflation

This is the honest accounting of "free gas" over time. Headline numbers are upper bounds; the one mechanism that would bound them (history-scaled allowance) is planned, not built. The full quantitative model is in [`ECONOMICS.md`](ECONOMICS.md).

**Per fee, net supply change (code-verified):**
- Sponsored fee: **+0.5X** (an upper bound; a buffer in the pool can pull this toward -0.4X).
- User-paid fee: **-0.4X** (the 40% squeeze burn is the only burn on chain).

**Annual:** with `F` = total annual gas fees and `s` = sponsored fraction:
```
inflation r = F * (0.9*s - 0.4) / 1e9
```
Break-even at `s = 44.4%`; the design runs at `s -> 1` (gasless), so `r ~ 0.5 * F / 1e9`.

| Scenario | Accounts | Gas/acct/day | Inflation/yr (vs total supply) |
|---|---:|---:|---:|
| Organic-light | 10,000 | 0.1 LIMO | +0.018% |
| Organic-heavy | 100,000 | 1 LIMO | +1.83% |
| Sybil, baseline maxed | 100,000 | 10 LIMO | +18.25% |
| Sybil, at scale | 1,000,000 | 10 LIMO | +182.5% |

**The core finding: steady-state inflation IS the sybil surface.** The pool re-mints to cover all sponsored gas, and sponsored gas is capped only by (number of accounts) x (per-account baseline). Accounts are effectively free to create, so inflation scales linearly with how many accounts draw the allowance. About 5,480 maxed accounts mint 1% of total supply per year, and more against the circulating float (the 1B includes the premine and locked grants, which do not circulate). Today realized inflation is ~0 because the live base fee is ~0, but minting is already exploitable by setting a positive gas price.

**The linchpin (PLANNED):** a **history-scaled allowance** that gives a fresh account ~0 allowance and only grows it for long-lived genuine accounts. This bounds the sybil surface and therefore the inflation. Until it is built, the open per-account baseline path should be treated as unbounded.

---

## 4. The open decisions before mainnet

These are quantitative choices to make (with counsel where relevant) before a mainnet launch:

1. A target steady-state inflation cap (for example <= 2%/yr).
2. The per-account daily gas baseline (live is 10 LIMO/day; the code default is 1).
3. Whether to set a positive minimum gas fee for anti-spam, and its value.
4. The history-scaling curve (how allowance grows with account age and history).
5. The pool refill policy (claw back excess above target? a per-epoch mint cap?).
6. Whether the open per-account baseline path is even enabled at mainnet genesis, or sponsorship is gated behind approved-dApp and developer-funded models from day one.

---

## 5. Decentralization roadmap

The chain is honest that it is team-operated today: a single validator, team-set genesis, and dApp sponsorship approval gated by one admin key (no on-chain governance yet). The path to "credibly neutral" runs through:

- single validator -> multiple independent operators (second-validator enablement, join automation);
- one admin key -> on-chain governance for sensitive roles (dApp approval, parameters);
- activating `x/valgrant` so validator onboarding is by application and grant, not by team delegation.

---

## 6. Validating at mainnet (the valgrant model)

The intended model is **apply, do not buy.** There is no public token sale, so you do not purchase a validator stake; you apply for one.

- An approved operator receives a **locked, non-transferable** grant: you can stake it to secure the network, but you can never sell it, and it is clawback-able.
- You keep the **liquid rewards** your validator earns. **Honest caveat:** today inflation is off and fees are ~0, so those rewards are effectively zero; the stream only becomes meaningful with real fee volume or a future schedule. It is a property of the model, not current income.
- As operators move to self-funding, the bootstrap grants are meant to be **burned**, never returned to the foundation, so no one profits from capitalizing validators.

**Status:** the `x/valgrant` module and its `0x900` admin precompile are built and proven on staging, but **not yet activated on the live chain** (which uses the interim team-delegation model described on the [testnet page](/how-it-works)). Burn-at-taper and governance clawback are planned.

---

## 7. Regulatory-gated items (airdrop and contest)

The two places where potentially valuable LIMO is distributed in connection with activity are the highest regulatory exposure, so they are deliberately undecided and gated on counsel:

- The **250M airdrop** method is not set. The method (retrospective and no-strings, versus conditioned on activity) largely determines how the token is characterized. No method is promised.
- The **ecosystem contest** distribution is being structured so that recognition does not read as compensation or an investment offer.
- The project geo-fences acquisition surfaces away from Canada, the United States, and China, and is structuring for the francophone-Europe market. Nothing on this page is an offer, solicitation, or promise of any asset or return.

---

*This is the plan. What runs today is on the [testnet page](/how-it-works). The full inflation and sybil model is in [`ECONOMICS.md`](ECONOMICS.md). Chain source (Apache-2.0): https://github.com/Limonata-Blockchain/limonata*
