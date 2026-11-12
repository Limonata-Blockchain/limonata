# Limonata Economics: Steady-State Inflation and the Sybil Surface

> Audience: counsel and prospective holders. This document is deliberately conservative. Numbers labeled UPPER BOUND are worst-case, not forecasts. Capabilities are tagged LIVE (running on the public testnet `limonata_10777-1` today) or ROADMAP (built but not activated, or not built). Regulatory-adjacent points are marked "validate with counsel."
>
> Companion: `HOW_IT_WORKS.md` (mechanics and the LIVE/ROADMAP module map). This file is the quantitative economic model only.

LIMO is a pure network-utility coin (gas and staking only): no yield, dividend, profit-share, governance vote, or equity. Nothing here changes that. This document quantifies one specific cost: the newly minted LIMO that funds "free gas," and how that quantity is bounded. Validate any token-characterization or disclosure conclusions with counsel.

---

## 1. The single core claim

The chain pays users' gas from a 200,000,000 LIMO pool that is re-minted to target every block. Sponsoring gas therefore mints LIMO. Historically the amount minted was bounded only by (number of accounts) x (per-account daily allowance), and because accounts are free to create, inflation and the sybil surface were the same unbounded quantity.

That is no longer true. Two LIVE mechanisms now bound the mint on two independent axes:

> **1. A per-account hold requirement (`HoldMinimum`).** Only accounts holding at least `HoldMinimum` LIMO earn the daily free-gas budget. To farm N maxed accounts you must immobilize `N x HoldMinimum` of real capital. Sybil now has a per-account capital cost, not a ~0 cost.
>
> **2. A hard daily mint cap (`RefillDailyMintCap`).** The pool-refill mint is ceilinged per UTC day. Once the day's minted total hits the cap, no further sponsored gas mints new supply that day — worst-case inflation is bounded **independent of N**.

The subsidy is still mildly inflationary and the supply is **not hard-capped** — do not read this as zero inflation. But steady-state inflation is now bounded by an explicit, governable ceiling rather than by the open account count.

---

## 2. Assumptions

| # | Assumption | Source / status |
|---|---|---|
| A1 | Total supply baseline = 1,000,000,000 LIMO (1e27 aLIMO) | Live genesis; x/mint inflation = 0, max_supply = 0 (uncapped) |
| A2 | Gas-pool target = floor = MinPoolBalance = 200,000,000 LIMO | One param is both floor and top-up target |
| A3 | Squeeze split: 20% burn (only burn on chain) / 20% pool recycle / 60% validators | `x/squeeze` (BurnBps=2000, GrantBps=2000; remainder 60% left for distribution). Governable params. |
| A4 | Refill mints deficit-to-target each block, but never past `RefillDailyMintCap` for the UTC day, and never removes excess (asymmetric) | `x/gassponsor` early-return when bal >= target; per-day mint accumulator vs cap |
| A5 | Per-account allowance = FLAT `DailyBudget` = 1 LIMO/day, granted only to accounts holding >= `HoldMinimum` (1 LIMO) — users and apps alike (uniform mode) | Live genesis; replaces the prior history-scaled formula |
| A6 | Allowance keyed on (UTC-day, sender address); eligibility gated on current held balance vs `HoldMinimum` | `x/gassponsor` keeper (`effectiveAllowance`) |
| A7 | A cold 0-balance never-seen account gets a one-shot LIFETIME `OnboardingGrant` (0.05 LIMO) so its first tx works with no faucet; once exhausted it must hold >= `HoldMinimum` to earn `DailyBudget` | `x/gassponsor` `tryOnboarding` (0x05 counter) |
| A8 | The daily counter debits on gas-LIMIT * price, but only gas-USED * price actually nets into fee_collector and is minted/burned. Scenarios assume gas-used ~ gas-limit (worst case); with unused gas, realized mint is below 0.6 * budget | `x/vm` VerifyFee uses ethTx.Gas(); refund returns unused gas to the pool |
| A9 | Live base fee truncates to 0; sponsorship engages only on a positive fee | Live feemarket params; keeper requires amt > 0 |

---

## 3. Per-fee supply deltas (derivation)

Trace one effective fee `X` (the post-refund amount that actually nets into `fee_collector`, identical in form for both paths) through the block pipeline. Squeeze runs before gassponsor, both before distribution. Under the 20/20/60 split: burn = 0.2X, pool recycle = 0.2X, validators = 0.6X.

**Sponsored fee.** The pool pays X into `fee_collector` (a transfer, supply unchanged; pool sits at T - X). Next block squeeze burns 0.2X (supply -0.2X), recycles 0.2X to the pool (pool now T - 0.8X), and leaves 0.6X for validators. Gassponsor sees the pool below target and mints the 0.8X deficit (supply +0.8X), restoring T. Net = -0.2X + 0.8X = **+0.6X**. (Gross mint 0.8X, burn 0.2X, net +0.6X.)

This +0.6X is an **UPPER BOUND**, valid only when (a) the pool is exactly at target with no carried excess and (b) the day's `RefillDailyMintCap` has not been reached. The refill never removes excess above target (A4), so recycled grants from user-paid fees accumulate as a permanent buffer that absorbs later sponsored deficits; when the cap binds, the deficit is not minted at all. Both push the realized sponsored coefficient below +0.6, down toward -0.2.

**User-paid / self-funded fee.** The user (or a developer's `x/sponsorpool` escrow deposit) moves pre-existing balance X into `fee_collector` (transfer, no mint). Next block squeeze burns 0.2X (supply -0.2X), recycles 0.2X (pre-existing supply relocated, neutral), leaves 0.6X for validators. The 0.2X pushes the pool to T + 0.2X >= target, so gassponsor mints nothing. Net = **-0.2X** (exact). The 20% squeeze burn is the only burn on chain. (Developer-escrow-funded contract gas is therefore non-inflationary: it is deposited supply, not new mint.)

---

## 4. The general model

Let `F` = total annual gas fees (LIMO, effective post-refund value into `fee_collector`) and `s` = sponsored fraction, s in [0,1].

```
net_supply_change (annual) = 0.6*(s*F) - 0.2*((1-s)*F) = F * (0.8*s - 0.2)
annual inflation r = net_supply_change / 1e9 = F * (0.8*s - 0.2) / 1e9
```

- **Break-even:** set `0.8*s - 0.2 = 0` -> `s* = 1/4 = 25%`. Above 25% sponsored, net inflationary (at the upper bound); below it, the burn dominates and it is net deflationary. Because the realized sponsored coefficient drops below 0.6 once an excess buffer builds or the daily mint cap binds, **25% is a lower bound on the true break-even**; the real break-even fraction is somewhat higher in mixed traffic.
- **Design case `s -> 1`:** `r ~ 0.6 * F / 1e9` (sponsored coefficient 0.6, upper bound), **and additionally ceilinged by `RefillDailyMintCap`**: annual mint <= `365 * RefillDailyMintCap` regardless of F or account count.
- **Validity caveat:** the aggregate formula holds while the pool is kept at target with no carried excess and below the daily mint cap. Once excess builds or the cap binds, true net inflation is lower than this upper bound.

### A note on the denominator (important)

`r` above is computed against **total** supply (~1,000,000,000 LIMO), which includes the dev premine, the foundation allocation, and the locked PermanentLockedAccount validator grants, none of which circulate. Dilution of the **liquid / circulating** float is larger in the same proportion that locked + premine is of total. Whatever the headline `r` against total supply, the sell-pressure on the circulating float, and the dilution felt by an actual holder, is proportionally higher. Any holder-facing inflation figure should state both the total-supply rate and the circulating-float rate. (Defining "circulating" precisely is itself a disclosure decision: validate with counsel.)

---

## 5. Scenario table

All rows assume `s ~ 1` (sponsored path), so net mint = `0.6 * F`. Maxed rows compute F directly from the live uniform budget: `F = accounts x 1 LIMO/day x 365`. Per A8, all rows are upper bounds (they assume gas-used ~ gas-limit; unused gas is refunded to the pool and lowers realized mint). Every maxed account must hold >= `HoldMinimum` (1 LIMO), so the maxed rows also state the capital an attacker must immobilize; and every row is additionally ceilinged by `RefillDailyMintCap` (A4), not shown.

| Scenario | Accounts | Sponsored gas/acct/day | Annual sponsored gas F | Net mint (LIMO) | Inflation vs total supply | Capital immobilized |
|---|---:|---:|---:|---:|---:|---:|
| Organic-light | 10,000 | 0.1 LIMO | 365,000 | +219,000 | +0.022% | — |
| Organic-heavy | 100,000 | 1 LIMO (full budget) | 36,500,000 | +21,900,000 | +2.19% | (held by real users) |
| Sybil-budget-maxed | 100,000 | 1 LIMO (full budget) | 36,500,000 | +21,900,000 | +2.19% | 100,000 LIMO locked |
| Sybil-at-scale | 1,000,000 | 1 LIMO (full budget) | 365,000,000 | +219,000,000 | +21.9% | 1,000,000 LIMO locked |

Reference point: one maxed account = 365 LIMO/yr sponsored gas -> +219 LIMO minted -> +0.0000219% inflation. **About 45,700 maxed accounts mint 1% of total supply per year — but to run them the attacker must lock ~45,700 LIMO (`HoldMinimum` each), and the daily mint cap ceilings the total regardless.** Organic-heavy and sybil-budget-maxed differ only in intent, not mechanics; the protocol cannot tell them apart and mints for both, but both now pay the hold requirement and both hit the same daily ceiling. Against the circulating float (smaller than total supply), every percentage above is correspondingly larger.

---

## 6. Sybil cost analysis

Sybil is no longer ~free. Each farmed account now carries a real, non-recoverable-while-farming capital cost:

- **Account creation = 0.** Accounts are lazily created in the ante with no fee; the keypair is generated offline for free.
- **But eligibility requires holding `HoldMinimum` LIMO (1 LIMO live).** `effectiveAllowance` returns 0 for any account holding less than `HoldMinimum`. The held balance is a reusable float (never debited when sponsored), but it must be *held* — so to run N maxed accounts an attacker must simultaneously immobilize `N x HoldMinimum` LIMO. That capital is not spent, but it is locked out of any other use for as long as the farm runs. This is the "skin-in-the-game" gate.
- **Cold-start onboarding is one-shot and tiny.** A brand-new 0-balance account gets a single lifetime `OnboardingGrant` (0.05 LIMO), enough for its first few transactions with no faucet, then must hold `HoldMinimum` to continue. It cannot be recycled per day.
- **The daily mint cap bounds the aggregate.** Even if an attacker funds many accounts, `RefillDailyMintCap` ceilings the total new supply the refill can mint per UTC day. Beyond the cap, sponsored gas is served from the existing pool buffer (no new mint) until it drains, at which point sponsorship for the day degrades rather than minting without limit.

So per fresh keypair an attacker farms up to 1 LIMO/day of sponsored gas (net +0.6 LIMO/day of new supply at the +0.6X upper bound) **only while locking >= 1 LIMO of real capital**, and the sum across all keypairs is hard-capped by the daily mint ceiling. The open, cost-free sybil surface of the earlier design is closed on both the per-account (capital) and the aggregate (mint-cap) axes.

Residual notes: allowance keys are still keyed on sender address per UTC-day and old-day keys are not deleted (a minor state-bloat side effect of high-volume traffic, not an inflation lever).

---

## 7. The synthesis: inflation is now bounded, not open-ended

Combining sections 4-6:

```
uncapped form:   F_max = N * DailyBudget * 365,   r ~ 0.6 * N * 365 / 1e9  (per account: +219 LIMO/yr)
bounded by:      (a) capital gate   -> each of the N accounts locks HoldMinimum LIMO
                 (b) hard mint cap  -> annual mint <= 365 * RefillDailyMintCap, independent of N
```

Inflation used to be set purely by N (the sybil surface) with nothing bounding it. It is now bounded from two directions at once: a per-account capital cost that makes large N expensive, and an absolute daily mint ceiling that makes worst-case inflation independent of N. It is still not zero, and the ceiling is a governance parameter (choose it deliberately — section 9), but "inflation = unbounded sybil surface" is no longer the correct description of the live binary.

**The base-fee tension (the remaining trade-off under the current design).**

- **base_fee ~ 0 (live today):** an organic zero-priced tx is free-by-truncation, not sponsored. It debits no daily counter and triggers no mint, so realized inflation from organic traffic is ~0 today. But there is also **no price-based anti-spam**. An attacker can still engage minting on demand by setting a positive gas price (the base fee is ~0, so the price is pure tip) — but now only from accounts that hold `HoldMinimum`, and only up to the daily mint cap.
- **base_fee > 0 (positive fee floor, likely needed for mainnet anti-spam):** every positive-fee tx is sponsored-and-minted (up to the cap). A fee floor does not create the attack; it additionally forces organic zero-priced traffic into the minted path too.

You still cannot get price-based anti-spam and zero sponsored-mint at the same time; but with the hold requirement and the daily mint cap, the *magnitude* of that mint is now bounded rather than open-ended.

---

## 8. Mitigations (LIVE vs ROADMAP)

1. **Per-account hold requirement (`HoldMinimum`) - LIVE. Capital gate.** Only accounts holding >= `HoldMinimum` (1 LIMO live) earn `DailyBudget`. Farming N accounts immobilizes `N x HoldMinimum` of real capital, converting the previously free sybil surface into a capital-bounded one.
2. **Hard daily mint cap (`RefillDailyMintCap`) - LIVE. Absolute ceiling.** The refill may not mint past a fixed aLIMO total per UTC day. This bounds worst-case inflation **independent of N** — the circuit-breaker that earlier revisions listed as "not built" now exists.
3. **Uniform daily budget (`DailyBudget`) - LIVE. Simplicity + predictability.** Every eligible account gets the same flat 1 LIMO/day (users and apps alike), replacing the prior history-scaled curve. Combined with the hold gate, per-account yield is fixed and legible; lowering it linearly lowers inflation.
4. **Developer-escrow (self-funded) sponsorship - LIVE, non-inflationary.** Beyond the free daily budget, apps fund their users' gas from an `x/sponsorpool` deposit (precompile 0x901). That gas is paid from deposited supply, not new mint, so it does not inflate. Moving heavy sponsorship onto this path puts an accountable payer (who buys LIMO to fund it) in front of the mint. The approved-dApp path (uncapped but admin-gated, bounded per-tx by `DappPerTxFeeCap`) is the other routed option; both are preferable to open baseline draw at scale.
5. **Asymmetric pool buffer - LIVE, structural dampener.** Excess above target is never clawed back, so recycled user-paid grants accumulate and absorb later sponsored deficits, pulling realized inflation below the +0.6X upper bound.
6. **One-shot onboarding grant (`OnboardingGrant`) - LIVE, bounded.** A cold wallet's first-tx grant is a single lifetime 0.05 LIMO, not a renewable per-day allowance, so it cannot be farmed by cycling fresh keypairs — its total draw across all accounts is itself counted against the daily mint cap.
7. **Non-zero mainnet fee floor - ROADMAP DECISION.** Restores economic anti-spam, but forces organic traffic into the minted path. Must be chosen jointly with the budget, the hold minimum, and the mint cap.

---

## 9. Open before-mainnet decisions (quantitative)

1. **Target steady-state inflation cap.** Choose the acceptable annual % (for example <= 2%/yr), stated against both total and circulating supply, and set `RefillDailyMintCap` to enforce it: `365 * RefillDailyMintCap <= cap * 1e9`. The mechanism now exists; the number is a governance choice. Disclosure of any cap to holders: validate with counsel.
2. **Daily budget size.** Set the mainnet per-account `DailyBudget`. Together with expected genuine account count it sets organic mint: `0.6 * N_genuine * DailyBudget * 365`.
3. **Hold minimum.** Set `HoldMinimum` — the per-account capital an honest user must hold and a sybil must lock. Higher tightens the sybil gate but raises the entry bar for real users.
4. **Fee floor.** Decide whether to set a positive minimum gas price and its value, accepting that any positive floor forces organic traffic into the minted path.
5. **Pool refill policy.** Decide whether to claw back excess above target (symmetric refill) in addition to the daily mint cap already in place.
6. **Sponsorship routing at launch.** Decide how much load sits on the open per-account budget vs the developer-escrow / approved-dApp routed paths from mainnet genesis.

---

## 10. Honest disclaimers

- "Gasless" is a subsidy, not magic. The mint-backstop refill makes sponsored gas mildly inflationary up to +0.6X per fee.
- The +0.6X sponsored delta is an UPPER BOUND; realized inflation is lower when an excess buffer is carried or the daily mint cap binds, and organic inflation is ~0 today only because the live base fee is ~0. Attacker-driven minting is still possible today by setting a positive gas price — but only from accounts holding `HoldMinimum`, and only up to `RefillDailyMintCap`.
- Steady-state inflation is now **bounded** on two axes (per-account hold requirement + hard daily mint cap) rather than being an open-ended function of account count. It is **not zero**, and the supply is **not hard-capped** while gas-pool minting is on. Do not represent it as zero-inflation or fixed-supply.
- Inflation `r` is quoted against total supply (~1B). Dilution of the circulating float is proportionally larger because the premine and locked validator grants do not circulate.
- Contract gas funded via the developer escrow (`x/sponsorpool`, precompile 0x901) is paid by the developer's deposit, not by new mint, so it is non-inflationary.
- Validators receive 60% of real fees under the split. This is **service compensation for operating a node**, not yield, APR, dividend, or a return on a purchase — LIMO carries no such promise. Today fees are ~0, so that compensation is effectively zero and only becomes meaningful with real fee volume.
- Testnet tokens are valueless. Any statement about mainnet token value, distribution, or characterization should be validated with counsel.
</content>
</invoke>
