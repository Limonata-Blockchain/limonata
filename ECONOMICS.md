# Limonata Economics: Steady-State Inflation and the Sybil Surface

> Audience: counsel and prospective holders. This document is deliberately conservative. Numbers labeled UPPER BOUND are worst-case, not forecasts. Capabilities are tagged LIVE (running on the public testnet `limonata_10777-1` today) or ROADMAP (built but not activated, or not built). Regulatory-adjacent points are marked "validate with counsel."
>
> Companion: `HOW_IT_WORKS.md` (mechanics and the LIVE/ROADMAP module map). This file is the quantitative economic model only.

LIMO is a pure network-utility coin (gas and staking only): no yield, dividend, profit-share, governance vote, or equity. Nothing here changes that. This document quantifies one specific cost: the newly minted LIMO that funds "free gas," and why that quantity is, by construction, the chain's sybil-attack surface. Validate any token-characterization or disclosure conclusions with counsel.

---

## 1. The single core claim

The chain pays users' gas from a 200,000,000 LIMO pool that is re-minted to target every block. Sponsoring gas therefore mints LIMO. The amount minted is capped only by how much sponsored gas is consumed, and sponsored gas is capped only by (number of accounts) x (per-account daily baseline). Because accounts are effectively free to create, the result is:

> **Steady-state inflation and the sybil-attack surface are the same quantity.** There is no separate inflation parameter in the code; inflation is a direct linear function of how many accounts draw sponsored gas, and today nothing in the binary bounds that count.

---

## 2. Assumptions

| # | Assumption | Source / status |
|---|---|---|
| A1 | Total supply baseline = 1,000,000,000 LIMO (1e27 aLIMO) | Live genesis; x/mint inflation = 0, max_supply = 0 (uncapped) |
| A2 | Gas-pool target = floor = MinPoolBalance = 200,000,000 LIMO | One param is both floor and top-up target |
| A3 | Squeeze split: 40% burn (only burn on chain) / 10% pool recycle / ~50% validators | `x/squeeze` (BurnBps=4000, GrantBps=1000) |
| A4 | Refill mints deficit-to-target each block; never removes excess (asymmetric) | `x/gassponsor` early-return when bal >= target |
| A5 | Per-account baseline = 10 LIMO/day (live); source default = 1 LIMO/day | Live genesis baseline_daily=1e19 |
| A6 | Baseline keyed only by (UTC-day, sender address); no account-age or history weighting | `x/gassponsor` keeper; no scaling field exists |
| A7 | Account creation cost = 0; the required balance is a reusable dust float, never debited when sponsored | Lazy ante creation; affordability gate is proof-of-funds only |
| A8 | The daily counter debits on gas-LIMIT * price, but only gas-USED * price actually nets into fee_collector and is minted/burned. Scenarios assume gas-used ~ gas-limit (worst case); with unused gas, realized mint is below 0.5 * baseline | `x/vm` VerifyFee uses ethTx.Gas(); refund returns unused gas to the pool |
| A9 | Live base fee truncates to 0; sponsorship engages only on a positive fee | Live feemarket params; keeper requires amt > 0 |

---

## 3. Per-fee supply deltas (derivation)

Trace one effective fee `X` (the post-refund amount that actually nets into `fee_collector`, identical in form for both paths) through the block pipeline. Squeeze runs before gassponsor, both before distribution.

**Sponsored fee.** The pool pays X into `fee_collector` (a transfer, supply unchanged; pool sits at T - X). Next block squeeze burns 0.4X (supply -0.4X) and recycles 0.1X to the pool (pool now T - 0.9X). Gassponsor sees the pool below target and mints the 0.9X deficit (supply +0.9X), restoring T. Net = -0.4X + 0.9X = **+0.5X**.

This +0.5X is an **UPPER BOUND**, valid only when the pool is exactly at target with no carried excess. The refill never removes excess above target (A4), so recycled grants from user-paid fees accumulate as a permanent buffer. In mixed traffic that buffer absorbs later sponsored deficits, so those sponsored fees mint less than 0.9X (down to zero), and the realized sponsored coefficient falls from +0.5 toward -0.4.

**User-paid fee.** The user moves pre-existing balance X into `fee_collector` (transfer, no mint). Next block squeeze burns 0.4X (supply -0.4X) and recycles 0.1X (pre-existing supply relocated, neutral). The 0.1X pushes the pool to T + 0.1X >= target, so gassponsor mints nothing. Net = **-0.4X** (exact). The 40% squeeze burn is the only burn on chain.

---

## 4. The general model

Let `F` = total annual gas fees (LIMO, effective post-refund value into `fee_collector`) and `s` = sponsored fraction, s in [0,1].

```
net_supply_change (annual) = 0.5*(s*F) - 0.4*((1-s)*F) = F * (0.9*s - 0.4)
annual inflation r = net_supply_change / 1e9 = F * (0.9*s - 0.4) / 1e9
```

- **Break-even:** set `0.9*s - 0.4 = 0` -> `s* = 4/9 ~ 44.4%`. Above 44.4% sponsored, net inflationary (at the upper bound); below it, the burn dominates and it is net deflationary. Because the realized sponsored coefficient drops below 0.5 once an excess buffer builds, **4/9 is a lower bound on the true break-even**; the real break-even fraction is somewhat higher in mixed traffic.
- **Design case `s -> 1`:** `r ~ 0.5 * F / 1e9` (sponsored coefficient 0.5, upper bound).
- **Validity caveat:** the aggregate formula holds while the pool is kept at target with no carried excess. Once excess builds, true net inflation is lower than this upper bound.

### A note on the denominator (important)

`r` above is computed against **total** supply (~1,000,000,000 LIMO), which includes the dev premine, the foundation allocation, and the locked PermanentLockedAccount validator grants, none of which circulate. Dilution of the **liquid / circulating** float is larger in the same proportion that locked + premine is of total. Whatever the headline `r` against total supply, the sell-pressure on the circulating float, and the dilution felt by an actual holder, is proportionally higher. Any holder-facing inflation figure should state both the total-supply rate and the circulating-float rate. (Defining "circulating" precisely is itself a disclosure decision: validate with counsel.)

---

## 5. Scenario table

All rows assume `s ~ 1` (sponsored path), so net mint = `0.5 * F`. Maxed (sybil) rows compute F directly from the live baseline: `F = accounts x 10 LIMO/day x 365`. Per A8, all rows are upper bounds (they assume gas-used ~ gas-limit; unused gas is refunded to the pool and lowers realized mint).

| Scenario | Accounts | Sponsored gas/acct/day | Annual sponsored gas F | Net mint (LIMO) | Inflation vs total supply |
|---|---:|---:|---:|---:|---:|
| Organic-light | 10,000 | 0.1 LIMO | 365,000 | +182,500 | +0.018% |
| Organic-heavy | 100,000 | 1 LIMO | 36,500,000 | +18,250,000 | +1.83% |
| Sybil-baseline-maxed | 100,000 | 10 LIMO (full baseline) | 365,000,000 | +182,500,000 | +18.25% |
| Sybil-at-scale | 1,000,000 | 10 LIMO (full baseline) | 3,650,000,000 | +1,825,000,000 | +182.5% (supply grows ~2.8x in one year) |

Reference point: one maxed account = 3,650 LIMO/yr sponsored gas -> +1,825 LIMO minted -> +0.0001825% inflation. **About 5,480 maxed accounts mint 1% of total supply per year.** Organic-heavy and sybil-baseline-maxed differ only in per-account draw; the protocol cannot tell them apart and mints for both. Against the circulating float (smaller than total supply), every percentage above is correspondingly larger.

---

## 6. Sybil cost analysis

The attacker's recoverable cost per farmed account is **~0**:

- **Account creation = 0.** Accounts are lazily created in the ante with no fee; the keypair is generated offline for free.
- **Per-tx fee within baseline = 0.** Sponsored txs are paid by the pool; the user balance is never touched.
- **The held balance is a reusable float, never spent.** The affordability gate requires `balance >= gasLimit*gasFeeCap + value` for the largest single tx, but the same balance satisfies every sponsored tx that day because it is never debited. The single-tx floor is ~21,000 aLIMO (~2.1e-14 LIMO) for one minimal transfer. But to actually **max** the 10 LIMO/day counter you need many txs (the counter debits gasLimit*price), and at a feasible volume of ~1e5 txs/day the per-tx price, and therefore the reusable float you must hold, is on the order of **~1e-4 LIMO**. That float is roughly **0.001% of the 10 LIMO/day of sponsored gas it unlocks**. The single-tx 21,000-aLIMO figure is the floor for one transaction only, not the cost to max the baseline.

So per fresh keypair an attacker farms up to ~10 LIMO/day of freshly minted sponsored gas (net +5 LIMO/day of new supply at the +0.5X upper bound) while holding a ~1e-4 LIMO float they never spend. N keypairs farm ~10N LIMO/day. The only limit is the attacker's willingness to generate keypairs.

Two structural facts compound this: the allowance is keyed solely on sender address with no account-age or creation cost (the core sybil lever), and old-day allowance keys are never deleted (a minor state-bloat side effect of high-volume farming).

---

## 7. The synthesis: inflation = sybil surface

Combining sections 4-6:

```
F_max = (farmable accounts N) * baseline * 365
r_max ~ 0.5 * N * 3650 / 1e9 = N * 1.825e-6   (vs total supply)
```

Every farmable account is exactly one account's worth of minted inflation. Inflation is not set by a parameter; it is set by N.

**The base-fee tension (the unavoidable trade-off under the current design).**

- **base_fee ~ 0 (live today):** an organic zero-priced tx is free-by-truncation, not sponsored. It debits no daily counter and triggers no mint, so realized inflation from organic traffic is ~0 today. But there is also **no price-based anti-spam**. Critically, **minting is already farmable on demand today**: an attacker simply sets a positive gas price (the base fee is ~0, so the price is pure tip), sponsorship engages, and the pool re-mints. No fee-floor change is needed to exploit it.
- **base_fee > 0 (positive fee floor, likely needed for mainnet anti-spam):** every positive-fee tx is sponsored-and-minted. A fee floor does not create the attack; it **additionally forces organic zero-priced traffic into the minted path** too.

You cannot get price-based anti-spam and zero sponsored-mint at the same time while the baseline is a flat per-account allowance.

---

## 8. Mitigations (LIVE vs ROADMAP)

1. **History-scaled allowance - ROADMAP (DESIGNED, NOT BUILT). The linchpin.** Scale the per-account baseline by account age / tx-history / sustained min-balance so a fresh keypair gets ~0 allowance and only long-lived genuine accounts accrue it. This bounds F to genuine accounts and collapses the sybil surface. Verified absent in code: the Params struct has exactly four fields (enabled, baseline_daily, refill_enabled, min_pool_balance) with no scaling knob even reserved, and no account-age, first-seen, or history field exists. Matches the project note that the mainnet history-scaled rule is "designed not built." **Until this ships, the open baseline path should be treated as unbounded.**
2. **Lower mainnet baseline - ROADMAP DECISION.** Live is 10 LIMO/day; the source default is 1 LIMO/day. Lowering it linearly lowers per-account yield and inflation, but does not change the structural `N * baseline` form. A knob, not a fix.
3. **Non-zero mainnet fee floor - ROADMAP DECISION.** Restores economic anti-spam, but forces organic traffic into the minted path. Must be chosen jointly with the baseline and the history-scaling curve.
4. **Route sponsorship through approved-dApp / dev-funded models - CODE LIVE / USE ROADMAP.** The approved-dApp path is uncapped but admin-gated, with zero live registrations; the dev-funded paymaster is a scaffold with no message server. Moving sponsorship off the open baseline onto these models puts an accountable payer (who buys LIMO to fund it) in front of the mint.
5. **Asymmetric pool buffer - LIVE, structural dampener only.** Excess above target is never clawed back, so recycled user-paid grants accumulate and absorb later sponsored deficits, pulling realized inflation below the +0.5X upper bound. A mild natural dampener, not a control.
6. **Per-epoch mint cap / circuit-breaker - ROADMAP (NOT BUILT).** A hard ceiling per block/epoch would bound worst-case inflation independent of N. Nothing of the kind exists today.

---

## 9. Open before-mainnet decisions (quantitative)

1. **Target steady-state inflation cap.** Choose the acceptable annual % (for example <= 2%/yr), stated against both total and circulating supply. Currently UNBOUNDED in code. This budget constrains everything below. Disclosure of any cap to holders: validate with counsel.
2. **Baseline size.** Set the mainnet per-account daily allowance. Must satisfy `cap * 1e9 >= 0.5 * N_genuine * baseline * 365` for the expected genuine account count.
3. **Fee floor.** Decide whether to set a positive minimum gas price and its value, accepting that any positive floor forces organic traffic into the minted path.
4. **History-scaling curve.** Define `allowance(account) = f(age, tx-count, sustained min-balance, ...)`, the cold-start allowance for new accounts, and the cap. The linchpin; build before the open baseline path is safe at scale.
5. **Pool refill policy.** Decide whether to claw back excess above target (symmetric refill) and whether to add a hard per-epoch mint cap / circuit-breaker.
6. **Sponsorship routing at launch.** Decide whether the open per-account baseline path is enabled at mainnet genesis at all, or gated behind approved-dApp / dev-funded sponsorship from day one.

---

## 10. Honest disclaimers

- "Gasless" is a subsidy, not magic. The mint-backstop refill makes sponsored gas mildly inflationary up to +0.5X per fee.
- The +0.5X sponsored delta is an UPPER BOUND; realized inflation is lower when an excess buffer is carried, and organic inflation is ~0 today only because the live base fee is ~0. Attacker-driven minting is already possible today by setting a positive gas price.
- Inflation `r` is quoted against total supply (~1B). Dilution of the circulating float is proportionally larger because the premine and locked validator grants do not circulate.
- The steady-state inflation rate is NOT yet bounded in code. The flat baseline plus free accounts means worst-case inflation scales linearly with the number of farmable accounts.
- Total supply is ~1B but not hard-capped while gas-pool minting is on.
- Testnet tokens are valueless. Any statement about mainnet token value, distribution, or characterization should be validated with counsel.
