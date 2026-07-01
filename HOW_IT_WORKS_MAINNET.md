# How Limonata Works: The Mainnet Plan

> This is the plan for mainnet - how the coin is split, how "free gas" is paid for, and how validators join. For what runs **today**, see the [testnet page](/how-it-works). This is intent, not a promise. Tags: **BUILT** = the code exists and is proven on staging; **PLANNED** = not built yet.

---

## 1. The coin

`LIMO` is a pure **utility coin**: it pays for gas and for staking, nothing else. No yield, dividend, profit-share, governance share, or equity.

**Total supply at launch: 1,000,000,000 LIMO.** (It is not strictly fixed - the gas pool tops itself up by minting to keep transactions free; see section 3.)

---

## 2. Where the 1 billion LIMO goes

Think of it in **three groups**:

**① The team's share - 25%**
| Bucket | LIMO | |
|---|---:|---|
| Founder & core team | 100M | locked, vests over a 12-month cliff + 36 months |
| Foundation / treasury | 150M | same vesting; funds the project's operations |

**② Protocol pools - 25% (owned by no one; they run features)**
| Bucket | LIMO | |
|---|---:|---|
| Gas pool | 200M | pays for free ("gasless") transactions |
| Validator bootstrap pool | 50M | funds the locked validator grants (section 5) |

**③ Reserves & operations - 50%**
| Bucket | LIMO | |
|---|---:|---|
| Ecosystem & community reserve | 250M | for the ecosystem; allocation undecided, governed |
| Strategic reserve | 150M | long-term, governance-locked |
| Relayer / IBC float | 50M | pays cross-chain (IBC) relayers |
| Safety buffer | 50M | emergency fund (incidents, bugs) |

*(A tiny "genesis validator" account - about 10,000 LIMO - runs the very first block. It's a technical bootstrap, not anyone's wealth.)*

**The team cannot dump.** The founder and foundation coins are **locked**: nothing unlocks for 12 months, then it releases slowly over 36 months. On top of that, a rate-limit caps how much those wallets can ever send out per period. The premine is held, not sold.

---

## 3. "Free gas" - who pays, and inflation

Free gas isn't actually free - **a pool pays for it.** When the network covers your transaction, the cost comes out of the **200M Gas Pool**, and the pool refills itself by **minting a little new LIMO**.

So two honest points:
- "Gasless" is a **subsidy**, and it adds **mild inflation** over time. The supply is **not hard-capped**.
- The thing that keeps inflation in check is a **limit on how much free gas each account gets** - lots for long-lived real accounts, ~0 for fresh throwaway accounts - so it can't be farmed by spinning up wallets. **(BUILT.)**

Staking inflation is **off** by default; the only minting is the gas-pool refill. The full math is in [`ECONOMICS.md`](ECONOMICS.md).

---

## 4. Decentralization - measurable, on a schedule

The chain is honest that it is **team-operated today**. But the mechanisms that make decentralization real are now **built** (proven on staging, to ship in the mainnet binary):

- **The validator set grows on a schedule:** it starts at **16** curated operators and governance raises the cap over time → **16 → 30 → 50 → 100**.
- **No one can dominate:** each validator's voting power is **capped at 10%** at the consensus layer (`x/vpcap`) - even if their stake is bigger, their power isn't.
- **The team's control shrinks, and it's measured on-chain:** the network's decentralization (Nakamoto coefficient, the foundation's voting-power share) is **computed every block**. The foundation's share falls on a published ladder: **<15% → <10% → <5% → <3%**.
- **The admin key is handed to governance:** sensitive roles can be **rotated or revoked by on-chain vote**, not by one key.

---

## 5. Becoming a validator (the heart of the model)

The model is **apply, don't buy.** There's no token sale - you don't purchase a validator stake, you **apply** for one.

- An approved operator gets a **locked grant**: stake you can use to secure the network, but can **never sell**, and that can be clawed back. You never buy or hold LIMO to take part.
- You earn a **share of network fees + your commission** - pay for operating a node, not a return on a purchase. *(Honest caveat: today fees are ~0 and staking inflation is off, so rewards are effectively zero; they only become real with fee volume or a future schedule.)*
- As new operators self-fund their own stake later, the leftover bootstrap pool is **burned** - never returned to the team.

**How the ~16 genesis operators are chosen:** by **application and vetting** - a proven track record, solid infrastructure (uptime, monitoring), and diversity (no single country or cloud dominates). Permissioned at genesis, opening up as the set grows. The foundation runs one or two; the rest are independent.

**The steps:**
1. **Apply** with your operator and infrastructure details.
2. **Get selected** - seats are allocated.
3. **Send a fresh address** - you generate a new account.
4. **Receive your grant** - a locked bonding stake + a small gas allowance (since there's no public faucet at mainnet, that allowance is what lets you pay the first transaction fee).
5. **Run `create-validator`** from the granted account.
6. **Validate and earn** for operating the node.

The **grant always comes first** - it funds the account you validate from.

---

## 6. What's built vs. still planned

| | Status |
|---|---|
| Per-validator 10% voting-power cap (`x/vpcap`) | **BUILT** |
| On-chain decentralization KPIs (`x/valgrant`) | **BUILT** |
| Governance can rotate/revoke admin roles | **BUILT** |
| Locked validator grants (`x/valgrant`, `0x900`) | **LIVE** - a real external operator already validates on a grant |
| Self-funded gas sponsorship (`x/sponsorpool`, `0x901`) | **LIVE** |
| History-scaled (anti-sybil) gas allowance | **LIVE** |
| Mainnet genesis (real key custody, governed reserve, vesting) | **PLANNED** |
| Encrypted mempool / real anti-MEV | **BUILT** - threshold-encrypted mempool (2-of-3 keypers), proven end-to-end + full gov-upgrade dry-run; deploying to **testnet** at block 766558 (upgrade `encmempool-threshold-vpcap-v1`). [Guide](/how-it-works/encrypted-mempool). |

---

## 7. The legal note

A few things are deliberately **undecided and gated on counsel**, because they're where a token could be mischaracterized:

- Any **ecosystem or community distribution** from the reserve, if and when made, would be a deliberate, counsel-reviewed decision. No method, amount, or eligibility is promised here.
- The **ecosystem contest** is being structured so recognition doesn't read as compensation or an investment offer.
- Acquisition surfaces are geo-fenced away from Canada, the US, and China, with the francophone-Europe market in mind.

**Nothing on this page is an offer, solicitation, or promise of any asset or return.**

---

*This is the plan. What runs today is on the [testnet page](/how-it-works). The full inflation and sybil model is in [`ECONOMICS.md`](ECONOMICS.md). Chain source (Apache-2.0): https://github.com/Limonata-Blockchain/limonata*
