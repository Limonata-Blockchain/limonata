# Gasless for developers — the 10-minute guide

**TL;DR: deploy any contract on Limonata and your users already have free gas. There is nothing to integrate.** No paymaster contract to deploy, no relayer to run, no SDK to import, no allowlist to join. Sponsorship is decided inside the chain's consensus (the ante handler), based only on the *sending account* — so it works identically from MetaMask, a Face ID passkey wallet, an embedded wallet, a bot, or any third-party frontend that lists the chain.

> **Status:** the uniform free-gas model below ships in this week's governance upgrade
> (`gassponsor-security-caps-v1`). The current chain already sponsors holders under an
> older formula, so gasless works today — the numbers below are the new, final regime.

---

## What your users get, automatically

| Account | Free gas | That's roughly |
|---|---|---|
| Holds ≥ 1 LIMO | **1 LIMO of gas per day** | ~2,500 contract calls/day (400k gas @ 1 gwei) |
| Brand-new, 0 balance | **one-shot starter grant** (0.05 LIMO, lifetime) | ~125 first calls — works with **no faucet** |
| Past the daily budget | pays own gas — **0.0004 LIMO** per 400k-gas call | or *your* deposit covers it (see 0x901 below) |

Two honest rules:

- **Value is never sponsored.** Free gas covers *gas*. A transaction that sends LIMO still requires the sender to hold that LIMO. Approvals, claims, game moves, swaps-of-tokens-already-owned: all fine from a nearly empty wallet.
- **It's bounded, not infinite.** The daily budget requires *holding* LIMO (farming costs locked capital per wallet) and a chain-wide daily mint cap ceilings the whole subsidy. Fees still exist (1 gwei floor) — they're just paid by the protocol within the budget.

---

## Quickstart: deploy on Limonata

Network: **chain id 10777**, RPC `https://rpc.limonata.xyz`, explorer `https://explorer.limonata.xyz`, faucet `https://faucet.limonata.xyz` (testnet LIMO).

Foundry:

```bash
forge create src/MyApp.sol:MyApp \
  --rpc-url https://rpc.limonata.xyz \
  --private-key $PK
```

Hardhat (`hardhat.config.js`):

```js
networks: {
  limonata: { url: 'https://rpc.limonata.xyz', chainId: 10777, accounts: [PK] },
}
```

That's it. Any account that holds ≥ 1 LIMO can now call your contract ~2,500×/day for free, and a brand-new wallet can make its first calls with nothing at all.

**See it yourself:** send a 0-value call from a funded account with a normal 1-gwei gas price, then check the balance — unchanged. The receipt shows a real `gasUsed`; the protocol's gas pool paid the fee in the same block.

---

## The prepaid gas card: covering your users beyond the free tier

If your app gets busy — a user burns through their personal 2,500 calls/day — you can cover the overage **from a developer deposit earmarked for your contract**. This is the `x/sponsorpool` precompile at:

```
0x0000000000000000000000000000000000000901
```

ABI (no contract to deploy — it's built into the chain):

```solidity
function deposit(address target, uint256 amount) external;        // pull LIMO from your wallet into your app's gas escrow (NON-payable)
function withdraw(address target, uint256 amount) external;       // reclaim unused escrow (only what you contributed)
function escrowOf(address target) external view returns (uint256);
function contributionOf(address sponsor, address target) external view returns (uint256);
```

One call funds it (amounts in wei, 1 LIMO = 1e18):

```bash
# fund 50 LIMO of gas for YOUR_CONTRACT's users
cast send 0x0000000000000000000000000000000000000901 \
  "deposit(address,uint256)" $YOUR_CONTRACT 50000000000000000000 \
  --rpc-url https://rpc.limonata.xyz --private-key $PK

# check the balance
cast call 0x0000000000000000000000000000000000000901 \
  "escrowOf(address)(uint256)" $YOUR_CONTRACT \
  --rpc-url https://rpc.limonata.xyz
```

ethers v6:

```js
const sponsor = new ethers.Contract(
  '0x0000000000000000000000000000000000000901',
  ['function deposit(address,uint256)', 'function withdraw(address,uint256)',
   'function escrowOf(address) view returns (uint256)'],
  wallet,
);
await sponsor.deposit(MY_CONTRACT, ethers.parseEther('50'));
```

Semantics worth knowing:

- `deposit` is **non-payable** — it pulls `amount` from your wallet balance (don't send `msg.value`).
- Every transaction *to your contract* draws its gas from the escrow while it lasts; when it runs dry, users fall back to their own daily budget, then to self-pay.
- Deposits are **permissionless** (anyone can sponsor any contract), **withdrawable** (up to your own contribution and the remaining escrow), and **non-inflationary** — the dev funds it, the protocol mints nothing for it.
- At 1 gwei, **1 LIMO of escrow ≈ 2,500 user calls** at 400k gas. 50 LIMO covers ~125k calls.

---

## Users without a wallet at all: Face ID

Limonata accounts can be **passkey smart accounts** — created and signed with Face ID / fingerprint, no seed phrase, no extension, verified on-chain by the native P-256 precompile (`0x100`). Combined with free gas, a first-time user goes from *nothing* to *transacting* in seconds. Try it at [limonata.xyz/passkey](https://limonata.xyz/passkey); integration guide: [/how-it-works/passkey](https://limonata.xyz/how-it-works/passkey).

---

## FAQ

**Do I need to register my app somewhere?** No. The baseline budget is universal. The 0x901 escrow is permissionless. (A separate curated "featured dApp" lane exists with its own per-tx cap, but you don't need it.)

**Does a frontend/terminal that lists Limonata need to integrate anything?** No — sponsorship is consensus-level and sender-based. If a trading terminal lists the chain, every trade its users sign is eligible for the same free gas as everyone else, with zero work on their side.

**What about my app's own hot wallet / relayer accounts?** They're accounts like any other: hold ≥ 1 LIMO and they get the same 1 LIMO/day budget.

**Can this be farmed?** Each farming wallet must *hold* LIMO (locked capital), the subsidy is capped per account per day, and a hard chain-wide daily mint cap bounds the total. Past the caps, gas is simply paid — nothing breaks.

**Is the gas really free, or deferred?** Free for the user, paid by the protocol's on-chain gas pool within hard caps (partly recycled from real fees, the shortfall minted under a daily ceiling — net-negligible at real usage, deflationary once apps self-fund). Nothing here is a rebate, a reward, or anything yield-like: it's fee abstraction, not a benefit that accrues to holders.

---

*Chain: `limonata_10777-1` (EVM 10777) · [How it works](https://limonata.xyz/how-it-works) · [Explorer](https://explorer.limonata.xyz) · [Discord](https://discord.gg/vzbJ5u5Kex)*
