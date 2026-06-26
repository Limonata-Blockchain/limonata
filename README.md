<p align="center">
  <img src="assets/limonata-logo.png" alt="Limonata" width="160" />
</p>

<h1 align="center">Limonata</h1>

<p align="center"><b>The highway, not the cars.</b><br/>
An EVM Layer&nbsp;1 on Cosmos SDK - single-slot finality (~0.3s), near-zero fees, gasless UX, and a full EVM toolkit. What you build on top is yours.</p>

---

## What is Limonata?

Limonata is a Cosmos SDK + [cosmos/evm](https://github.com/cosmos/evm) Layer&nbsp;1. `LIMO` is a **pure network-utility coin** - gas + staking only. No yield, no promise of value: it's the fuel to use and secure the network.

| | |
|---|---|
| Chain ID (EVM) | `10777` (`0x2a19`) |
| Cosmos chain-id | `limonata_10777-1` |
| Native coin | `LIMO` (base denom `aLIMO`, 18 decimals) |
| Block time | ~0.3s, single-slot BFT finality |
| Tooling | Solidity / MetaMask / Hardhat / Foundry / Viem - unchanged |

**Public testnet:** RPC `https://rpc.limonata.xyz` · Explorer `https://explorer.limonata.xyz` · Faucet `https://faucet.limonata.xyz` · Site `https://limonata.xyz`

> 📖 **How Limonata works**: [Testnet (live today)](HOW_IT_WORKS.md) explains what runs now and how to use it; [the mainnet plan](HOW_IT_WORKS_MAINNET.md) covers the cap table, vesting, the net-seller cap, the inflation/sybil economics ([ECONOMICS.md](ECONOMICS.md)), and what is still being built.

## What's different (the custom modules)

Limonata adds protocol-level modules on top of cosmos/evm:

- **`x/squeeze`** - every block, transaction fees are split in BeginBlock: 50% to validators, 40% burned, 10% recycled into the gas pool.
- **`x/gassponsor`** - the protocol pays EVM gas from an on-chain pool: a per-account daily allowance + uncapped for approved dApps, refilled by the squeeze recycle (and a mint backstop). Users transact without holding LIMO.
- **`x/paymaster`** - gasless sponsorship for Cosmos-SDK transactions from the same pool.
- **`x/encmempool`** - a commit-reveal mempool (anti-MEV foundation).
- **`x/contest`** - on-chain Ecosystem Development Contest leaderboard.
- **`x/valgrant`** - locked-grant validator bootstrap pool (`PermanentLockedAccount` grants + clawback) so new operators can bond without buying in.
- **`x/netcap`** - a net-seller cap: a rolling-window rate-limit on outbound transfers from designated addresses, enforced on **both** Cosmos sends (bank `SendRestriction`) and native EVM transfers (ante decorator), since EVM value transfers bypass `x/bank`.
- On-chain **P-256 / WebAuthn (passkey)** signature path + a `valgrant` admin precompile.

## Build & run

Requires Go 1.24+ and a C toolchain (CGO).

```bash
make install            # builds & installs the `evmd` binary
evmd version
```

Genesis + a 0.3s single-node testnet are produced by the scripts in this project's deployment tooling (see `limonata-genesis.sh`). Validator onboarding: see the [validator guide](https://limonata.xyz/VALIDATOR.md).

## Add Limonata to your wallet

Click **"Connect to RPC"** on [limonata.xyz](https://limonata.xyz), or add it manually:

- Network name: `Limonata Testnet` · RPC: `https://rpc.limonata.xyz` · Chain ID: `10777` · Symbol: `LIMO` · Explorer: `https://explorer.limonata.xyz`

## Become a validator

On Limonata, **validating is access, not capital.** There is no public token sale, so you don't *buy* a validator stake - you **apply** for one.

- Approved operators receive a **locked, non-transferable** bonding grant (`x/valgrant`): you can stake it to secure the network, but you can never sell it (even after unbonding), and it is **clawback-able** by governance.
- You keep the **rewards** your validator earns - that's liquid, your compensation for operating. *(Honest caveat: today `x/mint` staking inflation is off and fees are ~0, so those rewards are effectively zero right now - the stream only becomes meaningful with real fee volume or a future schedule. It's a property of the model, not current income.)*
- By design, as operators move to self-funding, the bootstrap grants are **burned** - never returned to the foundation, so no one profits from capitalizing validators.

The goal: *"anyone can run a validator"* is real, not nominal - without a token sale.

> **Status:** the `x/valgrant` module + the `0x900` admin precompile are **built and proven on staging, but NOT yet activated on the live testnet** - which currently runs a single validator with the team delegating stake manually as an interim. Live grant activation, burn-at-taper, and KPI-gated grant issuance are all on the roadmap (counsel-gated for mainnet). See [`HOW_IT_WORKS_MAINNET.md`](HOW_IT_WORKS_MAINNET.md) §6 for the full validator model and live-vs-roadmap breakdown.

See the [validator guide](https://limonata.xyz/VALIDATOR.md) to run a node.

## Built on cosmos/evm

Limonata is derived from [cosmos/evm](https://github.com/cosmos/evm) (Apache License 2.0). The upstream README is preserved as [`README.cosmos-evm.md`](README.cosmos-evm.md). See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## License

Apache License 2.0 - see [`LICENSE`](LICENSE).
