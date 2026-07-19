<p align="center">
  <img src="assets/limonata-logo.png" alt="Limonata" width="160" />
</p>

<h1 align="center">Limonata</h1>

<p align="center"><b>The highway, not the cars.</b><br/>
An EVM Layer&nbsp;1 on Cosmos SDK - single-slot finality (~2s), near-zero fees, gasless UX, and a full EVM toolkit. What you build on top is yours.</p>

---

## What is Limonata?

Limonata is a Cosmos SDK + [cosmos/evm](https://github.com/cosmos/evm) Layer&nbsp;1. `LIMO` is a **pure network-utility coin** - gas + staking only. No yield, no promise of value: it's the fuel to use and secure the network.

| | |
|---|---|
| Chain ID (EVM) | `10777` (`0x2a19`) |
| Cosmos chain-id | `limonata_10777-1` |
| Native coin | `LIMO` (base denom `aLIMO`, 18 decimals) |
| Block time | ~2s, single-slot BFT finality |
| Tooling | Solidity / MetaMask / Hardhat / Foundry / Viem - unchanged |

**Public testnet:** RPC `https://rpc.limonata.xyz` · Explorer `https://explorer.limonata.xyz` · Faucet `https://faucet.limonata.xyz` · Site `https://limonata.xyz`

## Start here

- 🚀 **Deploy a gasless contract in 5 minutes** → [limonata-quickstart](https://github.com/Limonata-Blockchain/limonata-quickstart)
- ⚡ **One-click gasless demo** (send a real tx, pay zero gas) → [limonata.xyz/demo](https://limonata.xyz/demo)
- 💬 **Join the community** → [Discord](https://discord.gg/vzbJ5u5Kex)

> 📖 **How Limonata works**: [Testnet (live today)](HOW_IT_WORKS.md) explains what runs now and how to use it; [the mainnet plan](HOW_IT_WORKS_MAINNET.md) covers the cap table, vesting, the net-seller cap, the inflation/sybil economics ([ECONOMICS.md](ECONOMICS.md)), and what is still being built.

## What's different (the custom modules)

Limonata adds protocol-level modules on top of cosmos/evm:

- **`x/squeeze`** - every block, transaction fees are split in BeginBlock (governable params): 60% to validators (compensation for operating a node), 20% burned, 20% recycled into the gas pool.
- **`x/gassponsor`** - the protocol pays EVM gas from a self-refilling on-chain pool: a **uniform** flat per-account daily budget (1 LIMO/day) for every account holding a minimum of LIMO - users and apps alike - plus a one-shot onboarding grant for a fresh zero-balance wallet. Anti-farm: the **hold requirement** makes each wallet cost locked capital and a **hard daily mint cap** ceilings total new supply. The subsidy is mildly inflationary (not zero) but hard-capped; see [`ECONOMICS.md`](ECONOMICS.md).
- **`x/sponsorpool`** (precompile `0x901`) - **developer-funded gas**: a dev deposits LIMO earmarked for their contract; transactions to that contract are sponsored from the deposit until it runs dry. Permissionless, withdrawable, and non-inflationary (the dev funds it, not new mint).
- **`x/paymaster`** - gasless sponsorship for Cosmos-SDK transactions from the same pool.
- **`x/encmempool`** - an encrypted mempool with a **transparent validator DKG** for anti-MEV. Validators generate and hold the threshold encryption key together, on-chain and inside consensus (via CometBFT vote extensions) - there is no trusted dealer, no keyper committee, no coordinator, and the master secret never exists in one place. Validators take part simply by running the node binary (no daemon, no account, no fees, no key setup). Decryption power is **stake-weighted**: reconstruction needs shares representing >2/3 of committee stake, it **fails closed** if concentration would let a sub-2/3-stake operator or coalition decrypt alone, and it **auto-rekeys** on membership change or stake drift >5%. Decrypted transactions execute on-chain at reveal. Live and exercised end-to-end on testnet.
- **`x/contest`** - on-chain Ecosystem Development Contest leaderboard.
- **`x/valgrant`** - locked-grant validator bootstrap pool (`PermanentLockedAccount` grants + clawback) so new operators can bond without buying in.
- **`x/netcap`** - a net-seller cap: a rolling-window rate-limit on outbound transfers from designated addresses, enforced on **both** Cosmos sends (bank `SendRestriction`) and native EVM transfers (ante decorator), since EVM value transfers bypass `x/bank`.
- On-chain **P-256 / WebAuthn (passkey)** signature path: sign Cosmos transactions with Face ID / a fingerprint, verified natively (no seed phrase, no extension). Developer guide: [`PASSKEY.md`](PASSKEY.md). Live demo: [limonata.xyz/passkey](https://limonata.xyz/passkey).
- A `valgrant` admin precompile (`0x900`).

## Build & run

Requires Go 1.24+ and a C toolchain (CGO).

```bash
make install            # builds & installs the `evmd` binary
evmd version
```

Genesis + a ~2s single-node testnet are produced by the scripts in this project's deployment tooling (see `limonata-genesis.sh`). Validator onboarding: see the [validator guide](https://limonata.xyz/VALIDATOR.md).

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
