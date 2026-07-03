# On-chain markets — permissionless bonding-curve infrastructure

Limonata's testnet ships a **permissionless, admin-less token factory + bonding-curve market** as native on-chain infrastructure. Anyone — a trading terminal, a wallet, a bot, a community frontend — can launch tokens and route trades against it directly. There is no operator to ask, no API key, no allowlist: it's a verified contract on a public chain, and this page is the integration manual.

> **Neutral infrastructure, plainly stated.** Limonata (the team) does not operate a trading
> frontend on this contract. It is documented here the way a chain documents any precompile:
> so builders can integrate it. Testnet tokens have **no value**; anyone offering a trading
> product on top of this infrastructure is responsible for their own users and compliance.

---

## The factory

| | |
|---|---|
| Contract | `SqueezeFactory` — **`0x39915b0B24Fe5d234FF6D8C65926c06c9962a8e4`** |
| Source | **verified on the explorer** → [read it](https://explorer.limonata.xyz/address/0x39915b0B24Fe5d234FF6D8C65926c06c9962a8e4) (solc 0.8.24, via-IR) |
| Admin functions | **none** — no owner, no pause, no upgrade; the treasury address is immutable |
| Chain | `limonata_10777-1` (EVM **10777**), RPC `https://rpc.limonata.xyz` |

**Curve model** (pump.fun-style virtual-reserve constant product): every launched token has `SUPPLY = 1B` minted to the factory and trades against native LIMO on `x·y = K` with `VIRT_LIMO = 30 LIMO` of virtual depth. **1% fee** on each buy and sell, split half to the token's creator, half to the (immutable) treasury — claimable, never automatic. A creator's launch-buy is capped at **20% of supply** (anti-snipe). At **85 LIMO** of real reserve the pool emits `Graduated` and sets a flag; trading continues (nothing is frozen).

---

## Write API

```solidity
// launch a token; optional msg.value performs the creator's initial buy (≤ 20% of supply)
function create(string name_, string symbol_) payable returns (address token);

// trade — slippage + deadline are enforced ON-CHAIN (reverts "slippage" / "expired")
function buy(address token, uint256 minTokensOut, uint256 deadline) payable;
function sell(address token, uint256 amount, uint256 minLimoOut, uint256 deadline);

// fees accrued to you (creator or treasury): pull-claim
function claimFees();
```

Notes integrators actually need:

- **`sell` needs no ERC-20 approval** — the factory is a trusted spender of its own tokens.
- Buys send native LIMO as `msg.value`. Compute `minTokensOut` from `quoteBuy` minus your slippage tolerance; quotes are **fee-inclusive** (what you'd receive).
- The launched tokens are plain ERC-20s (`transfer/approve/balanceOf...`), so wallets and portfolio UIs handle them out of the box. Transfers *to* the curve address are blocked (reserve-accounting safety) — trade via `buy`/`sell` only.

## Read API

```solidity
function tokenCount() view returns (uint256);
function tokensPage(uint256 offset, uint256 limit) view returns (address[]);
function price(address token) view returns (uint256);            // LIMO per token, 1e18-scaled
function quoteBuy(address token, uint256 limoIn) view returns (uint256 tokensOut);
function quoteSell(address token, uint256 tokIn) view returns (uint256 limoOut);
function poolInfo(address token) view returns (
  address creator, uint256 realLimo, uint256 reserveTok,
  uint256 priceX1e18, uint256 marketCapX1e18, uint256 createdAt,
  bool graduated, uint256 gradLimo
);
```

## Events (for charts, tapes, and indexing)

```solidity
event Launched(address indexed token, address indexed creator, string name, string symbol, uint256 supply, uint256 createdAt);
event Trade(address indexed token, address indexed trader, bool isBuy, uint256 limoAmount, uint256 tokenAmount, uint256 priceX1e18, uint256 ts);
event Graduated(address indexed token, uint256 realLimo, uint256 ts);
event FeesClaimed(address indexed who, uint256 amount);
```

`Trade.priceX1e18` is the post-trade price — one event stream is enough to build candles, volume, and per-trader stats. (Node note: `eth_getLogs` on the public RPC is capped at ~10k blocks per query — window your scans.)

---

## Why integrate here: every trade is gasless

Limonata sponsors gas **at consensus level** — nothing to integrate ([the 10-minute gasless guide](https://limonata.xyz/how-it-works/gasless)). Any account holding ≥ 1 LIMO gets ~2,500 free calls/day, so a terminal listing these markets gives its users **fee-free trading UX out of the box**: quotes, buys, sells, claims — the protocol pays the gas. The value leg is never sponsored (a buy still spends the user's LIMO — that's the trade itself), and the subsidy is bounded and farm-resistant by design.

## Quick smoke test

```bash
F=0x39915b0B24Fe5d234FF6D8C65926c06c9962a8e4
RPC=https://rpc.limonata.xyz
cast call $F "tokenCount()(uint256)" --rpc-url $RPC
T=$(cast call $F "tokensPage(uint256,uint256)(address[])" 0 1 --rpc-url $RPC | tr -d '[]' | cut -d, -f1)
cast call $F "poolInfo(address)(address,uint256,uint256,uint256,uint256,uint256,bool,uint256)" $T --rpc-url $RPC
cast call $F "quoteBuy(address,uint256)(uint256)" $T 1000000000000000000 --rpc-url $RPC   # 1 LIMO in
```

---

*Chain: `limonata_10777-1` (EVM 10777) · [Gasless for devs](https://limonata.xyz/how-it-works/gasless) · [Explorer](https://explorer.limonata.xyz) · [Discord](https://discord.gg/vzbJ5u5Kex)*
