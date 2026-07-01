# Signing with a passkey (Face ID / fingerprint) on Limonata

Limonata can verify **WebAuthn passkey** signatures natively. A passkey is a P-256
(secp256r1) key created and held inside a device secure element (Apple Secure Enclave,
Android StrongBox, Windows Hello, or a security key). The biometric (Face ID, Touch ID,
fingerprint) never leaves the device; it only unlocks the key so it can sign. Limonata's
ante handler checks the assertion on-chain, so a user can transact with **no seed phrase
and no browser extension**.

This document is the developer guide: how it works, the exact wire format, and how to add
"sign with Face ID" to your own app.

There is a live, working demo at **[limonata.xyz/passkey](https://limonata.xyz/passkey)**.

---

## Two ways to use passkeys on Limonata

There are two distinct integrations. Pick based on whether you want an EVM `0x`
account (visible in MetaMask + the EVM explorer) or a native Cosmos account.

- **A) Smart account (EVM `0x`)** - recommended for user wallets. The passkey owns a
  small contract wallet at a deterministic `0x` address. It shows in the EVM explorer,
  can be watched in MetaMask, holds LIMO, and calls any contract. The on-chain WebAuthn
  check uses the `0x100` precompile. A relayer EOA submits and pays for the tx; the user
  only signs a WebAuthn challenge and pays no gas.
- **B) Native Cosmos passkey account** - lower-level. The passkey IS a Cosmos
  `secp256r1` account (`cosmos1...`), verified by the chain's ante. No contract, but the
  account is Cosmos-only (not in MetaMask / the EVM explorer).

Section A is below; section B (the native path) follows it.

---

## A) Smart account (EVM 0x) - recommended

### Contracts

`PasskeyAccount` is a minimal contract wallet that stores the owner passkey public key
(P-256 x,y) and exposes `execute(to, value, data, auth)`. It authorizes the call by
recomputing the operation challenge and verifying the WebAuthn assertion with the
`WebAuthn` library, which calls the native RIP-7212 precompile at `0x100`. A
`PasskeyAccountFactory` deploys accounts at a CREATE2 address derived purely from the
public key, so the address is known (and fundable) before deployment.

The challenge bound by the signature is:

```
challenge = keccak256(abi.encode(block.chainid, account, nonce, to, value, keccak256(data)))
```

so a signature cannot be replayed across chains, accounts, nonces, or calls. Anyone
(a relayer) may submit the tx; only the passkey holder can authorize it.

Live factory on `limonata_10777-1`: `0x55052a71aacddee0282F74bcC0BAE7B0Df9fae9b`.
Contracts: `WebAuthn.sol`, `PasskeyAccount.sol`, `PasskeyAccountFactory.sol`.

### Who pays gas (and the `payable` confusion)

In plain EVM, gas is **always** charged to the EOA that signs and originates the
transaction (`tx.origin`) - never to a contract's balance, no matter how much it holds or
whether any function is `payable`. A `PasskeyAccount` is a contract, so it can never be a
transaction's `from`; and a passkey user has no EOA at all, only a WebAuthn signature. So a
**relayer EOA submits the `execute()` call and pays the gas**. The passkey signature
authorizes the call (the relayer cannot forge it), and that is what makes a relayer safe.

Three separate things, easy to conflate:

- **Gas** (`gasUsed x gasPrice`): paid by the **relayer EOA** (the faucet key here). The
  chain base fee is `0` and the relayer uses a tiny `1000` wei gas price, so the fee is
  ~0 and the user pays nothing. It is not reimbursed (plain relayer sponsorship), and is
  **unrelated to `payable`**.
- **Transfer value** (the LIMO delivered to `to`): comes from the **account's own balance**
  via `to.call{value: value}(data)` inside `execute()`. `execute()` is deliberately **not**
  `payable` - the relayer calls it with `value = 0`, so the relayer never supplies the
  amount; the account does. This is why the account must be funded first.
- **`receive() payable`**: only lets the account **receive** LIMO (be funded). `payable`
  governs receiving value, never paying gas, and is not on the `execute()` path.

> An account paying its own gas IS possible with ERC-4337 (an EntryPoint + paymaster pulls
> gas from the account/paymaster deposit) - but this design has no EntryPoint; it is a
> plain relayer.

### Relayer API (reference)

The reference relayer is the same Go service as the native path (`evmd/cmd/passkey-helper`);
the live demo proxies these under `/api/passkey/sa/*`:

```
POST /sa/address  { pubkey_b64 }                  -> { address, balance_limo, deployed, relayer }
POST /sa/fund     { pubkey_b64 }                  -> faucet-funds the 0x address (demo only)
POST /sa/prepare  { pubkey_b64, to, value_wei }   -> { address, nonce, needs_deploy, challenge_hex, challenge_b64 }
POST /sa/submit   { pubkey_b64, to, value_wei,    -> { ok, hash, status }   (deploys if needed, then execute)
                    authenticator_data_b64, client_data_json_b64,
                    challenge_index, type_index, r_hex, s_hex }
```

`pubkey_b64` is the passkey public key, either 65-byte uncompressed (`0x04||X||Y`, the
easiest to get from the browser) or 33-byte compressed.

### Browser flow

```js
// 1) Create the passkey; derive the uncompressed P-256 key from the SPKI (last 65 bytes).
const cred = await navigator.credentials.create({ publicKey: {
  challenge: crypto.getRandomValues(new Uint8Array(32)),
  rp: { name: "Your app", id: location.hostname },
  user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "user", displayName: "user" },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: { userVerification: "required" }, attestation: "none",
}});
const spki = new Uint8Array(cred.response.getPublicKey());
const pubkey_b64 = btoa(String.fromCharCode(...spki.slice(spki.length - 65))); // 0x04||X||Y

// 2) Prepare the operation -> get the challenge to sign.
const prep = await post("/api/passkey/sa/prepare", { pubkey_b64, to: recipient, value_wei: "10000000000000000" });
const challenge = Uint8Array.from(atob(prep.challenge_b64), c => c.charCodeAt(0));

// 3) Sign with Face ID.
const a = await navigator.credentials.get({ publicKey: {
  challenge, allowCredentials: [{ type: "public-key", id: credId }],
  userVerification: "required", rpId: location.hostname,
}});

// 4) WebAuthn returns a DER signature; parse to (r,s) and normalize to low-s, then submit.
//    (See the demo page source for parseDER + low-s; r_hex/s_hex are 0x 32-byte values.)
const [r_hex, s_hex] = rsFromDER(a.response.signature);
const cdj = new TextDecoder().decode(a.response.clientDataJSON);
await post("/api/passkey/sa/submit", {
  pubkey_b64, to: recipient, value_wei: "10000000000000000",
  authenticator_data_b64: b64(a.response.authenticatorData),
  client_data_json_b64: b64(a.response.clientDataJSON),
  challenge_index: cdj.indexOf('"challenge":"'),
  type_index: cdj.indexOf('"type":"webauthn.get"'),
  r_hex, s_hex,
});
```

Two browser-side gotchas, both handled in the demo source:
- **DER -> (r,s):** WebAuthn returns ASN.1 DER; extract the two integers, strip the
  leading zero byte, left-pad to 32 bytes.
- **low-s:** the EVM verifier rejects high-s for malleability; if `s > n/2`, use `n - s`.

---

## B) Native Cosmos passkey account

### The account model (read this first)

A passkey account is **not** an EVM `0x` account. It is a P-256 Cosmos-SDK account:

- **Key type:** `secp256r1` (P-256), the curve WebAuthn passkeys use.
- **Address:** a 32-byte ADR-28 address, bech32-encoded with the `cosmos` prefix
  (`cosmos1...`). It has no 20-byte EVM equivalent, so it is funded by a **Cosmos bank
  send**, not by an EVM transfer.
- **What it can do:** Cosmos-SDK messages (bank `MsgSend`, staking, gov, etc.).
- **What it cannot do:** be the `from` of a native EVM transaction. The EVM path uses
  `ethsecp256k1`; the passkey path is the Cosmos path.
- **Scope:** single-signer, ordered transactions, `SIGN_MODE_DIRECT` only. Multisig,
  unordered, and amino-JSON passkey txs are not supported.

Gas: the chain's minimum gas price is effectively zero, so a native Cosmos passkey tx costs
a negligible fee paid by the passkey account itself (the fee sits in `AuthInfo`; `/prepare`
with `"max"` sends the balance minus that fee). This differs from the EVM smart-account path
above, where a relayer EOA pays the gas. Protocol-level gas sponsorship is a separate,
not-yet-default feature; do not assume it.

---

## How verification works (the protocol side)

When the passkey param is enabled and a tx carries a passkey-packed signature, a dedicated
ante decorator runs (otherwise the standard signature path handles everything, so normal
txs are unaffected). The decorator:

1. Recomputes the tx's `SIGN_MODE_DIRECT` sign-bytes (these include chain-id, account
   number, and sequence).
2. Sets the expected challenge to `sha256(signBytes)`.
3. Verifies the WebAuthn assertion against the account's `secp256r1` public key.

Because the challenge is bound to the sign-bytes, an assertion cannot be replayed against a
different tx, chain, account, or sequence. User-verification (UV) is **required**: the
authenticator must report that the user passed a biometric or PIN, not just "user present".

The passkey path is **live on testnet and audit-gated before mainnet**.

---

## The wire format (the `WAS1` signature blob)

A passkey tx is a perfectly normal Cosmos `TxRaw`. The only special part is the single
entry in `signatures`: instead of a raw 64-byte signature, it is a packed WebAuthn
assertion that begins with the ASCII magic prefix `WAS1`:

```
WAS1 | uint32_be(len authenticatorData) | authenticatorData
     | uint32_be(len clientDataJSON)     | clientDataJSON
     | signature (ASN.1 DER ECDSA, exactly as a WebAuthn authenticator returns it)
```

The three pieces come straight from `navigator.credentials.get(...).response`:

- `authenticatorData` - raw bytes; the verifier checks the UP and UV flag bits.
- `clientDataJSON` - raw bytes; the verifier parses `type` (must be `webauthn.get`) and
  `challenge` (must equal `base64url(sha256(signBytes))`, no padding).
- `signature` - the DER signature. WebAuthn signs
  `sha256( authenticatorData || sha256(clientDataJSON) )`, which is exactly what the
  verifier recomputes.

The public key registered on the account is the **33-byte compressed P-256 key**, which is
the byte layout of a cosmos-sdk `secp256r1.PubKey`. The account's pubkey is set from the
tx's `SignerInfo` on the first transaction it sends, like any Cosmos account.

---

## Address derivation

The bech32 address is derived from the compressed P-256 key with the standard ADR-28 hash:

```
typ      = "cosmos.crypto.secp256r1.PubKey"
addr32   = sha256( sha256(typ) || compressedPubKey33 )      // 32 bytes, no truncation
address  = bech32("cosmos", addr32)                          // cosmos1...
```

In Go this is simply `sdk.AccAddress(secp256r1PubKey.Address())`.

---

## Integration path A: use a helper service (fastest)

The browser cannot, on its own, build byte-correct Cosmos `SIGN_MODE_DIRECT` sign-bytes,
so the simplest integration is a small backend that does the protobuf work while the
browser does only what must happen on-device (create the passkey, produce the assertion).
The reference helper is in this repo at `evmd/cmd/passkey-helper`; run your own instance
and expose these three calls. The live demo proxies to it under `/api/passkey/*`.

```
POST /prepare  { pubkey_b64, to, amount }
  -> { address, account_number, sequence, body_b64, authinfo_b64, challenge_b64 }
     (amount may be "max" to send the whole balance minus the fee)

POST /submit   { body_b64, authinfo_b64,
                 authenticator_data_b64, client_data_json_b64, signature_b64 }
  -> { ok, code, hash, log }

POST /fund     { pubkey_b64 }            // demo-only: seeds a new account from the faucet
  -> { funded_address, funder_address, amount, hash }
```

The browser half:

```js
// 1) Create the passkey (once). Face ID / fingerprint prompts here.
const cred = await navigator.credentials.create({ publicKey: {
  challenge: crypto.getRandomValues(new Uint8Array(32)),
  rp: { name: "Your app", id: location.hostname },
  user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "user", displayName: "user" },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],   // ES256 / P-256
  authenticatorSelection: { userVerification: "required" },
  attestation: "none",
}});

// The compressed P-256 key = last 65 bytes of the SPKI are 0x04||X||Y; compress to 33.
const spki = new Uint8Array(cred.response.getPublicKey());
const pt = spki.slice(spki.length - 65);                 // 0x04 || X(32) || Y(32)
const pub = new Uint8Array(33);
pub[0] = (pt[33 + 31] & 1) ? 0x03 : 0x02;                // prefix from Y parity
pub.set(pt.slice(1, 33), 1);                             // X
const pubkey_b64 = btoa(String.fromCharCode(...pub));
const credId = new Uint8Array(cred.rawId);

// 2) Ask the backend to build the tx, then sign the challenge on-device.
const prep = await (await fetch("/api/passkey/prepare", { method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ pubkey_b64, to: recipient, amount: "max" }) })).json();

const challenge = Uint8Array.from(atob(prep.challenge_b64), c => c.charCodeAt(0));
const a = await navigator.credentials.get({ publicKey: {
  challenge,                                              // = sha256(signBytes)
  allowCredentials: [{ type: "public-key", id: credId }],
  userVerification: "required", rpId: location.hostname,
}});
const r = a.response;
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

// 3) Submit. The backend packs the WAS1 blob and broadcasts.
const out = await (await fetch("/api/passkey/submit", { method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    body_b64: prep.body_b64, authinfo_b64: prep.authinfo_b64,
    authenticator_data_b64: b64(r.authenticatorData),
    client_data_json_b64: b64(r.clientDataJSON),
    signature_b64: b64(r.signature),
  }) })).json();
console.log(out.ok ? "tx " + out.hash : "rejected: " + out.log);
```

---

## Integration path B: build it fully client-side

If you would rather not run a backend, build the sign-bytes in the browser with cosmjs and
pack the blob yourself. The only P-256-specific parts are the pubkey Any and the address.

```js
import { makeAuthInfoBytes, makeSignDoc } from "@cosmjs/proto-signing";
import { TxBody, TxRaw, SignDoc } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { PubKey } from "cosmjs-types/cosmos/crypto/secp256r1/keys";
import { sha256 } from "@cosmjs/crypto";

// pubkey Any for a P-256 passkey:
const pubkeyAny = {
  typeUrl: "/cosmos.crypto.secp256r1.PubKey",
  value: PubKey.encode({ key: compressedPubKey33 }).finish(),
};

const bodyBytes = TxBody.encode(TxBody.fromPartial({ messages: [msgSendAny] })).finish();
const authInfoBytes = makeAuthInfoBytes(
  [{ pubkey: pubkeyAny, sequence }], fee, gasLimit, undefined, undefined,
  SignMode.SIGN_MODE_DIRECT);
const signDoc = makeSignDoc(bodyBytes, authInfoBytes, chainId, accountNumber);
const signBytes = SignDoc.encode(signDoc).finish();
const challenge = sha256(signBytes);                      // pass this to credentials.get

// ... call navigator.credentials.get({ publicKey: { challenge, ... } }) ...

// pack WAS1 = "WAS1" | u32be(len ad) | ad | u32be(len cdj) | cdj | derSig
function u32be(n){ const b=new Uint8Array(4); new DataView(b.buffer).setUint32(0,n); return b; }
const ad = new Uint8Array(r.authenticatorData), cdj = new Uint8Array(r.clientDataJSON), sig = new Uint8Array(r.signature);
const was1 = new Uint8Array([...new TextEncoder().encode("WAS1"),
  ...u32be(ad.length), ...ad, ...u32be(cdj.length), ...cdj, ...sig]);

const txBytes = TxRaw.encode(TxRaw.fromPartial({ bodyBytes, authInfoBytes, signatures: [was1] })).finish();
// broadcast txBytes via CometBFT RPC /broadcast_tx_sync (base64) or a tendermint client.
```

Deriving the address client-side:

```js
import { sha256 } from "@cosmjs/crypto";
import { toBech32 } from "@cosmjs/encoding";
const typ = new TextEncoder().encode("cosmos.crypto.secp256r1.PubKey");
const addr = sha256(new Uint8Array([...sha256(typ), ...compressedPubKey33]));  // 32 bytes
const bech = toBech32("cosmos", addr);                                          // cosmos1...
```

---

## Reference implementations

- **Exact reference bytes:** `x/paymaster/webauthn/authenticator.go` (the
  `SimulatedAuthenticator`) emits byte-for-byte what the verifier checks. Read it to see
  precisely how `authenticatorData`, `clientDataJSON`, and the signed digest are built.
- **Verifier:** `x/paymaster/webauthn/verify.go` and the ante at
  `ante/cosmos/webauthn_sigverify.go`.
- **Blob format:** `x/paymaster/webauthn/assertion.go` (`Marshal` / `UnmarshalAssertion`).
- **CLI:** `evmd/cmd/passkey-signer` builds, passkey-signs, and broadcasts a bank tx using
  a simulated authenticator. Good for proving the chain end-to-end from a terminal.
- **Helper service:** `evmd/cmd/passkey-helper` is the backend behind the live demo.

---

## Constraints and security notes

- **User verification is enforced.** The authenticator must set the UV flag, so a biometric
  or PIN gesture is mandatory.
- **Single-signer, ordered, `SIGN_MODE_DIRECT` only.** Anything else falls through to the
  standard signature path (which rejects the non-standard signature).
- **Replay-safe by construction:** the challenge is `sha256` of the sign-bytes, which bind
  chain-id, account number, and sequence.
- **Bind the origin yourself.** The current verifier checks the challenge, the
  `type`, and the UV/UP flags, but does not pin the relying-party id or origin. Treat that
  as the client's responsibility for now (set `rp.id` / `rpId` to your domain); the mainnet
  audit may tighten this server-side.
- **Audit-gated for mainnet.** The passkey path is experimental and enabled behind a param.
  Do not assume final mainnet semantics until the audit lands.
