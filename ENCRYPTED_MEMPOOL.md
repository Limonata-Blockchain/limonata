# Encrypted mempool - submitting an encrypted transaction

Limonata's encrypted mempool lets you submit a transaction whose **contents are
hidden until its order in the block is already fixed**. No validator and no
searcher can see what you're doing in time to front-run or sandwich you. The
payload is decrypted only after a **threshold of independent keypers** (2 of 3)
cooperate - which only happens *after* ordering. That's the anti-MEV guarantee.

This is **experimental, testnet-only**. Come break it.

## The 30-second version

```bash
# 1. encrypt your payload to the chain's threshold public key
limonatad keyper encrypt \
  --pubkey Aw2DNwiH87yToy7Q+HC3Bv4hBiihRYlqnqp5nKsTIfwN \
  --message "buy 1000 LIMO at market"

# -> prints a (base64), nonce (base64), body (base64)

# 2. submit the ciphertext (the body is unreadable on-chain)
limonatad tx encmempool submit-encrypted \
  --a <A> --nonce <NONCE> --body <BODY> \
  --from <your-key> --keyring-backend test \
  --chain-id limonata_10777-1 --node tcp://rpc.limonata.xyz:443 \
  --gas auto --gas-adjustment 1.4 --fees 5000000aLIMO -y
```

That's it. Your ciphertext is now stored on-chain with a fixed decrypt height. The
keypers post their decryption shares automatically; about ~30 seconds later (15
blocks) the chain decrypts it and emits the plaintext **in the order that was
locked in at submission time**.

## What just happened

1. **Encrypt.** `keyper encrypt` encrypts your message to the chain's single
   threshold public key. The output is a hybrid ciphertext: `a` (an ephemeral
   public key), a `nonce`, and the AES-GCM-encrypted `body`.
2. **Submit.** `submit-encrypted` stores `(a, nonce, body)` on-chain and assigns
   it a sequence number + a **decrypt height** (current height + 15). The order is
   fixed *now*, while the body is still unreadable.
3. **Keypers cooperate.** Each keyper independently computes a partial decryption
   from `a` and posts it. No single keyper - and no pair short of the threshold -
   can decrypt anything.
4. **Decrypt.** At the decrypt height, the chain combines the shares, decrypts the
   body, and emits an `encmempool_decrypted` event with the plaintext, in
   deterministic order. Every node computes the identical result (it's consensus
   logic, not a side service).

## Prove the anti-MEV property yourself

Submit a ciphertext, then **before** its decrypt height, query its on-chain data:
the `body` is opaque bytes - there is nothing to front-run. Query again **after**
the decrypt height and you'll see the `encmempool_decrypted` event with your exact
message. The order was committed in step 2, the readability in step 4. A searcher
watching the mempool sees only ciphertext until it's too late to reorder.

```bash
# watch for your decryption on the explorer or via:
limonatad q tx <SUBMIT_TXHASH> --node tcp://rpc.limonata.xyz:443 -o json
# note the decrypt_height in the encmempool_encrypted_submitted event, then check
# that block's results for encmempool_decrypted.
```

## Getting the binary

Use the `limonatad` release that ships with the encrypted-mempool upgrade (the same
binary validators run). `keyper encrypt` is a local, offline command - it never
touches your keys or the network; it only needs the public threshold key above.

## Honest limits (read this)

This is a **working prototype**, not an audited production system:

- The threshold key was created by a **trusted setup** (one-time key generation),
  not a distributed key-generation ceremony. A production deployment replaces this
  with DKG so no one ever holds the full key.
- There are **no per-share correctness proofs** yet - a malicious keyper could
  withhold or corrupt a share to grief a single ciphertext (it cannot decrypt it
  early or forge a different message).
- The decrypted payload is currently **emitted as an event** to demonstrate
  in-order decryption; full re-execution of the decrypted transaction through the
  EVM is the next step.
- It's **testnet-only** and unaudited. Don't rely on it for anything of value.

None of that changes the core property you can test today: **your transaction's
order is fixed before anyone can read it.** That's the hard part, and it works.

## Why it matters

On most chains, whoever orders the block (or watches the public mempool) can see
your trade and jump ahead of it - front-running, sandwiching, MEV extraction. An
encrypted mempool removes the information advantage: by the time your transaction
can be read, its position is already final. Limonata is testing this in the open.
🍋
