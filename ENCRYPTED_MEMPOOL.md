# Encrypted mempool - submitting an encrypted transaction

Limonata's encrypted mempool lets you submit a transaction whose **contents are
hidden until its order in the block is already fixed**. No validator and no
searcher can see what you're doing in time to front-run or sandwich you. The
payload is decrypted only after the validator set - which jointly holds the
threshold key inside consensus - combines shares representing **more than 2/3 of
committee stake**, and that only happens *after* ordering. That's the anti-MEV
guarantee.

This is **live on the Limonata testnet** and exercised end-to-end. Come try it.

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
validators post their decryption shares automatically; about ~30 seconds later
(15 blocks) the chain decrypts it and executes the recovered transaction **in the
order that was locked in at submission time**.

## What just happened

1. **Encrypt.** `keyper encrypt` encrypts your message to the chain's single
   threshold public key. The output is a hybrid ciphertext: `a` (an ephemeral
   public key), a `nonce`, and the AES-GCM-encrypted `body`.
2. **Submit.** `submit-encrypted` stores `(a, nonce, body)` on-chain and assigns
   it a sequence number + a **decrypt height** (current height + 15). The order is
   fixed *now*, while the body is still unreadable.
3. **Validators cooperate.** Each validator independently computes a partial
   decryption from `a` using its share of the threshold key, and posts it inside
   consensus. Shares are **stake-weighted**, so no single validator - and no
   coalition holding less than 2/3 of committee stake - can decrypt anything.
4. **Decrypt and execute.** At the decrypt height, the chain combines the shares,
   decrypts the body, emits an `encmempool_decrypted` event, and **executes the
   recovered transaction on-chain** (EncExec), in deterministic order. Every node
   computes the identical result (it's consensus logic, not a side service).

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

## How the key is held (read this)

The threshold key is **generated and held by the validators together, on-chain,
inside consensus** (via CometBFT vote extensions). There is no trusted dealer, no
keyper committee, and no coordinator - the master secret never exists in one
place. Validators take part simply by running the node binary: no daemon, no
separate account, no fees, no key setup.

- Decryption power is **stake-weighted** - each validator's shares are apportioned
  by bonded stake over a fixed budget, and reconstruction needs shares
  representing **more than 2/3 of committee stake**.
- It **fails closed**: if stake concentration would let one operator (or a
  sub-2/3-stake coalition) decrypt alone, the key does not activate.
- It **auto-rekeys** on any membership change and on stake drift over 5%, so the
  key tracks the live validator set.
- Decrypted transactions **execute on-chain at reveal** (EncExec), in the order
  locked in at submission time.

This runs on the Limonata **testnet** and has been exercised end-to-end - it
finalized its first key epoch on-chain - and reviewed across the repo's internal
audit cycles. The core property holds today: **your transaction's order is fixed
before anyone can read it.**

## Why it matters

On most chains, whoever orders the block (or watches the public mempool) can see
your trade and jump ahead of it - front-running, sandwiching, MEV extraction. An
encrypted mempool removes the information advantage: by the time your transaction
can be read, its position is already final. Limonata runs this live, in the open, on its testnet.
🍋
