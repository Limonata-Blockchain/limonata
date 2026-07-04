// Package dkgnode holds the NODE-LOCAL (non-consensus) half of the transparent
// in-node DKG: the auto-generated secp256k1 ECIES key a validator uses to seal/open
// DKG shares, plus the pure crypto that builds a dealing / derives a share / proves a
// decryption share for a vote extension. None of it touches consensus state directly —
// it operates on plain values handed in by the ABCI vote-extension handlers — so it
// carries NO determinism obligation (each node contributes its OWN dealing/shares; the
// chain verifies them via the audited public path). It deliberately introduces NO new
// cryptography; every primitive is reused from x/encmempool/dkg + /threshold.
package dkgnode

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// EncKeyFile is the node-home-relative filename of the persisted DKG enc key.
const EncKeyFile = "dkg_enc_key.json"

type encKeyJSON struct {
	Priv string `json:"priv"` // hex of the 32-byte secret scalar
	Pub  string `json:"pub"`  // hex of the 33-byte compressed pubkey (advisory)
}

// EncKey is a node's DKG encryption keypair (secret scalar + compressed pubkey).
type EncKey struct {
	Priv *secp256k1.ModNScalar
	Pub  []byte // 33-byte compressed secp256k1 point
}

// LoadOrCreateEncKey returns the node's DKG enc key from <homeDir>/dkg_enc_key.json,
// GENERATING + persisting it on first boot. This is the whole of the "transparent key"
// mechanism from the operator's side: they do nothing; the node mints its ECIES key once
// and announces the pubkey via its vote extension. The file is written 0600.
func LoadOrCreateEncKey(homeDir string) (*EncKey, error) {
	path := filepath.Join(homeDir, EncKeyFile)
	if raw, err := os.ReadFile(path); err == nil {
		return parseEncKey(raw)
	}
	pk, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	priv := new(secp256k1.ModNScalar)
	priv.Set(&pk.Key)
	pub := pk.PubKey().SerializeCompressed()
	rec := encKeyJSON{Priv: hex.EncodeToString(pk.Serialize()), Pub: hex.EncodeToString(pub)}
	bz, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, bz, 0o600); err != nil {
		return nil, err
	}
	return &EncKey{Priv: priv, Pub: pub}, nil
}

func parseEncKey(raw []byte) (*EncKey, error) {
	var rec encKeyJSON
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("malformed enc key file: %w", err)
	}
	b, err := hex.DecodeString(rec.Priv)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("enc key priv must be 32-byte hex")
	}
	var sb [32]byte
	copy(sb[:], b)
	s := new(secp256k1.ModNScalar)
	if s.SetBytes(&sb) != 0 {
		return nil, fmt.Errorf("enc key is not a canonical scalar")
	}
	var P secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(s, &P)
	P.ToAffine()
	pub := secp256k1.NewPublicKey(&P.X, &P.Y).SerializeCompressed()
	return &EncKey{Priv: s, Pub: pub}, nil
}

// MyIndex returns this node's 1-based DKG member index in a round by matching its enc
// pubkey against the round's member set, or 0 if the node is not a member. This is the
// "key doubles as self-identifier" mechanism: the node never needs to know its own
// operator/consensus address to find itself.
func (e *EncKey) MyIndex(members []types.RoundMember) uint64 {
	for _, m := range members {
		if len(m.EncPubKey) == len(e.Pub) && string(m.EncPubKey) == string(e.Pub) {
			return m.Index
		}
	}
	return 0
}

// BuildDealing builds this node's Feldman dealing for a round: fresh commitments plus one
// ECIES-sealed share per member. It is the in-node replacement for the daemon's MsgDkgDeal
// construction; the secret polynomial never leaves this function.
func BuildDealing(epoch uint64, members []types.RoundMember, myIndex uint64, thr int) (*types.VoteExtDealing, error) {
	idxs := make([]uint64, len(members))
	for i, m := range members {
		idxs[i] = m.Index
	}
	commitments, shares, err := dkg.Deal(myIndex, idxs, thr, rand.Reader)
	if err != nil {
		return nil, err
	}
	enc := make([]types.DkgStoredEncShare, 0, len(members))
	for _, m := range members {
		ct, err := dkg.EncryptShareTo(m.EncPubKey, shares[m.Index])
		if err != nil {
			return nil, fmt.Errorf("seal share to member %d: %w", m.Index, err)
		}
		enc = append(enc, types.DkgStoredEncShare{MemberIndex: m.Index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
	}
	return &types.VoteExtDealing{Epoch: epoch, Commitments: commitments, EncShares: enc}, nil
}

// DeriveShare reconstructs this node's final Shamir share X_m = Σ_{i∈QUAL} f_i(m) by
// opening the enc-share each QUAL dealer sealed to it. dealings is keyed by dealer index.
// It is the in-node replacement for the daemon's onFinalized share accumulation, but reads
// COMMITTED dealings instead of accumulated events.
func DeriveShare(myIndex uint64, encPriv *secp256k1.ModNScalar, qual []uint64, dealings map[uint64]types.Dealing) (threshold.Share, error) {
	X := new(secp256k1.ModNScalar)
	first := true
	for _, dealer := range qual {
		d, ok := dealings[dealer]
		if !ok {
			return threshold.Share{}, fmt.Errorf("missing dealing from qual dealer %d", dealer)
		}
		var ct *threshold.Ciphertext
		for i := range d.EncShares {
			if d.EncShares[i].MemberIndex == myIndex {
				ct = &threshold.Ciphertext{A: d.EncShares[i].A, Nonce: d.EncShares[i].Nonce, Body: d.EncShares[i].Body}
				break
			}
		}
		if ct == nil {
			return threshold.Share{}, fmt.Errorf("no enc-share for member %d from qual dealer %d", myIndex, dealer)
		}
		s, err := dkg.DecryptShareFrom(encPriv, myIndex, ct)
		if err != nil {
			return threshold.Share{}, fmt.Errorf("open share from dealer %d: %w", dealer, err)
		}
		if first {
			X.Set(s)
			first = false
		} else {
			X.Add(s)
		}
	}
	if first {
		return threshold.Share{}, fmt.Errorf("no qual dealers")
	}
	return threshold.Share{Index: myIndex, Xi: X}, nil
}

// ProveShareFor produces a DLEQ-proved decryption share for ciphertext component A (r*G,
// compressed) under this node's derived share. It wraps dkg.ProveDecryptShare.
func ProveShareFor(share threshold.Share, a []byte) (d []byte, proof []byte, err error) {
	ds, pf, err := dkg.ProveDecryptShare(share, &threshold.Ciphertext{A: a})
	if err != nil {
		return nil, nil, err
	}
	return ds.D, dkg.MarshalDLEQProof(pf), nil
}
