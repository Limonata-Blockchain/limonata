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

// privValKeyFile is the standard CometBFT path (relative to the node home) of the file
// carrying the node's consensus key + its derived consensus address.
const privValKeyFile = "config/priv_validator_key.json"

// LoadConsAddress reads THIS node's consensus address (the 20-byte address CometBFT tags
// its votes with) from <homeDir>/config/priv_validator_key.json. It is node-local and
// read-only — it never touches the priv-validator STATE file and never exposes the private
// key. The transparent DKG uses the returned address to resolve the node's operator (via
// staking), so the node can self-identify by OPERATOR and bind its enc-key proof-of-
// possession to that identity. Returns an error when the node has no validator key (a full
// node), in which case the caller simply does not participate.
func LoadConsAddress(homeDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(homeDir, privValKeyFile))
	if err != nil {
		return nil, err
	}
	var rec struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("malformed priv_validator_key.json: %w", err)
	}
	addr, err := hex.DecodeString(rec.Address)
	if err != nil || len(addr) == 0 {
		return nil, fmt.Errorf("priv_validator_key.json has no valid consensus address")
	}
	return addr, nil
}

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
// pubkey against the round's member set, or 0 if the node is not a member.
//
// DEPRECATED for self-identification (HIGH-4): matching by enc key is spoofable — a
// colliding key could misindex and silence an honest member. The live path now
// self-identifies by OPERATOR (types.MemberIndexByOperator, resolved from the node's
// consensus address). This method is retained only as a utility / for the regression that
// documents the difference; do NOT use it to route shares.
func (e *EncKey) MyIndex(members []types.RoundMember) uint64 {
	for _, m := range members {
		if len(m.EncPubKey) == len(e.Pub) && string(m.EncPubKey) == string(e.Pub) {
			return m.Index
		}
	}
	return 0
}

// BuildDealing builds this node's Feldman dealing for a round: fresh commitments plus one
// ECIES-sealed share per EVALUATION POINT in the round's stake-weighted budget domain (each
// point's share is sealed to the enc key of the member that owns it — HIGH-3). On the unweighted
// legacy path each member owns exactly one point == its index, so this reduces to one sealed
// share per member. It is the in-node replacement for the daemon's MsgDkgDeal construction; the
// secret polynomial never leaves this function. The per-dealing size is O(S) (budget) sealed
// shares + O(t) commitments, bounded regardless of raw stake.
func BuildDealing(epoch uint64, members []types.RoundMember, myIndex uint64, thr int) (*types.VoteExtDealing, error) {
	// The full evaluation-point domain (union of every member's owned points).
	var evalPoints []uint64
	for _, m := range members {
		evalPoints = append(evalPoints, m.OwnedEvalPoints()...)
	}
	commitments, shares, err := dkg.Deal(myIndex, evalPoints, thr, rand.Reader)
	if err != nil {
		return nil, err
	}
	enc := make([]types.DkgStoredEncShare, 0, len(evalPoints))
	for _, m := range members {
		for _, p := range m.OwnedEvalPoints() {
			s, ok := shares[p]
			if !ok {
				return nil, fmt.Errorf("missing share at eval point %d", p)
			}
			ct, err := dkg.EncryptShareTo(m.EncPubKey, s)
			if err != nil {
				return nil, fmt.Errorf("seal share at eval point %d to member %d: %w", p, m.Index, err)
			}
			enc = append(enc, types.DkgStoredEncShare{MemberIndex: p, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
	}
	return &types.VoteExtDealing{Epoch: epoch, Commitments: commitments, EncShares: enc}, nil
}

// DeriveShares reconstructs this node's final Shamir shares — ONE per evaluation point it owns —
// X_p = Σ_{i∈QUAL} f_i(p), by opening the enc-share each QUAL dealer sealed to it at point p.
// dealings is keyed by dealer index. It is the in-node replacement for the daemon's onFinalized
// share accumulation, but reads COMMITTED dealings instead of accumulated events. myEvalPoints is
// the caller's OwnedEvalPoints() for the round (so on the unweighted path it is a single point).
func DeriveShares(myEvalPoints []uint64, encPriv *secp256k1.ModNScalar, qual []uint64, dealings map[uint64]types.Dealing) ([]threshold.Share, error) {
	out := make([]threshold.Share, 0, len(myEvalPoints))
	for _, p := range myEvalPoints {
		X := new(secp256k1.ModNScalar)
		first := true
		for _, dealer := range qual {
			d, ok := dealings[dealer]
			if !ok {
				return nil, fmt.Errorf("missing dealing from qual dealer %d", dealer)
			}
			var ct *threshold.Ciphertext
			for i := range d.EncShares {
				if d.EncShares[i].MemberIndex == p {
					ct = &threshold.Ciphertext{A: d.EncShares[i].A, Nonce: d.EncShares[i].Nonce, Body: d.EncShares[i].Body}
					break
				}
			}
			if ct == nil {
				return nil, fmt.Errorf("no enc-share at eval point %d from qual dealer %d", p, dealer)
			}
			s, err := dkg.DecryptShareFrom(encPriv, p, ct)
			if err != nil {
				return nil, fmt.Errorf("open share at eval point %d from dealer %d: %w", p, dealer, err)
			}
			if first {
				X.Set(s)
				first = false
			} else {
				X.Add(s)
			}
		}
		if first {
			return nil, fmt.Errorf("no qual dealers")
		}
		out = append(out, threshold.Share{Index: p, Xi: X})
	}
	return out, nil
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
