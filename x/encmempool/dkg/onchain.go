// onchain.go adds the thin helpers the ON-CHAIN integration needs on top of the
// audited crypto core (dkg.go / proof.go). It deliberately lives in a SEPARATE
// file so the audited files stay pristine; every function here only reuses the
// package's existing, reviewed primitives (evalPoly, randScalarFrom, compressCopy,
// parsePoint, SharePubKey, the threshold hybrid scheme) — it introduces NO new
// cryptography.
//
// The split of responsibility between chain and node:
//   - the CHAIN sees only PUBLIC data (Feldman commitments) and computes the
//     public outputs (master pubkey, aggregate commitments, QUAL) via FinalizePublic;
//   - each NODE derives its OWN secret share locally from the point-to-point shares
//     that were ECIES-encrypted to it (Deal + EncryptShareTo on the dealer side,
//     DecryptShareFrom on the recipient side). The master secret is never formed and
//     the per-member shares never appear in plaintext on chain.
package dkg

import (
	"fmt"
	"io"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PublicDealing is a dealer's ON-CHAIN contribution: only the public Feldman
// commitments C_{i,0..t-1} (compressed). The point-to-point shares travel
// encrypted to each member OFF this struct, so — unlike dkg.Finalize —
// FinalizePublic computes only the PUBLIC outputs and never touches secret shares.
type PublicDealing struct {
	Dealer      uint64
	Commitments [][]byte // compressed C_{i,j}, len must be t
}

// PublicResult is the deterministic public output of the on-chain DKG finalize.
type PublicResult struct {
	Pub               []byte   // compress(msk*G) = Σ_{i∈QUAL} C_{i,0}
	PublicCommitments [][]byte // V_j = Σ_{i∈QUAL} C_{i,j} (compressed); V_0 = msk*G
	Qual              []uint64 // qualified dealer indices (sorted)
	Disqualified      []uint64 // members excluded (no/malformed dealing, or a valid complaint)
}

// FinalizePublic is the on-chain, share-free counterpart of Finalize. Given the
// member index set, threshold t, every dealer's PUBLIC commitments, and the set of
// dealer indices already disqualified by a JUSTIFIED complaint (verified by the
// caller — see keeper DkgComplaint), it deterministically computes QUAL and the
// aggregate key using the EXACT QUAL rules Finalize enforces:
//   - a dealer must publish EXACTLY t well-formed (parseable) commitments, else it
//     is dropped (matches Finalize's structural well-formedness pass);
//   - a member that did not deal at all is dropped;
//   - a complained-against dealer is dropped.
//
// Every node runs this over identical committed state, so all nodes compute an
// identical PublicResult. It reads NO secret and cannot form msk.
func FinalizePublic(members []uint64, t int, dealings []PublicDealing, disqualified []uint64) (*PublicResult, error) {
	// Unweighted path: every member counts as one Shamir share, and the QUAL size must be >= t
	// (the reconstruction threshold == the dealer-count bar). This is exactly the original
	// behaviour, so the legacy/declared DKG and the dkg-package tests are unchanged.
	return FinalizePublicWeighted(members, t, dealings, disqualified, nil, t)
}

// FinalizePublicWeighted is the STAKE-WEIGHTED generalization of FinalizePublic (HIGH-3).
//
//   - degree is the number of Feldman commitments each dealer must publish, i.e. the sharing
//     polynomial degree + 1 == the reconstruction threshold t. The aggregate key V has `degree`
//     coefficients, and RecoverVerified needs t of the Shamir evaluation points to reconstruct.
//   - weightOf[m] is the number of evaluation points member m owns (its stake weight in the
//     bounded budget). nil => every member weighs 1 (the unweighted path).
//   - minQualWeight is the minimum TOTAL evaluation-point weight the QUALified dealers must
//     collectively represent for the round to succeed. On the transparent path this is set to t,
//     so a round finalizes only when dealers owning >= t points participated (since points are
//     stake-proportional, that is a coalition above the proven decrypt bar — > 1/3 of committee
//     stake, ~2/3 - 2n/S in general; see keeper.stakeThreshold) — the correct robustness/secrecy
//     gate (msk is then guaranteed to mix in honest entropy, and enough of the committee dealt
//     to reconstruct).
//
// Decoupling degree (the poly / reconstruction threshold, which can exceed the dealer COUNT once
// points are stake-weighted) from the QUAL participation metric is exactly what lets a
// t = floor(2S/3)-n+1 threshold coexist with a committee of only n<=128 dealers.
func FinalizePublicWeighted(members []uint64, degree int, dealings []PublicDealing, disqualified []uint64, weightOf map[uint64]int, minQualWeight int) (*PublicResult, error) {
	if degree < 1 {
		return nil, fmt.Errorf("invalid threshold t=%d (must be >= 1)", degree)
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("no members")
	}

	// Parse + index each well-formed dealing's commitment points. A dealing with the
	// wrong number of commitments or an unparseable point is structurally malformed
	// and simply never enters byDealer (so its member is excluded from QUAL below).
	byDealer := make(map[uint64][]secp256k1.JacobianPoint, len(dealings))
	for _, d := range dealings {
		if len(d.Commitments) != degree {
			continue
		}
		pts, err := ParseCommitmentPoints(d.Commitments)
		if err != nil {
			continue
		}
		byDealer[d.Dealer] = pts
	}

	disq := make(map[uint64]bool, len(disqualified))
	for _, x := range disqualified {
		disq[x] = true
	}

	// Iterate members in ascending index order so QUAL/Disqualified are deterministic.
	sorted := append([]uint64(nil), members...)
	sortUint64(sorted)
	var qual, disqOut []uint64
	qualWeight := 0
	for _, m := range sorted {
		if _, dealt := byDealer[m]; !dealt || disq[m] {
			disqOut = append(disqOut, m)
			continue
		}
		qual = append(qual, m)
		qualWeight += memberWeight(weightOf, m)
	}
	if qualWeight < minQualWeight {
		return nil, fmt.Errorf("DKG failed: QUAL weight=%d < required=%d (|QUAL|=%d)", qualWeight, minQualWeight, len(qual))
	}

	// Aggregate V_j = Σ_{i∈QUAL} C_{i,j}. V_0 = (Σ s_i)*G = msk*G.
	V := make([]secp256k1.JacobianPoint, degree)
	for j := 0; j < degree; j++ {
		first := true
		for _, i := range qual {
			cij := byDealer[i][j]
			if first {
				V[j] = cij
				first = false
				continue
			}
			var sum secp256k1.JacobianPoint
			secp256k1.AddNonConst(&V[j], &cij, &sum)
			V[j] = sum
		}
	}
	vbz := make([][]byte, degree)
	for j := range V {
		vbz[j] = compressCopy(&V[j])
	}
	return &PublicResult{Pub: vbz[0], PublicCommitments: vbz, Qual: qual, Disqualified: disqOut}, nil
}

// memberWeight returns member m's evaluation-point weight from weightOf, defaulting to 1 when
// weightOf is nil (the unweighted path) or has no entry for m.
func memberWeight(weightOf map[uint64]int, m uint64) int {
	if weightOf == nil {
		return 1
	}
	if w, ok := weightOf[m]; ok {
		return w
	}
	return 1
}

// ValidCompressedPoint reports whether b is a well-formed COMPRESSED secp256k1 point
// (exactly 33 bytes, a valid 0x02/0x03 prefix, and ON the curve). It is the ingress
// gate for HIGH-1: an enc-share `A` (or a Feldman commitment) that does not satisfy
// this is structurally unopenable/unusable, so it must be rejected at DkgDeal before it
// can enter QUAL and poison every honest member's aggregate share. It reuses the same
// parsePoint the decrypt/complaint paths use, so "accepted at ingress" is exactly
// "parseable downstream".
func ValidCompressedPoint(b []byte) bool {
	_, err := parsePoint(b)
	return err == nil
}

// ParseCommitmentPoints parses a slice of compressed points (e.g. a stored
// ActiveThresholdKey's aggregate commitments) back into Jacobian points for
// RecoverVerified / SharePubKey.
func ParseCommitmentPoints(cbz [][]byte) ([]secp256k1.JacobianPoint, error) {
	out := make([]secp256k1.JacobianPoint, len(cbz))
	for i, cb := range cbz {
		p, err := parsePoint(cb)
		if err != nil {
			return nil, fmt.Errorf("commitment %d: %w", i, err)
		}
		out[i] = *p
	}
	return out, nil
}

// Deal generates dealer `index`'s Feldman dealing for the given member set: the
// compressed public commitments and the SECRET point-to-point share f_index(m) for
// each member m. The daemon then ECIES-encrypts each share to the matching member
// via EncryptShareTo. The dealer's secret s_index = coeffs[0] never leaves here.
//
// rng MUST be crypto/rand.Reader in real use (msk secrecy is delegated to it); a
// seeded reader is for reproducible tests only, exactly as RunDKG documents.
func Deal(index uint64, members []uint64, t int, rng io.Reader) (commitments [][]byte, shares map[uint64]*secp256k1.ModNScalar, err error) {
	if t < 1 {
		return nil, nil, fmt.Errorf("invalid threshold t=%d (must be >= 1)", t)
	}
	if len(members) == 0 {
		return nil, nil, fmt.Errorf("no members")
	}
	coeffs := make([]*secp256k1.ModNScalar, t)
	for j := range coeffs {
		s, e := randScalarFrom(rng)
		if e != nil {
			return nil, nil, e
		}
		coeffs[j] = s
	}
	commitments = make([][]byte, t)
	for j := range coeffs {
		var C secp256k1.JacobianPoint
		secp256k1.ScalarBaseMultNonConst(coeffs[j], &C)
		commitments[j] = compressCopy(&C)
	}
	shares = make(map[uint64]*secp256k1.ModNScalar, len(members))
	for _, m := range members {
		shares[m] = evalPoly(coeffs, m)
	}
	return commitments, shares, nil
}

// EncryptShareTo ECIES-encrypts a 32-byte share scalar to a member's encryption
// public key, REUSING the threshold hybrid scheme (hash-DH ElGamal + AES-GCM) as an
// ECIES primitive — so shares stay private on chain with zero new crypto. Only the
// member holding the matching secret can open it via DecryptShareFrom.
func EncryptShareTo(memberEncPub []byte, share *secp256k1.ModNScalar) (*threshold.Ciphertext, error) {
	b := share.Bytes()
	ct, err := threshold.Encrypt(memberEncPub, b[:])
	for i := range b { // best-effort wipe of the secret copy
		b[i] = 0
	}
	return ct, err
}

// DecryptShareFrom recovers a share scalar addressed to a member holding encPriv.
// The member's ECDH secret is s = encPriv*A = r*encPub, so ComputeShare (which
// computes encPriv*A) + Decrypt reproduce the exact plaintext the dealer sealed.
func DecryptShareFrom(encPriv *secp256k1.ModNScalar, memberIndex uint64, ct *threshold.Ciphertext) (*secp256k1.ModNScalar, error) {
	ds, err := threshold.ComputeShare(threshold.Share{Index: memberIndex, Xi: encPriv}, ct)
	if err != nil {
		return nil, err
	}
	Spub, err := parsePoint(ds.D)
	if err != nil {
		return nil, err
	}
	plain, err := threshold.Decrypt(Spub, ct)
	if err != nil {
		return nil, err
	}
	if len(plain) != 32 {
		return nil, fmt.Errorf("bad share plaintext length %d (want 32)", len(plain))
	}
	var sb [32]byte
	copy(sb[:], plain)
	s := new(secp256k1.ModNScalar)
	if s.SetBytes(&sb) != 0 {
		return nil, fmt.Errorf("decrypted share is not a canonical scalar")
	}
	return s, nil
}

// VerifyJustifiedComplaint checks a framing-resistant complaint entirely from
// bytes, keeping all secp256k1 handling inside this package. The accuser reveals
// the ECDH point S it derived for the disputed enc-share plus a DLEQ proof that S
// was formed with the accuser's OWN encryption secret (S = x*encA ∧ encPub = x*G) —
// so a lying accuser cannot pick an S that frames an honest dealer.
//
// It returns (cheated, proofValid):
//   - proofValid=false  => the DLEQ did not verify (frivolous/framing attempt); the
//     complaint MUST be rejected.
//   - proofValid=true, cheated=true  => the dealer PROVABLY misbehaved (sealed a
//     share inconsistent with its public commitments, or unopenable garbage); the
//     dealer MUST be disqualified.
//   - proofValid=true, cheated=false => the dealer's share is valid; reject the
//     (frivolous) complaint.
func VerifyJustifiedComplaint(accuserIndex uint64, accuserEncPub []byte, dealerCommitments [][]byte, encA, encNonce, encBody, sharedPoint, dleqProof []byte) (cheated, proofValid bool) {
	// DEFENSE-IN-DEPTH (HIGH-1): a structurally-malformed enc-share is a PUBLIC,
	// incontrovertible dealer fault — the dealer's OWN on-chain bytes do not form an
	// openable sealed share (A is not a curve point, or the AES-GCM nonce is the wrong
	// length), so NO accuser secret or DLEQ proof is needed to justify disqualification:
	// there is nothing to frame, since any node recomputes this purely from public
	// state. Return (cheated, proofValid) = (true, true) so the complaint is recorded.
	// DkgDeal ingress now rejects such dealings up front, so this path is normally
	// unreachable; keeping it here closes the complaint route independently (e.g. a
	// dealing imported via genesis that bypassed the handler). Previously this exact
	// case short-circuited at parsePoint(encA) inside VerifyDecryptShare and returned
	// proofValid=false, making the fault structurally UNCOMPLAINABLE — the HIGH-1 bug.
	if _, err := parsePoint(encA); err != nil {
		return true, true
	}
	if len(encNonce) != threshold.NonceSize {
		return true, true
	}
	Y, err := parsePoint(accuserEncPub)
	if err != nil {
		return false, false
	}
	proof, err := ParseDLEQProof(dleqProof)
	if err != nil {
		return false, false
	}
	ds := &threshold.DecryptShare{Index: accuserIndex, D: sharedPoint}
	if !VerifyDecryptShare(encA, ds, Y, proof) {
		return false, false // accuser did not prove S is its real ECDH secret
	}
	// The proof is valid: S is genuinely the accuser's ECDH secret for this share.
	Spt, err := parsePoint(sharedPoint)
	if err != nil {
		return false, true
	}
	plain, err := threshold.Decrypt(Spt, &threshold.Ciphertext{A: encA, Nonce: encNonce, Body: encBody})
	if err != nil || len(plain) != 32 {
		return true, true // unopenable / wrong-length seal => dealer cheated
	}
	commitments, err := ParseCommitmentPoints(dealerCommitments)
	if err != nil {
		return true, true // dealer's own commitments are malformed
	}
	var sb [32]byte
	copy(sb[:], plain)
	s := new(secp256k1.ModNScalar)
	if s.SetBytes(&sb) != 0 {
		return true, true // non-canonical share scalar => cheated
	}
	if VerifyShare(commitments, accuserIndex, s) {
		return false, true // the dealt share is valid — frivolous complaint
	}
	return true, true // share inconsistent with public commitments => cheated
}

// MarshalDLEQProof serializes a DLEQ proof as C||Z (32+32 bytes) for the
// MsgSubmitDecryptionShare proof field / on-chain EncShare storage.
func MarshalDLEQProof(p *DLEQProof) []byte {
	if p == nil || p.C == nil || p.Z == nil {
		return nil
	}
	c := p.C.Bytes()
	z := p.Z.Bytes()
	out := make([]byte, 0, 64)
	out = append(out, c[:]...)
	out = append(out, z[:]...)
	return out
}

// ParseDLEQProof parses a C||Z proof produced by MarshalDLEQProof.
func ParseDLEQProof(b []byte) (*DLEQProof, error) {
	if len(b) != 64 {
		return nil, fmt.Errorf("dleq proof must be 64 bytes, got %d", len(b))
	}
	var cb, zb [32]byte
	copy(cb[:], b[:32])
	copy(zb[:], b[32:])
	c := new(secp256k1.ModNScalar)
	z := new(secp256k1.ModNScalar)
	c.SetBytes(&cb)
	z.SetBytes(&zb)
	return &DLEQProof{C: c, Z: z}, nil
}

// sortUint64 sorts ascending (small local helper; avoids importing sort at call sites).
func sortUint64(s []uint64) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
