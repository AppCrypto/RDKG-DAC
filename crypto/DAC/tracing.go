package DAC

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG"
	"EVOLV_DAO/crypto/RDKG/sss"
	"fmt"
	"math/big"
)

type TraceCommittee struct {
	Pub      *sss.PubPara
	Shares   []*RDKG.SecretKey // in-memory local fixture only; never serialized to results
	Public   []*RDKG.VerifKey
	D        *bn256.G1
	PublicG1 []*bn256.G1
}
type DecryptionProof struct{ C, Z *big.Int }
type DecryptionShare struct {
	Index int
	Delta *bn256.G1
	Proof *DecryptionProof
}

func NewTraceCommittee(p *Params, t, n int) (*TraceCommittee, error) {
	if t <= n/2 || t > n {
		return nil, fmt.Errorf("invalid threshold")
	}
	keys, pubs, _, _, _, err := RDKG.GenPK(p.G2, p.Order, 0, t, n)
	if err != nil {
		return nil, err
	}
	pub, _ := sss.Setup(n, t)
	I := make([]int, t)
	for i := range I {
		I[i] = i
	}
	ls, _ := sss.PrecomputeLagCoef(pub, I)
	out := &TraceCommittee{Pub: pub, Shares: keys, Public: pubs, PublicG1: make([]*bn256.G1, n), D: new(bn256.G1).ScalarBaseMult(big.NewInt(0))}
	for i, k := range keys {
		out.PublicG1[i] = new(bn256.G1).ScalarMult(p.G1, k.X)
	}
	for k, i := range I {
		out.D.Add(out.D, new(bn256.G1).ScalarMult(out.PublicG1[i], ls[k]))
	}
	if !validG1(out.D, true) {
		return nil, fmt.Errorf("identity tracing key; retry setup")
	}
	return out, nil
}
func (c *TraceCommittee) Evolve(p *Params, t, n int, S []int) (*TraceCommittee, error) {
	if t <= n/2 || t > n {
		return nil, fmt.Errorf("invalid threshold")
	}
	to, _ := sss.Setup(n, t)
	sk, vk, err := RDKG.EvolveVerified(c.Shares, c.Public, c.Pub, to, S)
	if err != nil {
		return nil, err
	}
	next := &TraceCommittee{Pub: to, Shares: sk, Public: vk, D: c.D, PublicG1: make([]*bn256.G1, n)}
	for i, k := range sk {
		next.PublicG1[i] = new(bn256.G1).ScalarMult(p.G1, k.X)
	}
	I := make([]int, t)
	for i := range I {
		I[i] = i
	}
	ls, _ := sss.PrecomputeLagCoef(to, I)
	D := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for k, i := range I {
		D.Add(D, new(bn256.G1).ScalarMult(next.PublicG1[i], ls[k]))
	}
	if !equalG1(D, c.D) {
		return nil, fmt.Errorf("tracing key changed")
	}
	return next, nil
}
func decryptionChallenge(p *Params, c *TraceCommittee, ct *ElGamalCipher, s *DecryptionShare, T1, T2 *bn256.G1) *big.Int {
	return challenge("DAC/decryption-share/v1", p, []*bn256.G1{c.D, c.PublicG1[s.Index], ct.A, ct.B, s.Delta, T1, T2}, nil, big.NewInt(int64(s.Index)), big.NewInt(int64(c.Pub.T)), big.NewInt(int64(c.Pub.N)))
}
func ComputeDecryptionShare(p *Params, c *TraceCommittee, ct *ElGamalCipher, i int) (*DecryptionShare, error) {
	if c == nil || ct == nil || i < 0 || i >= len(c.Shares) || !validG1(ct.A, false) || !validG1(ct.B, false) {
		return nil, fmt.Errorf("invalid trace input")
	}
	return &DecryptionShare{Index: i, Delta: new(bn256.G1).ScalarMult(ct.A, c.Shares[i].X)}, nil
}
func ProveDecryptionShare(p *Params, c *TraceCommittee, ct *ElGamalCipher, s *DecryptionShare) error {
	if s == nil || s.Index < 0 || s.Index >= len(c.Shares) || !validG1(s.Delta, false) {
		return fmt.Errorf("invalid partial decryption")
	}
	w, err := randomScalar(false)
	if err != nil {
		return err
	}
	ch := decryptionChallenge(p, c, ct, s, new(bn256.G1).ScalarMult(p.G1, w), new(bn256.G1).ScalarMult(ct.A, w))
	s.Proof = &DecryptionProof{C: ch, Z: response(w, ch, c.Shares[s.Index].X)}
	return nil
}
func VerifyDecryptionShare(p *Params, c *TraceCommittee, ct *ElGamalCipher, s *DecryptionShare) bool {
	if c == nil || ct == nil || s == nil || s.Index < 0 || s.Index >= len(c.PublicG1) || s.Proof == nil || !validScalar(s.Proof.C) || !validScalar(s.Proof.Z) || !validG1(s.Delta, false) || !validG1(ct.A, false) || !validG1(ct.B, false) {
		return false
	}
	T1 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(p.G1, s.Proof.Z), new(bn256.G1).ScalarMult(c.PublicG1[s.Index], s.Proof.C))
	T2 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(ct.A, s.Proof.Z), new(bn256.G1).ScalarMult(s.Delta, s.Proof.C))
	return s.Proof.C.Cmp(decryptionChallenge(p, c, ct, s, T1, T2)) == 0
}

// CombineVerifiedDecryption is arithmetic only. The caller must first verify every share.
// Trace below is the public fail-closed interface used for end-to-end measurements.
func CombineVerifiedDecryption(c *TraceCommittee, ct *ElGamalCipher, shares []*DecryptionShare) (*bn256.G1, error) {
	I := make([]int, len(shares))
	for j, s := range shares {
		if s == nil {
			return nil, fmt.Errorf("missing share")
		}
		I[j] = s.Index
	}
	if !validIndices(I, c.Pub.N, c.Pub.T) {
		return nil, fmt.Errorf("need distinct threshold shares")
	}
	ls, e := sss.PrecomputeLagCoef(c.Pub, I)
	if e != nil {
		return nil, e
	}
	product := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for j, s := range shares {
		product.Add(product, new(bn256.G1).ScalarMult(s.Delta, ls[j]))
	}
	return new(bn256.G1).Add(ct.B, new(bn256.G1).Neg(product)), nil
}
func Trace(p *Params, c *TraceCommittee, ct *ElGamalCipher, shares []*DecryptionShare) (*bn256.G1, error) {
	for _, s := range shares {
		if !VerifyDecryptionShare(p, c, ct, s) {
			return nil, fmt.Errorf("invalid decryption proof")
		}
	}
	return CombineVerifiedDecryption(c, ct, shares)
}
