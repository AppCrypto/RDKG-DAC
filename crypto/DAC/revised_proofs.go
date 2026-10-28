package DAC

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
)

type DisclosedAttribute struct {
	Index int
	Value *big.Int
}

func randomScalar(nonzero bool) (*big.Int, error) {
	for {
		x, e := rand.Int(rand.Reader, bn256.Order)
		if e != nil {
			return nil, e
		}
		if !nonzero || x.Sign() != 0 {
			return x, nil
		}
	}
}
func validScalar(x *big.Int) bool      { return x != nil && x.Sign() >= 0 && x.Cmp(bn256.Order) < 0 }
func addScalar(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), bn256.Order) }
func response(w, c, x *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(w, new(big.Int).Mul(c, x)), bn256.Order)
}
func equalG1(a, b *bn256.G1) bool { return bytes.Equal(a.Marshal(), b.Marshal()) }
func validG1(a *bn256.G1, nonzero bool) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if a == nil {
		return false
	}
	raw := a.Marshal()
	_, err := new(bn256.G1).Unmarshal(raw)
	return err == nil && (!nonzero || !bytes.Equal(raw, new(bn256.G1).ScalarBaseMult(big.NewInt(0)).Marshal()))
}
func validG2(a *bn256.G2) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if a == nil {
		return false
	}
	_, err := new(bn256.G2).Unmarshal(a.Marshal())
	if err != nil {
		return false
	}
	// This library's G2 multiplication does not reduce its scalar; this checks the prime-order subgroup.
	return bytes.Equal(new(bn256.G2).ScalarMult(a, bn256.Order).Marshal(), new(bn256.G2).ScalarBaseMult(big.NewInt(0)).Marshal())
}
func validIndices(is []int, n, t int) bool {
	if len(is) < t {
		return false
	}
	seen := map[int]bool{}
	for _, i := range is {
		if i < 0 || i >= n || seen[i] {
			return false
		}
		seen[i] = true
	}
	return true
}
func credentialBase(cm *bn256.G1) (*bn256.G1, error) {
	h, e := bn256.HashG1("cred" + string(cm.Marshal()))
	if e != nil || !validG1(h, true) {
		return nil, fmt.Errorf("invalid commitment-derived base")
	}
	return h, nil
}

// Each field is length-framed. Public statements and witness commitments are bound together.
func challenge(domain string, p *Params, g1 []*bn256.G1, g2 []*bn256.G2, scalars ...*big.Int) *big.Int {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte(domain))
	field(p.Context)
	field(p.Order.Bytes())
	field(p.G1.Marshal())
	field(p.G2.Marshal())
	field(big.NewInt(int64(len(p.Hs))).Bytes())
	for _, b := range p.Hs {
		field(b.Marshal())
	}
	field(big.NewInt(int64(len(g1))).Bytes())
	for _, v := range g1 {
		field(v.Marshal())
	}
	field(big.NewInt(int64(len(g2))).Bytes())
	for _, v := range g2 {
		field(v.Marshal())
	}
	field(big.NewInt(int64(len(scalars))).Bytes())
	for _, v := range scalars {
		field(v.Bytes())
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), p.Order)
}

// BindContext is setup-time work, outside timed issuance/presentation operations.
func BindContext(p *Params, vk *RDKG.AggVerifKey, tracingKey *bn256.G1) {
	h := sha256.New()
	h.Write([]byte("DAC/master-key/v1"))
	h.Write(vk.G2.Marshal())
	h.Write(vk.Alpha.Marshal())
	for _, b := range vk.Betas {
		h.Write(b.Marshal())
	}
	h.Write(tracingKey.Marshal())
	p.Context = h.Sum(nil)
}
func issuanceChallenge(p *Params, r *Commitment, wd, wc *bn256.G1, wa, wb []*bn256.G1) *big.Int {
	gs := []*bn256.G1{r.gamma, r.Cm, r.H, wd, wc}
	for _, c := range r.C {
		gs = append(gs, c[0], c[1])
	}
	gs = append(gs, wa...)
	gs = append(gs, wb...)
	return challenge("DAC/issuance/v2", p, gs, nil, r.ID)
}
func MakePiS_EDAO(p *Params, r *Commitment, ks []*big.Int, opening, du *big.Int, attrs []*big.Int) (*PiS, error) {
	wd, e := randomScalar(false)
	if e != nil {
		return nil, e
	}
	wo, e := randomScalar(false)
	if e != nil {
		return nil, e
	}
	q := len(attrs)
	wk := make([]*big.Int, q)
	wm := make([]*big.Int, q)
	wa := make([]*bn256.G1, q)
	wb := make([]*bn256.G1, q)
	cw := new(bn256.G1).ScalarMult(p.G1, wo)
	for j := 0; j < q; j++ {
		wk[j], e = randomScalar(false)
		if e != nil {
			return nil, e
		}
		wm[j], e = randomScalar(false)
		if e != nil {
			return nil, e
		}
		wa[j] = new(bn256.G1).ScalarMult(p.G1, wk[j])
		wb[j] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(r.gamma, wk[j]), new(bn256.G1).ScalarMult(r.H, wm[j]))
		cw.Add(cw, new(bn256.G1).ScalarMult(p.Hs[j+1], wm[j]))
	}
	c := issuanceChallenge(p, r, new(bn256.G1).ScalarMult(p.G1, wd), cw, wa, wb)
	proof := &PiS{C: c, Rr: response(wd, c, du), Ro: response(wo, c, opening), Rk: make([]*big.Int, q), Rm: make([]*big.Int, q)}
	for j := 0; j < q; j++ {
		proof.Rk[j] = response(wk[j], c, ks[j])
		proof.Rm[j] = response(wm[j], c, attrs[j])
	}
	return proof, nil
}
func VerifyPiS_EDAO(p *Params, r *Commitment) (bool, error) {
	if r == nil || r.PiS == nil || !validScalar(r.ID) || !validG1(r.gamma, true) || !validG1(r.Cm, false) || !validG1(r.H, true) || len(r.C)+1 != len(p.Hs) {
		return false, fmt.Errorf("malformed issuance request")
	}
	h, e := credentialBase(r.Cm)
	if e != nil || !equalG1(h, r.H) {
		return false, fmt.Errorf("base/commitment mismatch")
	}
	proof := r.PiS
	q := len(r.C)
	c := proof.C
	if !validScalar(c) || !validScalar(proof.Rr) || !validScalar(proof.Ro) || len(proof.Rm) != q || len(proof.Rk) != q {
		return false, fmt.Errorf("malformed issuance proof")
	}
	wd := new(bn256.G1).Add(new(bn256.G1).ScalarMult(r.gamma, c), new(bn256.G1).ScalarMult(p.G1, proof.Rr))
	normalized := new(bn256.G1).Add(r.Cm, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(p.Hs[0], r.ID)))
	cw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(normalized, c), new(bn256.G1).ScalarMult(p.G1, proof.Ro))
	wa := make([]*bn256.G1, q)
	wb := make([]*bn256.G1, q)
	for j := 0; j < q; j++ {
		if !validScalar(proof.Rm[j]) || !validScalar(proof.Rk[j]) || !validG1(r.C[j][0], false) || !validG1(r.C[j][1], false) {
			return false, fmt.Errorf("malformed ciphertext/proof")
		}
		wa[j] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(r.C[j][0], c), new(bn256.G1).ScalarMult(p.G1, proof.Rk[j]))
		wb[j] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(r.C[j][1], c), new(bn256.G1).ScalarMult(r.gamma, proof.Rk[j]))
		wb[j].Add(wb[j], new(bn256.G1).ScalarMult(r.H, proof.Rm[j]))
		cw.Add(cw, new(bn256.G1).ScalarMult(p.Hs[j+1], proof.Rm[j]))
	}
	return c.Cmp(issuanceChallenge(p, r, wd, cw, wa, wb)) == 0, nil
}
func partition(values []*big.Int, indices []int) ([]DisclosedAttribute, []int, error) {
	ds := append([]int(nil), indices...)
	sort.Ints(ds)
	out := make([]DisclosedAttribute, 0, len(ds))
	seen := map[int]bool{}
	for _, j := range ds {
		if j <= 0 || j >= len(values) || seen[j] {
			return nil, nil, fmt.Errorf("invalid disclosure index")
		}
		seen[j] = true
		out = append(out, DisclosedAttribute{j, new(big.Int).Set(values[j])})
	}
	hidden := []int{}
	for j, m := range values {
		if !validScalar(m) {
			return nil, nil, fmt.Errorf("invalid attribute scalar")
		}
		if !seen[j] {
			hidden = append(hidden, j)
		}
	}
	return out, hidden, nil
}
func disclosureIndices(ds []DisclosedAttribute, q int) ([]int, error) {
	seen := map[int]bool{}
	last := 0
	for _, a := range ds {
		if a.Index <= last || a.Index > q || !validScalar(a.Value) {
			return nil, fmt.Errorf("invalid disclosure")
		}
		seen[a.Index] = true
		last = a.Index
	}
	hidden := []int{}
	for j := 0; j <= q; j++ {
		if !seen[j] {
			hidden = append(hidden, j)
		}
	}
	return hidden, nil
}
func equalDisclosures(a, b []DisclosedAttribute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Index != b[i].Index || !validScalar(a[i].Value) || !validScalar(b[i].Value) || a[i].Value.Cmp(b[i].Value) != 0 {
			return false
		}
	}
	return true
}
func presentationChallenge(p *Params, vk *RDKG.AggVerifKey, D *bn256.G1, t *Theta, wa, wb, wv *bn256.G1, we *bn256.G2) *big.Int {
	gs := []*bn256.G1{D, t.SigPrime.H, t.SigPrime.S, t.Nu, t.ElGamalCipher.A, t.ElGamalCipher.B, wa, wb, wv}
	g2 := append([]*bn256.G2{vk.G2, vk.Alpha, t.Kappa, we}, vk.Betas...)
	scalars := []*big.Int{}
	for _, a := range t.Disclosed {
		scalars = append(scalars, big.NewInt(int64(a.Index)), a.Value)
	}
	return challenge("DAC/presentation/v2", p, gs, g2, scalars...)
}
func MakePiH(p *Params, vk *RDKG.AggVerifKey, D *bn256.G1, t *Theta, values []*big.Int, hidden []int, re, rp, rs *big.Int) (*PiV_EDAO, error) {
	we, e := randomScalar(false)
	if e != nil {
		return nil, e
	}
	wp, e := randomScalar(false)
	if e != nil {
		return nil, e
	}
	ws, e := randomScalar(false)
	if e != nil {
		return nil, e
	}
	wm := make([]*big.Int, len(hidden))
	eta := new(bn256.G2).ScalarMult(vk.G2, addScalar(wp, ws))
	for k, j := range hidden {
		wm[k], e = randomScalar(false)
		if e != nil {
			return nil, e
		}
		eta.Add(eta, new(bn256.G2).ScalarMult(vk.Betas[j], wm[k]))
	}
	a := new(bn256.G1).ScalarMult(p.G1, we)
	b := new(bn256.G1).Add(new(bn256.G1).ScalarMult(D, we), new(bn256.G1).ScalarMult(p.G1, wm[0]))
	v := new(bn256.G1).ScalarMult(t.SigPrime.H, wp)
	c := presentationChallenge(p, vk, D, t, a, b, v, eta)
	proof := &PiV_EDAO{C: c, Rr: response(wp, c, rp), Rrp: response(we, c, re), Rrs: response(ws, c, rs), Rm: make([]*big.Int, len(hidden))}
	for k, j := range hidden {
		proof.Rm[k] = response(wm[k], c, values[j])
	}
	return proof, nil
}
func VerifyPiH(p *Params, vk *RDKG.AggVerifKey, D *bn256.G1, t *Theta) (bool, error) {
	hidden, e := disclosureIndices(t.Disclosed, len(vk.Betas)-1)
	if e != nil {
		return false, e
	}
	pr := t.PiV
	c := pr.C
	if !validScalar(c) || !validScalar(pr.Rr) || !validScalar(pr.Rrp) || !validScalar(pr.Rrs) || len(pr.Rm) != len(hidden) {
		return false, fmt.Errorf("malformed showing proof")
	}
	for _, v := range pr.Rm {
		if !validScalar(v) {
			return false, fmt.Errorf("invalid response")
		}
	}
	a := new(bn256.G1).Add(new(bn256.G1).ScalarMult(t.ElGamalCipher.A, c), new(bn256.G1).ScalarMult(p.G1, pr.Rrp))
	b := new(bn256.G1).Add(new(bn256.G1).ScalarMult(t.ElGamalCipher.B, c), new(bn256.G1).ScalarMult(D, pr.Rrp))
	b.Add(b, new(bn256.G1).ScalarMult(p.G1, pr.Rm[0]))
	v := new(bn256.G1).Add(new(bn256.G1).ScalarMult(t.Nu, c), new(bn256.G1).ScalarMult(t.SigPrime.H, pr.Rr))
	normalized := new(bn256.G2).Add(t.Kappa, new(bn256.G2).Neg(vk.Alpha))
	eta := new(bn256.G2).Add(new(bn256.G2).ScalarMult(normalized, c), new(bn256.G2).ScalarMult(vk.G2, addScalar(pr.Rr, pr.Rrs)))
	for k, j := range hidden {
		eta.Add(eta, new(bn256.G2).ScalarMult(vk.Betas[j], pr.Rm[k]))
	}
	return c.Cmp(presentationChallenge(p, vk, D, t, a, b, v, eta)) == 0, nil
}
