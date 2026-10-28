package DAC

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG"
	"EVOLV_DAO/crypto/RDKG/sss"
	"EVOLV_DAO/crypto/RDKG/vss"
	"bytes"
	"math/big"
	"testing"
)

type fixture struct {
	p      *Params
	sk     []*RDKG.SecretKey
	vk     []*RDKG.VerifKey
	avk    *RDKG.AggVerifKey
	trace  *TraceCommittee
	du     *big.Int
	gamma  *bn256.G1
	attrs  []*big.Int
	id     *big.Int
	req    *Commitment
	blinds []*BlindSignature
	sig    *Signature
	par    *vss.Par
	I      []int
}

func setupFixture(t *testing.T, q int) *fixture {
	t.Helper()
	f := &fixture{p: Setup(q + 1), id: big.NewInt(101), I: []int{1, 3, 4}}
	var err error
	f.sk, f.vk, f.avk, _, _, err = RDKG.GenPK(f.p.G2, f.p.Order, q+1, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	f.trace, err = NewTraceCommittee(f.p, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	BindContext(f.p, f.avk, f.trace.D)
	f.du, f.gamma, err = ElGamalKeyGen(f.p.Order)
	if err != nil {
		t.Fatal(err)
	}
	f.par, _ = vss.Setup(5, 3)
	for j := 0; j < q; j++ {
		f.attrs = append(f.attrs, big.NewInt(int64(j+2)))
	}
	f.req, _, err = PrepareBlindSign_EDAO(f.p, f.gamma, f.du, f.attrs, f.id)
	if err != nil {
		t.Fatal(err)
	}
	f.blinds = make([]*BlindSignature, 5)
	for _, i := range f.I {
		f.blinds[i], err = BlindSign_EDAO(f.p, f.sk[i], f.req, f.id)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.sig, err = ObtainCred(f.I, f.blinds, f.du, f.par, f.vk, append([]*big.Int{f.id}, f.attrs...))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) token(t *testing.T, ds []int) *Theta {
	t.Helper()
	th, e := GenToken(f.p, f.avk, f.trace.D, f.sig, f.attrs, f.id, ds)
	if e != nil {
		t.Fatal(e)
	}
	return th
}
func TestRevisedLifecycle(t *testing.T) {
	f := setupFixture(t, 4)
	ok, e := VerifyCred(f.sig, append([]*big.Int{f.id}, f.attrs...), f.avk)
	if e != nil || !ok {
		t.Fatal("credential failed", e)
	}
	for _, ds := range [][]int{nil, {1, 3}, {1, 2, 3, 4}} {
		th := f.token(t, ds)
		ok, e := VerifyTok(f.p, f.avk, f.trace.D, th, th.Disclosed)
		if e != nil || !ok {
			t.Fatal("presentation failed", ds, e)
		}
		shares := []*DecryptionShare{}
		for _, i := range f.I {
			s, e := ComputeDecryptionShare(f.p, f.trace, th.ElGamalCipher, i)
			if e != nil {
				t.Fatal(e)
			}
			if e = ProveDecryptionShare(f.p, f.trace, th.ElGamalCipher, s); e != nil {
				t.Fatal(e)
			}
			shares = append(shares, s)
		}
		u, e := Trace(f.p, f.trace, th.ElGamalCipher, shares)
		if e != nil || !equalG1(u, new(bn256.G1).ScalarMult(f.p.G1, f.id)) {
			t.Fatal("trace failed", e)
		}
	}
	r, _, e := PrepareBlindSign_EDAO(f.p, f.gamma, f.du, f.attrs, f.id)
	if e != nil {
		t.Fatal(e)
	}
	if equalG1(r.H, f.req.H) || equalG1(r.Cm, f.req.Cm) {
		t.Fatal("base reused")
	}
	// A full known candidate vector does not match the independently masked signature.
	th := f.token(t, nil)
	K := new(bn256.G2).Set(f.avk.Alpha)
	for j, m := range append([]*big.Int{f.id}, f.attrs...) {
		K.Add(K, new(bn256.G2).ScalarMult(f.avk.Betas[j], m))
	}
	if bytes.Equal(bn256.Pair(th.SigPrime.H, K).Marshal(), bn256.Pair(th.SigPrime.S, f.p.G2).Marshal()) {
		t.Fatal("unmasked candidate-vector test unexpectedly passed")
	}
}
func TestIssuanceRejectsTampering(t *testing.T) {
	f := setupFixture(t, 2)
	cases := map[string]func(*Commitment){"commitment": func(r *Commitment) { r.Cm = new(bn256.G1).Add(r.Cm, f.p.G1) }, "base": func(r *Commitment) { r.H = f.p.G1 }, "identity": func(r *Commitment) { r.ID = big.NewInt(102) }, "ciphertext": func(r *Commitment) {
		r.C = append([][2]*bn256.G1(nil), r.C...)
		r.C[0][1] = new(bn256.G1).Add(r.C[0][1], f.p.G1)
	}, "missing-proof": func(r *Commitment) { r.PiS = nil }, "false-proof": func(r *Commitment) { x := *r.PiS; x.C = addScalar(x.C, big.NewInt(1)); r.PiS = &x }, "identity-base": func(r *Commitment) { r.H = new(bn256.G1).ScalarBaseMult(big.NewInt(0)) }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := *f.req
			mutate(&r)
			if _, e := BlindSign_EDAO(f.p, f.sk[0], &r, f.id); e == nil {
				t.Fatal("invalid request signed")
			}
		})
	}
	bad := append([]*BlindSignature(nil), f.blinds...)
	x := *bad[f.I[0]]
	x.S[1] = new(bn256.G1).Add(x.S[1], f.p.G1)
	bad[f.I[0]] = &x
	if _, e := ObtainCred(f.I, bad, f.du, f.par, f.vk, append([]*big.Int{f.id}, f.attrs...)); e == nil {
		t.Fatal("invalid partial signature accepted")
	}
	if _, e := ObtainCred([]int{1, 1, 4}, f.blinds, f.du, f.par, f.vk, append([]*big.Int{f.id}, f.attrs...)); e == nil {
		t.Fatal("duplicate signers accepted")
	}
}
func TestPresentationRejectsTampering(t *testing.T) {
	f := setupFixture(t, 3)
	cases := map[string]func(*Theta){"ciphertext": func(th *Theta) {
		ct := *th.ElGamalCipher
		ct.B = new(bn256.G1).Add(ct.B, f.p.G1)
		th.ElGamalCipher = &ct
	}, "signature": func(th *Theta) { sig := *th.SigPrime; sig.S = new(bn256.G1).Add(sig.S, f.p.G1); th.SigPrime = &sig }, "identity-h": func(th *Theta) {
		sig := *th.SigPrime
		sig.H = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		th.SigPrime = &sig
	}, "eta": func(th *Theta) { th.Kappa = new(bn256.G2).Add(th.Kappa, f.p.G2) }, "nu": func(th *Theta) { th.Nu = new(bn256.G1).Add(th.Nu, f.p.G1) }, "missing-proof": func(th *Theta) { th.PiV = nil }, "false-proof": func(th *Theta) { x := *th.PiV; x.C = addScalar(x.C, big.NewInt(1)); th.PiV = &x }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			th := f.token(t, []int{2})
			mutate(th)
			ok, _ := VerifyTok(f.p, f.avk, f.trace.D, th, th.Disclosed)
			if ok {
				t.Fatal("tampered token accepted")
			}
		})
	}
	th := f.token(t, []int{2})
	ds := []DisclosedAttribute{{2, big.NewInt(999)}}
	ok, _ := VerifyTok(f.p, f.avk, f.trace.D, th, ds)
	if ok {
		t.Fatal("changed public disclosure accepted")
	}
	old := append([]byte(nil), f.p.Context...)
	f.p.Context = []byte("another application/master key")
	ok, _ = VerifyTok(f.p, f.avk, f.trace.D, th, th.Disclosed)
	f.p.Context = old
	if ok {
		t.Fatal("cross-context replay accepted")
	}
	if _, e := GenToken(f.p, f.avk, f.trace.D, f.sig, f.attrs, f.id, []int{0}); e == nil {
		t.Fatal("identity disclosed")
	}
	other, e := GenToken(f.p, f.avk, f.trace.D, f.sig, f.attrs, big.NewInt(102), nil)
	if e != nil {
		t.Fatal(e)
	}
	ok, _ = VerifyTok(f.p, f.avk, f.trace.D, other, nil)
	if ok {
		t.Fatal("traced identity not bound to credential")
	}
}
func TestTracingAndEvolution(t *testing.T) {
	f := setupFixture(t, 2)
	th := f.token(t, nil)
	shares := []*DecryptionShare{}
	for _, i := range f.I {
		s, _ := ComputeDecryptionShare(f.p, f.trace, th.ElGamalCipher, i)
		if e := ProveDecryptionShare(f.p, f.trace, th.ElGamalCipher, s); e != nil {
			t.Fatal(e)
		}
		shares = append(shares, s)
	}
	if _, e := Trace(f.p, f.trace, th.ElGamalCipher, shares[:2]); e == nil {
		t.Fatal("subthreshold trace")
	}
	if _, e := Trace(f.p, f.trace, th.ElGamalCipher, []*DecryptionShare{shares[0], shares[0], shares[2]}); e == nil {
		t.Fatal("duplicate trace shares")
	}
	bad := *shares[0]
	bad.Delta = new(bn256.G1).Add(bad.Delta, f.p.G1)
	if _, e := Trace(f.p, f.trace, th.ElGamalCipher, []*DecryptionShare{&bad, shares[1], shares[2]}); e == nil {
		t.Fatal("false trace share accepted")
	}
	to, _ := sss.Setup(7, 4)
	newSK, newVK, e := RDKG.EvolveVerified(f.sk, f.vk, f.par.Pub, to, f.I)
	if e != nil {
		t.Fatal(e)
	}
	I := []int{0, 2, 4, 6}
	ls, _ := sss.PrecomputeLagCoef(to, I)
	avk := &RDKG.AggVerifKey{G2: f.p.G2, Alpha: new(bn256.G2).ScalarBaseMult(big.NewInt(0)), Betas: make([]*bn256.G2, len(f.avk.Betas))}
	for j := range avk.Betas {
		avk.Betas[j] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}
	for k, i := range I {
		avk.Alpha.Add(avk.Alpha, new(bn256.G2).ScalarMult(newVK[i].AX, ls[k]))
		for j := range avk.Betas {
			avk.Betas[j].Add(avk.Betas[j], new(bn256.G2).ScalarMult(newVK[i].BYs[j], ls[k]))
		}
	}
	ok, e := VerifyCred(f.sig, append([]*big.Int{f.id}, f.attrs...), avk)
	if e != nil || !ok {
		t.Fatal("old credential invalid after evolution", e)
	}
	next, e := f.trace.Evolve(f.p, 4, 7, f.I)
	if e != nil {
		t.Fatal(e)
	}
	newShares := []*DecryptionShare{}
	for _, i := range I {
		s, _ := ComputeDecryptionShare(f.p, next, th.ElGamalCipher, i)
		if e := ProveDecryptionShare(f.p, next, th.ElGamalCipher, s); e != nil {
			t.Fatal(e)
		}
		newShares = append(newShares, s)
	}
	u, e := Trace(f.p, next, th.ElGamalCipher, newShares)
	if e != nil || !equalG1(u, new(bn256.G1).ScalarMult(f.p.G1, f.id)) {
		t.Fatal("old token not traceable after evolution", e)
	}
	// Same-base update factors are not implemented: an approved update is freshly issued.
	updated := append([]*big.Int(nil), f.attrs...)
	updated[0] = big.NewInt(999)
	req, _, e := PrepareBlindSign_EDAO(f.p, f.gamma, f.du, updated, f.id)
	if e != nil {
		t.Fatal(e)
	}
	blinds := make([]*BlindSignature, 7)
	for _, i := range I {
		blinds[i], e = BlindSign_EDAO(f.p, newSK[i], req, f.id)
		if e != nil {
			t.Fatal(e)
		}
	}
	par, _ := vss.Setup(7, 4)
	sig, e := ObtainCred(I, blinds, f.du, par, newVK, append([]*big.Int{f.id}, updated...))
	if e != nil {
		t.Fatal(e)
	}
	if equalG1(sig.H, f.sig.H) {
		t.Fatal("attribute update reused signing base")
	}
	wrong := append([]*RDKG.SecretKey(nil), f.sk...)
	x := *wrong[1]
	x.X = addScalar(x.X, big.NewInt(1))
	wrong[1] = &x
	if _, _, e := RDKG.EvolveVerified(wrong, f.vk, f.par.Pub, to, f.I); e == nil {
		t.Fatal("invalid old share accepted in evolution")
	}
}
