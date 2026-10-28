package DAC

import (
	"EVOLV_DAO/bn256"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type PiS struct {
	C  *big.Int   // challenge
	Rk []*big.Int // responses for k_i
	Rm []*big.Int // responses for m_i
	Rr *big.Int   // response for r (user decryption key in EDAO)
	Ro *big.Int   // EDAO commitment opening response
}

type PiV struct {
	C    *big.Int   // challenge
	Rm   []*big.Int // 响应属性
	Rr   *big.Int   // 响应随机数 t
	Rk   *big.Int
	RIDu *big.Int
}

type PiV_EDAO struct {
	C   *big.Int   // challenge
	Rm  []*big.Int // 响应属性
	Rr  *big.Int   // 响应随机数 t
	Rrp *big.Int
	Rrs *big.Int // independent displayed-signature mask response
}

func ToChallenge(elements []*bn256.G1) *big.Int {
	hasher := sha256.New()
	for _, e := range elements {
		hasher.Write(e.Marshal())
	}
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func ToChallengeMixed(g1s []*bn256.G1, g2s []*bn256.G2) *big.Int {
	hasher := sha256.New()
	for _, g := range g1s {
		hasher.Write(g.Marshal())
	}
	for _, g := range g2s {
		hasher.Write(g.Marshal())
	}
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func MakePiS_Coconut(params *Params, gamma *bn256.G1, ciphertext [][2]*bn256.G1, cm *bn256.G1,
	k []*big.Int, r *big.Int, publicM, privateM []*big.Int) (*PiS, error) {

	o := params.Order
	p := len(privateM)
	q := len(publicM)
	total := p + q

	if len(ciphertext) != p || len(k) != p || total > len(params.Hs) {
		return nil, fmt.Errorf("invalid input lengths")
	}

	// 1. Generate random witnesses
	wr, _ := rand.Int(rand.Reader, o)
	wk := make([]*big.Int, p)
	wm := make([]*big.Int, total)
	for i := 0; i < p; i++ {
		wk[i], _ = rand.Int(rand.Reader, o)
	}
	for i := 0; i < total; i++ {
		wm[i], _ = rand.Int(rand.Reader, o)
	}

	// 2. h = HashG1(cm)
	h, _ := bn256.HashG1(string(cm.Marshal()))

	// 3. Compute Aw = g1^wk[i]
	Aw := make([]*bn256.G1, p)
	for i := 0; i < p; i++ {
		Aw[i] = new(bn256.G1).ScalarMult(params.G1, wk[i])
	}

	// 4. Compute Bw[i] = gamma^wk[i] * h^wm[i]
	Bw := make([]*bn256.G1, p)
	for i := 0; i < p; i++ {
		gwk := new(bn256.G1).ScalarMult(gamma, wk[i])
		hwm := new(bn256.G1).ScalarMult(h, wm[i])
		Bw[i] = new(bn256.G1).Add(gwk, hwm)
	}

	// 5. Compute Cw = g1^wr * ∏ h_i^wm_i
	Cw := new(bn256.G1).ScalarMult(params.G1, wr)
	for i := 0; i < total; i++ {
		term := new(bn256.G1).ScalarMult(params.Hs[i], wm[i])
		Cw.Add(Cw, term)
	}

	// 6. Compute challenge
	toHash := []*bn256.G1{params.G1, cm, h, Cw}
	toHash = append(toHash, params.Hs[:total]...)
	toHash = append(toHash, Aw...)
	toHash = append(toHash, Bw...)
	c := ToChallenge(toHash)

	// 7. Responses
	rr := new(big.Int).Sub(wr, new(big.Int).Mul(c, r))
	rr.Mod(rr, o)

	rk := make([]*big.Int, p)
	for i := 0; i < p; i++ {
		rk[i] = new(big.Int).Sub(wk[i], new(big.Int).Mul(c, k[i]))
		rk[i].Mod(rk[i], o)
	}

	attributes := append([]*big.Int{}, privateM...)
	attributes = append(attributes, publicM...)

	rm := make([]*big.Int, total)
	for i := 0; i < total; i++ {
		rm[i] = new(big.Int).Sub(wm[i], new(big.Int).Mul(c, attributes[i]))
		rm[i].Mod(rm[i], o)
	}

	return &PiS{C: c, Rk: rk, Rm: rm, Rr: rr}, nil
}

func VerifyPiS_Coconut(params *Params, gamma *bn256.G1, ciphertext [][2]*bn256.G1, cm *bn256.G1, proof *PiS) (bool, error) {
	c := proof.C
	rk := proof.Rk
	rm := proof.Rm
	rr := proof.Rr

	p := len(rk)
	total := len(rm)

	// 1. h = HashG1(cm)
	h, _ := bn256.HashG1(string(cm.Marshal()))

	// 2. Recompute Aw, Bw
	Aw := make([]*bn256.G1, p)
	Bw := make([]*bn256.G1, p)
	for i := 0; i < p; i++ {
		a := ciphertext[i][0]
		b := ciphertext[i][1]

		termA := new(bn256.G1).ScalarMult(a, c)
		termG := new(bn256.G1).ScalarMult(params.G1, rk[i])
		Aw[i] = new(bn256.G1).Add(termA, termG)

		gwk := new(bn256.G1).ScalarMult(gamma, rk[i])
		hwm := new(bn256.G1).ScalarMult(h, rm[i])
		part := new(bn256.G1).Add(gwk, hwm)

		bc := new(bn256.G1).ScalarMult(b, c)
		Bw[i] = new(bn256.G1).Add(bc, part)
	}

	// 3. Recompute Cw
	Cw := new(bn256.G1).ScalarMult(cm, c)
	Cw.Add(Cw, new(bn256.G1).ScalarMult(params.G1, rr))
	for i := 0; i < total; i++ {
		term := new(bn256.G1).ScalarMult(params.Hs[i], rm[i])
		Cw.Add(Cw, term)
	}

	// 4. Recompute challenge
	toHash := []*bn256.G1{params.G1, cm, h, Cw}
	toHash = append(toHash, params.Hs[:total]...)
	toHash = append(toHash, Aw...)
	toHash = append(toHash, Bw...)
	cPrime := ToChallenge(toHash)

	return cPrime.Cmp(c) == 0, nil
}
