package DAC

import (
	bn256 "EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG"
	"EVOLV_DAO/crypto/RDKG/sss"
	"EVOLV_DAO/crypto/RDKG/vss"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type Params struct {
	Order   *big.Int
	G1      *bn256.G1
	G2      *bn256.G2
	Hs      []*bn256.G1
	Context []byte // application/master-key context bound into Fiat--Shamir challenges
}

type Commitment struct {
	gamma *bn256.G1
	Cm    *bn256.G1      // 承诺 cm
	C     [][2]*bn256.G1 // ElGamal 密文 (aᵢ, bᵢ)
	H     *bn256.G1      // fresh commitment-derived signing base
	ID    *big.Int       // authenticated registration identity, public at issuance
	PiS   *PiS           // 零知识证明 π_s
}

type BlindSignature struct {
	H *bn256.G1    // Hash(cm)
	S [2]*bn256.G1 // (t2, t3)
}

type Signature struct {
	H *bn256.G1
	S *bn256.G1
}

type Theta struct {
	Kappa         *bn256.G2            // commitment in G2
	Nu            *bn256.G1            // randomization in G1
	SigPrime      *Signature           // sigma'
	ElGamalCipher *ElGamalCipher       // C_h
	Disclosed     []DisclosedAttribute // indexed public attributes; identity index 0 stays hidden
	PiV           *PiV_EDAO            // PiV      interface{}  // optional zero-knowledge proof
}

func Setup(q int) *Params {
	if q <= 0 {
		return nil
	}

	order := bn256.Order
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	hs := make([]*bn256.G1, q)
	for i := 0; i < q; i++ {
		label := fmt.Sprintf("DAC/commitment/v1/%d", i)
		h, _ := bn256.HashG1(label)
		hs[i] = h
	}

	return &Params{
		Order: order,
		G1:    g1,
		G2:    g2,
		Hs:    hs,
	}
}

func TTPKeyGen(params *Params, t, n int) ([]*RDKG.SecretKey, []*RDKG.VerifKey, *RDKG.AggVerifKey, *big.Int, *bn256.G1, error) {
	q := len(params.Hs)
	g2 := params.G2

	// ElGamal 密钥对
	d_DAO, Gamma, err := ElGamalKeyGen(bn256.Order)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("ElGamal keygen failed: %v", err)
	}

	// 门限签名密钥生成
	sks, vks, avk, _, _, err := RDKG.GenPK(g2, params.Order, q, t, n)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("RDKG.GenPK failed: %v", err)
	}

	return sks, vks, avk, d_DAO, Gamma, nil
}

func PrepareBlindSign_Coconut(params *Params, gamma *bn256.G1, privateM, publicM []*big.Int) (*Commitment, error) {
	o := params.Order
	g1 := params.G1
	hs := params.Hs

	attributes := append([]*big.Int{}, privateM...)
	attributes = append(attributes, publicM...)

	if len(attributes) > len(hs) {
		return nil, fmt.Errorf("too many attributes: max %d, got %d", len(hs), len(attributes))
	}

	// 1. 生成随机数 r ∈ Zp
	r, _ := rand.Int(rand.Reader, o)

	// 2. cm = r·g₁ + ∑ mᵢ·hᵢ
	cm := new(bn256.G1).ScalarMult(g1, r)
	for i, m := range attributes {
		hi := hs[i]
		term := new(bn256.G1).ScalarMult(hi, m)
		cm.Add(cm, term)
	}

	// 3. h = HashG1(cm)
	h, err := bn256.HashG1(string(cm.Marshal()))
	if err != nil {
		return nil, fmt.Errorf("hash to G1 failed: %v", err)
	}

	// 4. 使用 ElGamal 加密每个 private attribute，同时保存 k
	C := make([][2]*bn256.G1, len(privateM))
	k := make([]*big.Int, len(privateM))
	for i, m := range privateM {
		a, b, ki, err := ElGamalEncrypt(gamma, h, m, o)
		if err != nil {
			return nil, err
		}
		k[i] = ki
		C[i] = [2]*bn256.G1{a, b}
	}

	// 5. 构建零知识证明 π_s
	piS, err := MakePiS_Coconut(params, gamma, C, cm, k, r, publicM, privateM)
	if err != nil {
		return nil, fmt.Errorf("MakePiS_Coconut failed: %v", err)
	}

	// 6. 返回 commitment
	return &Commitment{
		gamma: gamma,
		Cm:    cm,
		C:     C,
		PiS:   piS,
	}, nil
}

func BlindSign_Coconut(params *Params, sk *RDKG.SecretKey, lambda *Commitment, publicM []*big.Int) (*BlindSignature, error) {
	q := len(params.Hs)
	if len(lambda.C)+len(publicM) > q {
		return nil, fmt.Errorf("too many attributes")
	}

	ok, err := VerifyPiS_Coconut(params, lambda.gamma, lambda.C, lambda.Cm, lambda.PiS)
	if err != nil || !ok {
		return nil, fmt.Errorf("invalid Coconut issuance proof: %v", err)
	}

	// 1. 计算 h = HashG1(cm)
	hBytes := lambda.Cm.Marshal()
	h, err := bn256.HashG1(string(hBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to hash Cm: %v", err)
	}

	// 2. t1 = ∑ (mᵢ · h)^yᵢ，对应公开属性部分，从 index = len(privateM) 开始
	t1 := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // 初始化为 0 元
	for i, mi := range publicM {
		attrIndex := len(lambda.C) + i // 属性真实下标（跳过私有属性）
		if attrIndex >= len(sk.Ys) {
			return nil, fmt.Errorf("not enough Y values for public attribute at index %d", attrIndex)
		}
		// t = h^{mi * y_i}
		exponent := new(big.Int).Mul(mi, sk.Ys[attrIndex])
		term := new(bn256.G1).ScalarMult(h, exponent)
		t1.Add(t1, term)
	}

	// 3. t2 = ∑ yᵢ · aᵢ （签名者用私钥 Y 乘以用户加密的 ElGamal a）
	t2 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(lambda.C); i++ {
		yi := sk.Ys[i]
		a := lambda.C[i][0]
		term := new(bn256.G1).ScalarMult(a, yi)
		t2.Add(t2, term)
	}

	// 4. t3 = x·h + ∑ yᵢ·(bᵢ) + t1
	t3 := new(bn256.G1).ScalarMult(h, sk.X) // x·h
	for i := 0; i < len(lambda.C); i++ {
		yi := sk.Ys[i]
		b := lambda.C[i][1]
		term := new(bn256.G1).ScalarMult(b, yi)
		t3.Add(t3, term)
	}
	t3.Add(t3, t1) // 加上公开部分

	return &BlindSignature{
		H: h,
		S: [2]*bn256.G1{t2, t3},
	}, nil
}

// PrepareBlindSign_EDAO binds a caller-authenticated registration ID to a fresh request.
// params.Hs has q+1 bases, including the identity slot at index zero.
func PrepareBlindSign_EDAO(params *Params, gamma *bn256.G1, d *big.Int, attributes []*big.Int, id *big.Int) (*Commitment, *big.Int, error) {
	if !validScalar(id) || !validScalar(d) || !validG1(gamma, true) || !equalG1(gamma, new(bn256.G1).ScalarMult(params.G1, d)) || len(attributes)+1 != len(params.Hs) {
		return nil, nil, fmt.Errorf("invalid registered identity, key, or attribute schema")
	}
	opening, err := randomScalar(false)
	if err != nil {
		return nil, nil, err
	}
	cm := new(bn256.G1).ScalarMult(params.G1, opening)
	cm.Add(cm, new(bn256.G1).ScalarMult(params.Hs[0], id))
	for j, m := range attributes {
		if !validScalar(m) {
			return nil, nil, fmt.Errorf("invalid attribute")
		}
		cm.Add(cm, new(bn256.G1).ScalarMult(params.Hs[j+1], m))
	}
	h, err := credentialBase(cm)
	if err != nil {
		return nil, nil, err
	}
	req := &Commitment{gamma: gamma, Cm: cm, H: h, ID: new(big.Int).Set(id), C: make([][2]*bn256.G1, len(attributes))}
	ks := make([]*big.Int, len(attributes))
	for j, m := range attributes {
		a, b, k, err := ElGamalEncrypt(gamma, h, m, params.Order)
		if err != nil {
			return nil, nil, err
		}
		req.C[j] = [2]*bn256.G1{a, b}
		ks[j] = k
	}
	req.PiS, err = MakePiS_EDAO(params, req, ks, opening, d, attributes)
	if err != nil {
		return nil, nil, err
	}
	return req, new(big.Int).Set(id), nil
}

func BlindSign_EDAO(params *Params, sk *RDKG.SecretKey, lambda *Commitment, ID_u *big.Int) (*BlindSignature, error) {

	if lambda == nil || !validScalar(ID_u) || lambda.ID == nil || ID_u.Cmp(lambda.ID) != 0 || len(sk.Ys) != len(lambda.C)+1 {
		return nil, fmt.Errorf("identity/schema mismatch")
	}
	ok, err := VerifyPiS_EDAO(params, lambda)
	if err != nil || !ok {
		return nil, fmt.Errorf("invalid issuance proof: %v", err)
	}
	h := lambda.H

	// 2. t1 = h ^ (ID_u * y_i0)
	t1 := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // 初始化为 0 元
	exponent := new(big.Int).Mul(ID_u, sk.Ys[0])
	term := new(bn256.G1).ScalarMult(h, exponent)
	t1.Add(t1, term)

	// 3. t2 = ∑ yᵢ · aᵢ （签名者用私钥 Y 乘以用户加密的 ElGamal a）
	t2 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 1; i < len(lambda.C)+1; i++ {
		yi := sk.Ys[i]
		a := lambda.C[i-1][0]
		term = new(bn256.G1).ScalarMult(a, yi)
		t2.Add(t2, term)
	}

	// 4. t3 = x·h + ∑ yᵢ·(bᵢ) + t1
	t3 := new(bn256.G1).ScalarMult(h, sk.X) // x·h
	for i := 1; i < len(lambda.C)+1; i++ {
		yi := sk.Ys[i]
		b := lambda.C[i-1][1]
		term = new(bn256.G1).ScalarMult(b, yi)
		t3.Add(t3, term)
	}
	t3.Add(t3, t1) // 加上公开部分

	return &BlindSignature{
		H: h,
		S: [2]*bn256.G1{t2, t3},
	}, nil
}

func ObtainCred(I []int, blindSigs []*BlindSignature, d *big.Int, par *vss.Par, vks []*RDKG.VerifKey, attrs []*big.Int) (*Signature, error) {
	if !validIndices(I, par.Pub.N, par.Pub.T) || len(vks) != par.Pub.N {
		return nil, errors.New("not enough partial signatures to aggregate")
	}

	// Step 1: 解盲每个 BlindSignature → Signature
	sigs := make([]*Signature, len(blindSigs))
	for _, idx := range I {
		if idx >= len(blindSigs) || blindSigs[idx] == nil {
			return nil, fmt.Errorf("invalid or missing blind signature at index %d", idx)
		}
		sigs[idx] = &Signature{
			H: blindSigs[idx].H,
			S: ElGamalDecrypt(d, blindSigs[idx].S[0], blindSigs[idx].S[1]),
		}
		ok, err := VerifyPartialCred(sigs[idx], attrs, vks[idx])
		if err != nil || !ok {
			return nil, fmt.Errorf("invalid partial signature %d", idx)
		}
	}

	// Step 2: 聚合门限签名（复制 AggCred 中的逻辑）
	lambdas, err := sss.PrecomputeLagCoef(par.Pub, I)
	if err != nil {
		return nil, err
	}

	var commonH *bn256.G1
	aggS := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(I); i++ {
		idx := I[i]
		sig := sigs[idx]
		if sig == nil {
			return nil, fmt.Errorf("signature at index %d is nil", idx)
		}
		if i == 0 {
			commonH = sig.H
		} else if sig.H.String() != commonH.String() {
			return nil, errors.New("inconsistent H values among partial signatures")
		}
		term := new(bn256.G1).ScalarMult(sig.S, lambdas[i])
		aggS = new(bn256.G1).Add(aggS, term)
	}

	return &Signature{
		H: commonH,
		S: aggS,
	}, nil
}

// GenToken supports arbitrary disclosed attribute indices in [1,q].
func GenToken(params *Params, vk *RDKG.AggVerifKey, Gamma *bn256.G1, sig *Signature, attrs []*big.Int, id *big.Int, disclose []int) (*Theta, error) {
	if sig == nil || !validG1(sig.H, true) || !validG1(sig.S, false) || !validG1(Gamma, true) || len(attrs)+1 != len(vk.Betas) || !validScalar(id) {
		return nil, fmt.Errorf("invalid credential/schema")
	}
	values := append([]*big.Int{id}, attrs...)
	disclosed, hidden, err := partition(values, disclose)
	if err != nil {
		return nil, err
	}
	rp, err := randomScalar(false)
	if err != nil {
		return nil, err
	}
	re, err := randomScalar(false)
	if err != nil {
		return nil, err
	}
	rs, err := randomScalar(false)
	if err != nil {
		return nil, err
	}
	rprime, err := randomScalar(true)
	if err != nil {
		return nil, err
	}
	hp := new(bn256.G1).ScalarMult(sig.H, rprime)
	zp := new(bn256.G1).ScalarMult(sig.S, rprime)
	zp.Add(zp, new(bn256.G1).ScalarMult(hp, rs))
	eta := new(bn256.G2).Set(vk.Alpha)
	for _, j := range hidden {
		eta.Add(eta, new(bn256.G2).ScalarMult(vk.Betas[j], values[j]))
	}
	eta.Add(eta, new(bn256.G2).ScalarMult(params.G2, addScalar(rp, rs)))
	// Compute the identity encoding here (not cached) to match the paper's counting convention.
	u := new(bn256.G1).ScalarMult(params.G1, id)
	theta := &Theta{Kappa: eta, Nu: new(bn256.G1).ScalarMult(hp, rp), SigPrime: &Signature{H: hp, S: zp}, ElGamalCipher: &ElGamalCipher{A: new(bn256.G1).ScalarMult(params.G1, re), B: new(bn256.G1).Add(new(bn256.G1).ScalarMult(Gamma, re), u)}, Disclosed: disclosed}
	theta.PiV, err = MakePiH(params, vk, Gamma, theta, values, hidden, re, rp, rs)
	return theta, err
}

func VerifyTok(params *Params, vk *RDKG.AggVerifKey, Gamma *bn256.G1, theta *Theta, disclosed []DisclosedAttribute) (bool, error) {
	if theta == nil || theta.SigPrime == nil || theta.ElGamalCipher == nil || theta.PiV == nil || !validG1(Gamma, true) || !validG1(theta.SigPrime.H, true) || !validG1(theta.SigPrime.S, false) || !validG1(theta.Nu, false) || !validG1(theta.ElGamalCipher.A, false) || !validG1(theta.ElGamalCipher.B, false) || !validG2(theta.Kappa) {
		return false, fmt.Errorf("malformed presentation")
	}
	if !equalDisclosures(disclosed, theta.Disclosed) {
		return false, fmt.Errorf("disclosure mismatch")
	}
	ok, err := VerifyPiH(params, vk, Gamma, theta)
	if err != nil || !ok {
		return false, err
	}
	k := new(bn256.G2).Set(theta.Kappa)
	for _, a := range disclosed {
		k.Add(k, new(bn256.G2).ScalarMult(vk.Betas[a.Index], a.Value))
	}
	left := bn256.Pair(theta.SigPrime.H, k)
	right := bn256.Pair(new(bn256.G1).Add(theta.SigPrime.S, theta.Nu), vk.G2)
	return bytes.Equal(left.Marshal(), right.Marshal()), nil
}

func VerifyPartialCred(sig *Signature, attrs []*big.Int, vk *RDKG.VerifKey) (bool, error) {
	if sig == nil || !validG1(sig.H, true) || !validG1(sig.S, false) || len(attrs) != len(vk.BYs) {
		return false, fmt.Errorf("too many attributes for this verifier")
	}

	// k = AX + ∑ BY_j^m_j
	k := new(bn256.G2).Set(vk.AX)
	for j, m := range attrs {
		betaExp := new(bn256.G2).ScalarMult(vk.BYs[j], m)
		k.Add(k, betaExp)
	}

	left := bn256.Pair(sig.H, k)
	right := bn256.Pair(sig.S, vk.G2)
	return left.String() == right.String(), nil
}

func VerifyCred(sig *Signature, attrs []*big.Int, mpk *RDKG.AggVerifKey) (bool, error) {
	if sig == nil || !validG1(sig.H, true) || !validG1(sig.S, false) || len(attrs) != len(mpk.Betas) {
		return false, fmt.Errorf("too many attributes: got %d, max %d", len(attrs), len(mpk.Betas))
	}

	// k = α * ∏ β_j^m_j
	k := new(bn256.G2).Set(mpk.Alpha)
	for j, m := range attrs {
		betaExp := new(bn256.G2).ScalarMult(mpk.Betas[j], m)
		k.Add(k, betaExp)
	}

	// e(h, k)
	pair1 := bn256.Pair(sig.H, k)

	// e(s, g2)
	pair2 := bn256.Pair(sig.S, mpk.G2)

	return pair1.String() == pair2.String(), nil
}

//func Unblind(sig *BlindSignature, d *big.Int) *Signature {
//	// s = t3 - d·t2 = b - d·a
//	s := ElGamalDecrypt(d, sig.S[0], sig.S[1])
//	return &Signature{
//		H: sig.H,
//		S: s,
//	}
//}
//
//func AggCred(I []int, sigs []*Signature, par *vss.Par) (*Signature, error) {
//	if len(I) < par.Pub.T {
//		return nil, errors.New("not enough partial signatures to aggregate")
//	}
//
//	// 计算拉格朗日系数
//	lambdas, err := sss.PrecomputeLagCoef(par.Pub, I)
//	if err != nil {
//		return nil, err
//	}
//
//	// 聚合 S 部分
//	var commonH *bn256.G1
//	aggS := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // 初始化为 G1 群的 0 元
//
//	for i := 0; i < len(I); i++ {
//		idx := I[i]
//		sig := sigs[idx]
//		if sig == nil {
//			return nil, fmt.Errorf("signature at index %d is nil", idx)
//		}
//		if i == 0 {
//			commonH = sig.H
//		} else if sig.H.String() != commonH.String() {
//			return nil, errors.New("inconsistent H values among partial signatures")
//		}
//		term := new(bn256.G1).ScalarMult(sig.S, lambdas[i])
//		aggS = new(bn256.G1).Add(aggS, term)
//	}
//
//	return &Signature{
//		H: commonH,
//		S: aggS,
//	}, nil
//}
