package vss

import (
	bn256 "EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG/sss"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Reuse the pub struct of sss
type Par struct {
	Pub *sss.PubPara
	G2  *bn256.G2
}

func Setup(n, t int) (*Par, error) {
	pub, err := sss.Setup(n, t)
	if err != nil {
		fmt.Println("SSS Setup Failed!")
	}
	g := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	par := &Par{
		Pub: pub,
		G2:  g,
	}
	return par, nil
}

// VSS.Share
func Share(alpha0 *big.Int, par *Par) ([]*big.Int, []*bn256.G2, time.Duration, time.Duration, error) {
	alpha := make([]*big.Int, par.Pub.T)
	alpha[0] = alpha0
	Com := make([]*bn256.G2, par.Pub.T)
	Com[0] = new(bn256.G2).ScalarMult(par.G2, alpha0)
	timestart := time.Now()
	for i := 1; i < par.Pub.T; i++ {
		alpha[i], _ = rand.Int(rand.Reader, par.Pub.Order)
		Com[i] = new(bn256.G2).ScalarMult(par.G2, alpha[i])
	}
	t1 := time.Since(timestart)

	s := make([]*big.Int, par.Pub.N)
	timestart = time.Now()
	for i := 0; i < par.Pub.N; i++ {
		s[i] = sss.EvaluatePolynomial(alpha, big.NewInt(int64(i+1)), par.Pub.Order) //私🔑
	}
	t2 := time.Since(timestart)
	return s, Com, t1, t2, nil
}

// I is the index of shares
func Verify(I []int, shares []*bn256.G2, Com []*bn256.G2) (bool, error) {
	for i := 0; i < len(I); i++ {
		x := big.NewInt(int64(I[i]) + 1)
		left := shares[I[i]]
		right := Com[0]
		for j := 1; j < len(Com); j++ {
			term := new(bn256.G2).ScalarMult(Com[j], x.Exp(x, big.NewInt(int64(j)), nil))
			right = new(bn256.G2).Add(right, term)
		}
		if !(left.String() == right.String()) {
			fmt.Println("The ", i, "-th share is invalid")
			return false, errors.New("Invalid proof")
		}
		// fmt.Println("The ", i, "-th share is valid")
	}
	return true, nil
}

func Recon(I []int, s []*big.Int, par *Par) (*big.Int, error) {
	secret, err := sss.Recon(I, s, par.Pub)
	if err != nil {
		fmt.Println("SSS Recon Falied!")
	}
	return secret, nil
}

// 使用 share 中的 g2^s[i] 和拉格朗日系数恢复 g2^alpha0
func AggregatePubKey_G2(I []int, shares []*bn256.G2, par *Par) (*bn256.G2, error) {
	if len(I) < par.Pub.T {
		return nil, errors.New("not enough shares to recover public key")
	}

	lambdas, err := sss.PrecomputeLagCoef(par.Pub, I)
	if err != nil {
		return nil, err
	}

	agg := new(bn256.G2).ScalarBaseMult(big.NewInt(0)) // 初始化为 G2 群的 0 元

	for i := 0; i < len(I); i++ {
		term := new(bn256.G2).ScalarMult(shares[I[i]], lambdas[i])
		agg = new(bn256.G2).Add(agg, term)
	}

	return agg, nil
}

func AggregatePubKey_G1(I []int, shares []*bn256.G1, par *Par) (*bn256.G1, error) {
	if len(I) < par.Pub.T {
		return nil, errors.New("not enough shares to recover public key")
	}

	lambdas, err := sss.PrecomputeLagCoef(par.Pub, I)
	if err != nil {
		return nil, err
	}

	agg := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // 初始化为 G2 群的 0 元

	for i := 0; i < len(I); i++ {
		term := new(bn256.G1).ScalarMult(shares[I[i]], lambdas[i])
		agg = new(bn256.G1).Add(agg, term)
	}

	return agg, nil
}

// VerifySingleShare 验证单个 VSS 分享是否合法
func VerifySingleShare(index int, share *bn256.G2, com []*bn256.G2) (bool, error) {
	x := big.NewInt(int64(index + 1)) // 索引从 1 开始
	right := new(bn256.G2).Set(com[0])

	xPower := new(big.Int).Set(x)
	for j := 1; j < len(com); j++ {
		term := new(bn256.G2).ScalarMult(com[j], xPower)
		right.Add(right, term)
		xPower.Mul(xPower, x)
	}

	if share.String() != right.String() {
		return false, errors.New("invalid share: does not match commitment")
	}
	return true, nil
}
