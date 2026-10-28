package DAC

import (
	bn256 "EVOLV_DAO/bn256"
	"crypto/rand"
	"math/big"
)

type ElGamalCipher struct {
	A *bn256.G1
	B *bn256.G1
}

func ElGamalKeyGen(order *big.Int) (*big.Int, *bn256.G1, error) {
	d, err := randomScalar(true)
	if err != nil {
		return nil, nil, err
	}
	gamma := new(bn256.G1).ScalarBaseMult(d)
	return d, gamma, nil
}

func ElGamalEncrypt(gamma, h *bn256.G1, m *big.Int, order *big.Int) (*bn256.G1, *bn256.G1, *big.Int, error) {
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, nil, err
	}

	a := new(bn256.G1).ScalarBaseMult(k)         // a = k * g1
	hm := new(bn256.G1).ScalarMult(h, m)         // h^m
	kgamma := new(bn256.G1).ScalarMult(gamma, k) // k * gamma
	b := new(bn256.G1).Add(kgamma, hm)           // b = k * gamma + h^m

	return a, b, k, nil
}

func ElGamalDecrypt(d *big.Int, a, b *bn256.G1) *bn256.G1 {
	da := new(bn256.G1).ScalarMult(a, d)              // d * a
	mh := new(bn256.G1).Add(b, new(bn256.G1).Neg(da)) // b - d * a = h^m
	return mh
}
