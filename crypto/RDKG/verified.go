package RDKG

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG/sss"
	"EVOLV_DAO/crypto/RDKG/vss"
	"bytes"
	"fmt"
	"math/big"
)

// EvolveVerified is the local cryptographic resharing path used by revised tests.
// Transport, broadcast, complaint resolution and governance are outside this local simulation.
// No master secret is reconstructed. Old public shares are authenticated inputs.
func EvolveVerified(old []*SecretKey, public []*VerifKey, from, to *sss.PubPara, S []int) ([]*SecretKey, []*VerifKey, error) {
	if from == nil || to == nil || from.T < 1 || from.T > from.N || to.T < 1 || to.T > to.N || len(old) != from.N || len(public) != from.N || len(S) < from.T {
		return nil, nil, fmt.Errorf("invalid resharing parameters")
	}
	seen := map[int]bool{}
	for _, i := range S {
		if i < 0 || i >= from.N || seen[i] {
			return nil, nil, fmt.Errorf("invalid old subset")
		}
		seen[i] = true
	}
	q := len(old[S[0]].Ys)
	lambda, err := sss.PrecomputeLagCoef(from, S)
	if err != nil {
		return nil, nil, err
	}
	newSK := make([]*SecretKey, to.N)
	newVK := make([]*VerifKey, to.N)
	for j := 0; j < to.N; j++ {
		newSK[j] = &SecretKey{Ys: make([]*big.Int, q)}
		newVK[j] = &VerifKey{G2: public[S[0]].G2, BYs: make([]*bn256.G2, q)}
	}
	par, _ := vss.Setup(to.N, to.T)
	for a := 0; a <= q; a++ {
		accum := make([]*big.Int, to.N)
		for j := range accum {
			accum[j] = big.NewInt(0)
		}
		commitments := make([]*bn256.G2, to.T)
		for k := range commitments {
			commitments[k] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
		}
		expectedMaster := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
		for k, i := range S {
			if old[i] == nil || public[i] == nil || len(old[i].Ys) != q || len(public[i].BYs) != q {
				return nil, nil, fmt.Errorf("inconsistent old schema")
			}
			secret, pk := old[i].X, public[i].AX
			if a > 0 {
				secret, pk = old[i].Ys[a-1], public[i].BYs[a-1]
			}
			weighted := new(big.Int).Mod(new(big.Int).Mul(lambda[k], secret), from.Order)
			shares, com, _, _, err := vss.Share(weighted, par)
			if err != nil {
				return nil, nil, err
			}
			expected := new(bn256.G2).ScalarMult(pk, lambda[k])
			if !bytes.Equal(com[0].Marshal(), expected.Marshal()) {
				return nil, nil, fmt.Errorf("old share %d does not match authenticated public share", i)
			}
			expectedMaster.Add(expectedMaster, expected)
			for j := 0; j < to.N; j++ {
				check := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
				power := big.NewInt(1)
				x := big.NewInt(int64(j + 1))
				for _, c := range com {
					check.Add(check, new(bn256.G2).ScalarMult(c, power))
					power.Mul(power, x).Mod(power, to.Order)
				}
				if !bytes.Equal(new(bn256.G2).ScalarMult(par.G2, shares[j]).Marshal(), check.Marshal()) {
					return nil, nil, fmt.Errorf("invalid reshared evaluation")
				}
				accum[j].Add(accum[j], shares[j]).Mod(accum[j], to.Order)
			}
			for h, c := range com {
				commitments[h].Add(commitments[h], c)
			}
		}
		if !bytes.Equal(commitments[0].Marshal(), expectedMaster.Marshal()) {
			return nil, nil, fmt.Errorf("master public key changed")
		}
		for j, secret := range accum {
			pk := new(bn256.G2).ScalarMult(par.G2, secret)
			if a == 0 {
				newSK[j].X = secret
				newVK[j].AX = pk
			} else {
				newSK[j].Ys[a-1] = secret
				newVK[j].BYs[a-1] = pk
			}
		}
	}
	return newSK, newVK, nil
}
