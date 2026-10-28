package sss

import (
	bn128 "EVOLV_DAO/bn256"
	"crypto/rand"
	"errors"
	"math/big"
)

// Public parameters
type PubPara struct {
	Order *big.Int
	N     int
	T     int
}

// var G = new(bn256.G1).ScalarBaseMult(big.NewInt(1))

// Generate public parameters
func Setup(n, t int) (*PubPara, error) {
	order := bn128.Order
	pub := &PubPara{
		Order: order,
		N:     n,
		T:     t,
	}
	return pub, nil
}

func Share(pub *PubPara, s *big.Int) ([]*big.Int, error) {
	// Generate a random polynomial (coefficients)
	coefficients := make([]*big.Int, pub.T)
	coefficients[0] = s
	for i := 1; i < pub.T; i++ {
		coefficients[i], _ = rand.Int(rand.Reader, pub.Order)
	}
	// Calculate the secret shares
	shares := make([]*big.Int, pub.N)
	for i := 0; i < pub.N; i++ {
		shares[i] = EvaluatePolynomial(coefficients, big.NewInt(int64(i+1)), pub.Order)
	}
	return shares, nil
}

func Share2(pub *PubPara, s *big.Int) ([]*big.Int, []*big.Int, error) {
	// Generate a random polynomial (coefficients)
	coefficients := make([]*big.Int, pub.T)
	coefficients[0] = s
	for i := 1; i < pub.T; i++ {
		coefficients[i], _ = rand.Int(rand.Reader, pub.Order)
	}
	// Calculate the secret shares
	shares := make([]*big.Int, pub.N)
	for i := 0; i < pub.N; i++ {
		shares[i] = EvaluatePolynomial(coefficients, big.NewInt(int64(i+1)), pub.Order)
	}
	return coefficients, shares, nil
}

// Reconstruct the secret
// I is the index of the shares used by the reconstruction
func Recon(I []int, shares []*big.Int, pub *PubPara) (*big.Int, error) {
	lambdas, err := PrecomputeLagCoef(pub, I)
	if err != nil {
		return nil, err
	}
	if len(shares) < pub.N {
		return nil, errors.New("expected index-addressed shares")
	}
	for _, i := range I {
		if shares[i] == nil {
			return nil, errors.New("missing selected share")
		}
	}
	secret := big.NewInt(0)
	for i := 0; i < len(I); i++ {
		lambda_i := lambdas[i]
		temp := new(big.Int).Mul(shares[I[i]], lambda_i)
		secret.Add(secret, temp)
		secret.Mod(secret, bn128.Order)
	}
	return secret, nil
}

// Precompute the coefficients of the Lagrange interpolation polynomial
func PrecomputeLagCoef(pub *PubPara, I []int) ([]*big.Int, error) {
	if pub == nil || pub.T < 1 || pub.T > pub.N || len(I) < pub.T {
		return nil, errors.New("not enough shares to recover the secret")
	}
	seen := map[int]bool{}
	for _, i := range I {
		if i < 0 || i >= pub.N || seen[i] {
			return nil, errors.New("invalid shareholder indices")
		}
		seen[i] = true
	}
	// Compute lambda: the Lagrange Coefficients
	lambdas := make([]*big.Int, len(I))
	for i := 0; i < len(I); i++ {
		alpha_i := big.NewInt(int64(I[i]) + 1)
		lambda_i := big.NewInt(1)
		for j := 0; j < len(I); j++ {
			if i != j {
				alpha_j := big.NewInt(int64(I[j]) + 1)
				// λ_i = λ_i * (0 - α_j) / (α_i - α_j) mod p
				num := new(big.Int).Sub(big.NewInt(0), alpha_j)
				den := new(big.Int).Sub(alpha_i, alpha_j)
				den.ModInverse(den, pub.Order)

				lambda_i.Mul(lambda_i, num)
				lambda_i.Mul(lambda_i, den)
				lambda_i.Mod(lambda_i, pub.Order)
			}
		}
		lambdas[i] = lambda_i
	}
	return lambdas, nil
}

// Compute the value of the polynomial point x
func EvaluatePolynomial(coefficients []*big.Int, x, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	xPower := new(big.Int).Set(x)

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		term.Mod(term, order)
		result.Add(result, term)
		result.Mod(result, order)
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, order)
	}

	return result
}
