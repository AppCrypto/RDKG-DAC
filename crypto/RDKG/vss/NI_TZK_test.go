package vss

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG/sss"
	"math/big"
	"testing"
	"time"
)

func TestNITZK(t *testing.T) {
	order := bn256.Order
	pub := &sss.PubPara{
		T:     3,
		N:     5,
		Order: order,
	}
	rounds := 100

	type BroadcastMsg struct {
		C       [][]byte
		CPrime  [][]byte
		RCoeffs []*big.Int
		ProofY  [][2]*big.Int
		Shares  []*big.Int
	}

	N := pub.N
	messages := make([]*BroadcastMsg, N)
	for i := 0; i < N; i++ {
		C, CPrime, rCoeffs, proofY, shares, _, _, _ := Prove(pub)
		messages[i] = &BroadcastMsg{
			C:       C,
			CPrime:  CPrime,
			RCoeffs: rCoeffs,
			ProofY:  proofY,
			Shares:  shares,
		}
	}

	time_cost := time.Duration(0)
	for k := 0; k < rounds; k++ {
		finalSecrets := make([]*big.Int, N)
		for i := 0; i < N; i++ {
			finalSecrets[i] = new(big.Int).Set(messages[i].Shares[i])
			for j := 0; j < N; j++ {
				if i == j {
					continue
				}
				msg := messages[j]
				time_start := time.Now()
				ok, _ := Single_verify(pub, i, msg.Shares[i], msg.C, msg.CPrime, msg.RCoeffs, msg.ProofY[i])
				time_cost += time.Since(time_start)
				if ok {
					finalSecrets[i].Add(finalSecrets[i], msg.Shares[i])
					finalSecrets[i].Mod(finalSecrets[i], pub.Order)
				} else {
					t.Errorf("Party %d rejected share from Party %d", i+1, j+1)
				}
			}
		}
	}
	t.Logf("平均验证时间: %s per person\n", time_cost/time.Duration(N*rounds))
}
