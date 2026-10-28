package RDKG

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG/resharing"
	"EVOLV_DAO/crypto/RDKG/sss"
	"EVOLV_DAO/crypto/RDKG/vss"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

type SecretKey struct {
	X  *big.Int
	Ys []*big.Int
}

type AggVerifKey struct {
	G2    *bn256.G2
	Alpha *bn256.G2   // g2^v_0
	Betas []*bn256.G2 // g2^v_1 ... g2^v_q
}

type VerifKey struct {
	G2  *bn256.G2
	AX  *bn256.G2
	BYs []*bn256.G2
}

func GenPK(
	g2 *bn256.G2,
	order *big.Int,
	q, t, n int,
) ([]*SecretKey, []*VerifKey, *AggVerifKey, [][][]*bn256.G2, []time.Duration, error) {
	par, _ := vss.Setup(n, t)

	SecretKeys := make([]*SecretKey, n)
	VerifKeys := make([]*VerifKey, n)
	Coms := make([][][]*bn256.G2, n) // [n][q+1][t]
	for i := 0; i < n; i++ {
		SecretKeys[i] = &SecretKey{Ys: make([]*big.Int, q)}
		VerifKeys[i] = &VerifKey{G2: g2, BYs: make([]*bn256.G2, q)}
		Coms[i] = make([][]*bn256.G2, q+1)
	}
	com_cost := time.Duration(0)
	share_cost := time.Duration(0)
	skShares := make([][][]*big.Int, q+1)
	for j := 0; j <= q; j++ {
		skShares[j] = make([][]*big.Int, n)
		for i := 0; i < n; i++ {
			vij, _ := rand.Int(rand.Reader, order)
			sks, com, t1, t2, _ := vss.Share(vij, par)
			skShares[j][i] = sks
			Coms[i][j] = com
			com_cost += t1
			share_cost += t2
		}
	}
	com_cost = com_cost / time.Duration(n)
	share_cost = share_cost / time.Duration(n)

	for i := 0; i < n; i++ {
		for j := 0; j <= q; j++ {
			sum := big.NewInt(0)
			for k := 0; k < n; k++ {
				sum.Add(sum, skShares[j][k][i])
				sum.Mod(sum, order)
			}
			if j == 0 {
				SecretKeys[i].X = sum
				VerifKeys[i].AX = new(bn256.G2).ScalarMult(g2, sum)
			} else {
				SecretKeys[i].Ys[j-1] = sum
				VerifKeys[i].BYs[j-1] = new(bn256.G2).ScalarMult(g2, sum)
			}
		}
	}

	I := make([]int, t)
	for i := 0; i < t; i++ {
		I[i] = i
	}

	axShares := make([]*bn256.G2, n)
	for i := 0; i < n; i++ {
		axShares[i] = VerifKeys[i].AX
	}
	alpha, _ := vss.AggregatePubKey_G2(I, axShares, par)

	betas := make([]*bn256.G2, q)
	for j := 0; j < q; j++ {
		byj := make([]*bn256.G2, n)
		for i := 0; i < n; i++ {
			byj[i] = VerifKeys[i].BYs[j]
		}
		betas[j], _ = vss.AggregatePubKey_G2(I, byj, par)
	}

	masterVK := &AggVerifKey{
		G2:    g2,
		Alpha: alpha,
		Betas: betas,
	}
	return SecretKeys, VerifKeys, masterVK, Coms, []time.Duration{com_cost, share_cost}, nil
}

func GenSK(I []int, sks []*SecretKey, pub *sss.PubPara) (*big.Int, []*big.Int, error) {
	if len(I) < pub.T {
		return nil, nil, fmt.Errorf("not enough shares to reconstruct the key")
	}

	// 提取 X 值：每个 SecretKey 的 X 是 v_0 对应份额
	xShares := make([]*big.Int, len(sks))
	for i := 0; i < len(I); i++ {
		xShares[I[i]] = sks[I[i]].X
	}

	// 重建主私钥 x = v_0
	masterX, err := sss.Recon(I, xShares, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct master secret: %v", err)
	}

	// 如果需要恢复每个属性对应的 v_j（j >= 1），也可以：
	q := len(sks[I[0]].Ys)
	masterYs := make([]*big.Int, q)
	for j := 0; j < q; j++ {
		yShares := make([]*big.Int, len(sks))
		for i := 0; i < len(I); i++ {
			yShares[I[i]] = sks[I[i]].Ys[j]
		}
		masterYs[j], _ = sss.Recon(I, yShares, pub)
	}

	return masterX, masterYs, nil
}

func Evolve(
	oldShares []*SecretKey, // 原组份额
	pub, pubp *sss.PubPara, // 原组阈值参数 // 新组阈值参数
) ([]*SecretKey, *big.Int, []*big.Int, time.Duration, error) {
	q := len(oldShares[0].Ys)
	nNew := pubp.N

	I := make([]int, pub.T)
	for i := 0; i < pub.T; i++ {
		I[i] = i
	}

	// 1. 拆解出 xShares 和每个 yShares[j]
	xShares := make([]*big.Int, len(I))
	yShares := make([][]*big.Int, q)
	for j := 0; j < q; j++ {
		yShares[j] = make([]*big.Int, len(I))
	}
	for i, idx := range I {
		xShares[i] = oldShares[idx].X
		for j := 0; j < q; j++ {
			yShares[j][i] = oldShares[idx].Ys[j]
		}
	}

	time_start := time.Now()
	// 2. Reshare 所有份额（对每个 v_j 再分享成 nNew 个）
	resharedX, _ := resharing.Reshare(pubp, xShares) // [][]*big.Int: i × j
	resharedYs := make([][][]*big.Int, q)
	for j := 0; j < q; j++ {
		resharedYs[j], _ = resharing.Reshare(pubp, yShares[j])
	}

	// 3. 利用 ReshareAgg 聚合每列（按新成员 j 收集）
	newX, err := resharing.ReshareAgg(I, resharedX, pub)
	if err != nil {
		return nil, nil, nil, time.Duration(0), fmt.Errorf("combine for x failed: %v", err)
	}

	newYs := make([][]*big.Int, q)
	for j := 0; j < q; j++ {
		newYs[j], err = resharing.ReshareAgg(I, resharedYs[j], pub)
		if err != nil {
			return nil, nil, nil, time.Duration(0), fmt.Errorf("combine for y[%d] failed: %v", j, err)
		}
	}
	time_cost := time.Since(time_start)

	// 4. 组装新的 SecretKey
	newShares := make([]*SecretKey, nNew)
	for j := 0; j < nNew; j++ {
		yList := make([]*big.Int, q)
		for i := 0; i < q; i++ {
			yList[i] = newYs[i][j]
		}
		newShares[j] = &SecretKey{
			X:  newX[j],
			Ys: yList,
		}
	}

	// 5. 可选：恢复主密钥以校验一致性
	J := make([]int, pubp.T)
	for i := 0; i < pubp.T; i++ {
		J[i] = i
	}
	masterX, masterYs, err := GenSK(J, newShares, pubp)
	if err != nil {
		return nil, nil, nil, time.Duration(0), fmt.Errorf("failed to reconstruct final secret: %v", err)
	}

	return newShares, masterX, masterYs, time_cost, nil
}
