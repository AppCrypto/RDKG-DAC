package resharing

import (
	"EVOLV_DAO/crypto/RDKG/sss"
	"fmt"
	"math/big"
)

func Reshare(pubp *sss.PubPara, oldShares []*big.Int) ([][]*big.Int, error) {
	newShares := make([][]*big.Int, len(oldShares))
	for i := 0; i < len(oldShares); i++ {
		newShares[i] = make([]*big.Int, pubp.N)
	}

	for i, si := range oldShares {
		subShares, err := sss.Share(pubp, si)
		if err != nil {
			fmt.Println("The ", i, "-th Share Falied!")
		}
		newShares[i] = subShares
	}
	return newShares, nil
}

// ReshareToNewGroupShares reshapes old shares to new shares for new group members.
// Input:
//   - newShares[i][j]: 第 i 个旧组成员给新组第 j 个成员的份额
//   - I: 旧组参与重构的索引
//   - pub: 原来的 pub 参数（含旧的 t 和 order）
//
// Output:
//   - reshared[j]: 新成员 j 的新份额 s'_j
func ReshareAgg(I []int, newShares [][]*big.Int, pub *sss.PubPara) ([]*big.Int, error) {
	nNew := len(newShares[0]) // 新组人数 = 每列长度
	reshared := make([]*big.Int, nNew)

	for j := 0; j < nNew; j++ {
		// 收集列元素：s_{i,j}
		columnShares := make([]*big.Int, pub.N)
		for _, i := range I {
			columnShares[i] = newShares[i][j]
		}

		// 使用旧的拉格朗日系数进行重构
		sj, err := sss.Recon(I, columnShares, pub)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct share for new member %d: %v", j, err)
		}
		reshared[j] = sj
	}
	return reshared, nil
}

func ReshareRec(I []int, reshared []*big.Int, pub *sss.PubPara) (*big.Int, error) {
	// 1. 检查输入合法性
	if len(I) < pub.T {
		return nil, fmt.Errorf("not enough shares to reconstruct the secret: need at least %d, got %d", pub.T, len(I))
	}
	if len(reshared) < pub.N {
		return nil, fmt.Errorf("reshared shares are incomplete: expected at least %d shares, got %d", pub.N, len(reshared))
	}

	// 2. 收集索引 I 对应的份额
	selectedShares := make([]*big.Int, pub.N)
	for _, i := range I {
		if i >= len(reshared) || i < 0 {
			return nil, fmt.Errorf("index out of bounds: %d", i)
		}
		selectedShares[i] = reshared[i]
	}

	// 3. 调用重构函数 Recon
	secret, err := sss.Recon(I, selectedShares, pub)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct secret: %v", err)
	}

	return secret, nil
}
