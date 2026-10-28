package resharing

import (
	"EVOLV_DAO/crypto/RDKG/sss"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestResharing(t *testing.T) {
	n := 5          // 原始参与者数量
	threshold := 3  // 原始阈值
	np := 7         // 新组参与者数量
	thresholdp := 5 // 新组阈值

	pub, _ := sss.Setup(n, threshold)
	pubp, _ := sss.Setup(np, thresholdp)

	// 随机生成一个秘密
	s, _ := rand.Int(rand.Reader, pub.Order)

	// 原始分享
	oldShares, err := sss.Share(pub, s)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	// 从原始份额重新共享：每个旧节点将自己的份额再分享给新组成员
	newShares, err := Reshare(pubp, oldShares) // newShares[i][j] 表示旧节点 i 给新节点 j 的份额
	if err != nil {
		t.Fatalf("Reshare failed: %v", err)
	}

	// 每个新组成员 j 收到来自 I 中旧节点的份额 s_{i,j}
	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i
	}

	newSharesForNewGroup, _ := ReshareAgg(I, newShares, pub)

	// 新组成员重构秘密
	J := make([]int, thresholdp)
	for i := 0; i < thresholdp; i++ {
		J[i] = i
	}

	// 最终重构原始秘密
	recovered, err := ReshareRec(J, newSharesForNewGroup, pubp)
	if err != nil {
		t.Fatalf("Final reconstruction failed: %v", err)
	}

	fmt.Println("original secret =", s)
	fmt.Println("recovered secret =", recovered)

	if recovered.Cmp(s) != 0 {
		t.Fatal("Reconstructed secret does not match original")
	}
}
