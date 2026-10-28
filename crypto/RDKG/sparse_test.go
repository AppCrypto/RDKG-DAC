package RDKG

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/RDKG/resharing"
	"EVOLV_DAO/crypto/RDKG/sss"
	"math/big"
	"testing"
)

func TestSparseOriginalReconstruction(t *testing.T) {
	sk, _, _, _, _, e := GenPK(new(bn256.G2).ScalarBaseMult(big.NewInt(1)), bn256.Order, 1, 3, 5)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := sss.Setup(5, 3)
	x, ys, e := GenSK([]int{0, 1, 2}, sk, pub)
	if e != nil {
		t.Fatal(e)
	}
	sparse := []int{1, 3, 4}
	x2, y2, e := GenSK(sparse, sk, pub)
	if e != nil || x.Cmp(x2) != 0 || ys[0].Cmp(y2[0]) != 0 {
		t.Fatal("sparse master reconstruction", e)
	}
	to, _ := sss.Setup(7, 4)
	shares := make([]*big.Int, 5)
	for i := range shares {
		shares[i] = sk[i].X
	}
	mat, e := resharing.Reshare(to, shares)
	if e != nil {
		t.Fatal(e)
	}
	next, e := resharing.ReshareAgg(sparse, mat, pub)
	if e != nil {
		t.Fatal(e)
	}
	got, e := resharing.ReshareRec([]int{0, 2, 4, 6}, next, to)
	if e != nil || got.Cmp(x) != 0 {
		t.Fatal("sparse resharing", e)
	}
}
