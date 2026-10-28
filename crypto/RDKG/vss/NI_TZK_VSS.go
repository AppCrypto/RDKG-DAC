package vss

import (
	"EVOLV_DAO/crypto/RDKG/sss"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"
)

// --- Hash 函数 ---

// C: 将两个 []byte 映射为 []byte
func HashC(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// H: 将 []byte 映射为有限域内整数
func HashH(data []byte, order *big.Int) *big.Int {
	h := sha256.Sum256(data)
	return new(big.Int).SetBytes(h[:]).Mod(new(big.Int).SetBytes(h[:]), order)
}

// 拼接二维 byte 数组为一个 byte 串
func ConcatBytes(arr [][]byte) []byte {
	var result []byte
	for _, b := range arr {
		result = append(result, b...)
	}
	return result
}

// 检查 C 是否匹配
func HashCEqual(expected []byte, a, b *big.Int) bool {
	actual := HashC(a.Bytes(), b.Bytes())
	return bytes.Equal(expected, actual)
}

// --- 多项式评估函数 ---

func Prove(pub *sss.PubPara) (
	C [][]byte, CPrime [][]byte, rCoeffs []*big.Int, proofY [][2]*big.Int, x []*big.Int, share_cost time.Duration, prove_cost time.Duration, err error,
) {
	// 随机生成 secret
	secret, _ := rand.Int(rand.Reader, pub.Order)

	time_start := time.Now()
	// 生成 f(x) 多项式并分享
	fCoeffs, x, _ := sss.Share2(pub, secret)
	share_cost = time.Since(time_start)

	time_start = time.Now()
	// 1. b(X) ∈ Z_N[X]_t
	bCoeffs := make([]*big.Int, pub.T)
	for i := 0; i < pub.T; i++ {
		bCoeffs[i], _ = rand.Int(rand.Reader, pub.Order)
	}

	bi := make([]*big.Int, pub.N)
	// 5. 计算 r(x_i)
	for i := 0; i < pub.N; i++ {
		bi[i] = sss.EvaluatePolynomial(bCoeffs, big.NewInt(int64(i+1)), pub.Order)
	}

	C = make([][]byte, pub.N)
	CPrime = make([][]byte, pub.N)
	proofY = make([][2]*big.Int, pub.N)

	// 2. 随机采样 y_i, y_i′
	for i := 0; i < pub.N; i++ {
		yi, _ := rand.Int(rand.Reader, pub.Order)
		yip, _ := rand.Int(rand.Reader, pub.Order)

		xi := x[i]
		C[i] = HashC(bi[i].Bytes(), yi.Bytes())
		CPrime[i] = HashC(xi.Bytes(), yip.Bytes())
		proofY[i] = [2]*big.Int{yi, yip}
	}

	// 3. 计算 d = H(C, C′)
	d := HashH(ConcatBytes(append(C, CPrime...)), pub.Order)

	// 4. r(X) = b(X) - d ⋅ f(X)
	rCoeffs = make([]*big.Int, pub.T)
	for i := 0; i < pub.T; i++ {
		tmp := new(big.Int).Mul(d, fCoeffs[i])
		rCoeffs[i] = new(big.Int).Sub(bCoeffs[i], tmp)
		rCoeffs[i].Mod(rCoeffs[i], pub.Order)
	}
	prove_cost = time.Since(time_start)

	return C, CPrime, rCoeffs, proofY, x, share_cost, prove_cost, nil
}

// --- Verifier 实现 ---

func Single_verify(
	pub *sss.PubPara,
	i int, // 要验证的索引
	x *big.Int, // 第 i 个参与者的 x_i
	C, CPrime [][]byte, // 所有 C_i 和 C_i′
	rCoeffs []*big.Int, // r(X) 的多项式系数
	proofY [2]*big.Int, // 第 i 个参与者的 (y_i, y_i′)
) (bool, time.Duration) {
	if i < 0 || i >= pub.N {
		return false, time.Duration(0) // 索引非法
	}

	Ci := C[i]
	CiPrime := CPrime[i]
	yi := proofY[0]
	yip := proofY[1]

	// 1. 全局挑战 d = H(C, C′)
	d := HashH(ConcatBytes(append(C, CPrime...)), pub.Order)

	time_start := time.Now()
	// 2. 验证 C′_i == C(x_i, y_i′)
	if !HashCEqual(CiPrime, x, yip) {
		return false, time.Duration(0)
	}

	// 3. 评估 r(x_i)
	rxi := sss.EvaluatePolynomial(rCoeffs, big.NewInt(int64(i+1)), pub.Order)

	// 4. 验证 C_i == C(r(x_i) + d⋅x_i, y_i)
	dx := new(big.Int).Mul(d, x)
	lhs := new(big.Int).Add(rxi, dx)
	lhs.Mod(lhs, pub.Order)

	if !HashCEqual(Ci, lhs, yi) {
		return false, time.Duration(0)
	}
	time_cost := time.Since(time_start)

	return true, time_cost
}
