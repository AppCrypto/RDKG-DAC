package Convert

import (
	"EVOLV_DAO/compile/contract"
	"encoding/base64"
	"math/big"

	bn256 "EVOLV_DAO/bn256"
)

func G1ToG1Point(bn256Point *bn256.G1) contract.DACG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	point := bn256Point.Marshal()

	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(point[:32])
	y := new(big.Int).SetBytes(point[32:64])

	g1Point := contract.DACG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G1PointToG1(g1point contract.DACG1Point) *bn256.G1 {
	// 将 x 和 y 转换为字节数组
	xBytes := g1point.X.Bytes()
	yBytes := g1point.Y.Bytes()

	// 将两个字节数组拼接起来
	decodedBytes := append(xBytes, yBytes...)
	g1 := new(bn256.G1)
	g1.Unmarshal(decodedBytes)
	return g1
}

func G2ToG2Point(point *bn256.G2) contract.DACG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := contract.DACG2Point{
		X: [2]*big.Int{a1, a2},
		Y: [2]*big.Int{b1, b2},
	}
	return g2Point
}

func FlattenG2Array(points [][]*bn256.G2) [][4]*big.Int {
	var flat [][4]*big.Int
	for i := 0; i < len(points); i++ {
		for j := 0; j < len(points[i]); j++ {
			pt := points[i][j]
			ptBytes := pt.Marshal()

			X0 := new(big.Int).SetBytes(ptBytes[:32])
			X1 := new(big.Int).SetBytes(ptBytes[32:64])
			Y0 := new(big.Int).SetBytes(ptBytes[64:96])
			Y1 := new(big.Int).SetBytes(ptBytes[96:128])

			flat = append(flat, [4]*big.Int{X0, X1, Y0, Y1})
		}
	}
	return flat
}

func G2ToG2Point2(point *bn256.G2) contract.DACG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := contract.DACG2Point{
		X: [2]*big.Int{a2, a1},
		Y: [2]*big.Int{b2, b1},
	}
	return g2Point
}

func G2PointToG2(g2point contract.DACG2Point) *bn256.G2 {
	// 将 X 和 Y 中的每个元素转换为字节数组
	x1Bytes := g2point.X[0].Bytes()
	x2Bytes := g2point.X[1].Bytes()
	y1Bytes := g2point.Y[0].Bytes()
	y2Bytes := g2point.Y[1].Bytes()

	// 将四个字节数组拼接成一个完整的字节数组
	decodedBytes := append(x1Bytes, x2Bytes...)
	decodedBytes = append(decodedBytes, y1Bytes...)
	decodedBytes = append(decodedBytes, y2Bytes...)

	g2 := new(bn256.G2)
	g2.Unmarshal(decodedBytes)
	return g2
}

// GTToString 将 bn256.GT 元素编码为 Base64 字符串
func GTToString(gt *bn256.GT) string {

	// 使用 Marshal 将 GT 序列化为字节切片
	gtBytes := gt.Marshal()

	// 使用 Base64 编码为字符串
	encoded := base64.StdEncoding.EncodeToString(gtBytes)
	return encoded
}

// StringToGT 从 Base64 字符串解码还原 bn256.GT 元素
func StringToGT(encoded string) *bn256.GT {
	// 使用 Base64 解码为字节切片
	decodedBytes, _ := base64.StdEncoding.DecodeString(encoded)
	// 使用 Unmarshal 还原为 GT 元素
	gt := new(bn256.GT)
	gt.Unmarshal(decodedBytes)
	return gt
}

func G1ToBigIntArray(point *bn256.G1) [2]*big.Int {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()

	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	return [2]*big.Int{x, y}
}
