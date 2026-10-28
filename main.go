package main

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/compile/contract"
	"EVOLV_DAO/crypto/Convert"
	"EVOLV_DAO/crypto/DAC"
	"EVOLV_DAO/crypto/RDKG"
	"EVOLV_DAO/crypto/RDKG/sss"
	"EVOLV_DAO/crypto/RDKG/vss"
	"EVOLV_DAO/internal/benchfixture"
	"EVOLV_DAO/utils"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math/big"
	"time"
)

func InitAndDeployContract(contractName string, rpcURL string, privateKey string) (*contract.Contract, *ethclient.Client, common.Address) {
	// Connect to Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// Create transaction auth
	auth := utils.Transact(client, privateKey, big.NewInt(0))

	// Deploy contract
	address, _ := utils.Deploy(client, contractName, auth)

	// Bind contract instance
	ctc, err := contract.NewContract(common.HexToAddress(address.Hex()), client)
	if err != nil {
		log.Fatalf("Failed to bind contract instance: %v", err)
	}

	fmt.Println("...........................................................System Initialization............................................................")
	fmt.Println("Contract deployed at:", address.Hex())

	return ctc, client, address
}

func AggregateComs(coms [][][]*bn256.G2) [][]*bn256.G2 {
	if len(coms) == 0 {
		return nil
	}
	n := len(coms)
	qPlus1 := len(coms[0])
	t := len(coms[0][0])

	agg := make([][]*bn256.G2, qPlus1)
	for j := 0; j < qPlus1; j++ {
		agg[j] = make([]*bn256.G2, t)
		for k := 0; k < t; k++ {
			agg[j][k] = new(bn256.G2)
			for i := 0; i < n; i++ {
				agg[j][k].Add(agg[j][k], coms[i][j][k])
			}
		}
	}
	return agg
}

func uploadComsForAllMembers(client *ethclient.Client, ctc *contract.Contract, priv string, coms [][][]*bn256.G2, q, t int) {
	for i := 0; i < len(coms); i++ {
		auth := utils.Transact(client, priv, big.NewInt(0))
		tx, err := ctc.UploadComs(auth, big.NewInt(int64(i+1)), big.NewInt(int64(q+1)), big.NewInt(int64(t)), Convert.FlattenG2Array(coms[i]))
		if err != nil {
			fmt.Printf("UploadComs failed for member %d: %v\n", i+1, err)
		} else {
			fmt.Printf("UploadComs succeeded for member %d\n", i+1)
		}
		receipt, err := bind.WaitMined(context.Background(), client, tx)
		if err != nil {
			fmt.Println("Tx receipt error:", err)
		} else {
			fmt.Printf("Gas Used for Upload commitments: %d\n", receipt.GasUsed)
		}
	}

}

func verifyAllAttributesOnChain(client *ethclient.Client, ctc *contract.Contract, priv string, vk *RDKG.VerifKey, q, t int) {
	for i := 0; i <= q; i++ {
		auth := utils.Transact(client, priv, big.NewInt(0))

		var tx *types.Transaction
		var err error

		if i == 0 {
			tx, err = ctc.VerifySingleShare(auth, big.NewInt(2), big.NewInt(int64(i)), big.NewInt(int64(t)), Convert.G2ToG2Point(vk.AX))
		} else {
			tx, err = ctc.VerifySingleShare(auth, big.NewInt(2), big.NewInt(int64(i)), big.NewInt(int64(t)), Convert.G2ToG2Point(vk.BYs[i-1]))
		}

		if err != nil {
			fmt.Printf("VerifySingleShare failed for q=%d: %v\n", i, err)
			continue
		}

		result, _ := ctc.GetPKResult(nil)
		fmt.Printf("On-chain PK verify (q=%d): %v\n", i, result)

		receipt, err := bind.WaitMined(context.Background(), client, tx)
		if err != nil {
			fmt.Println("Tx receipt error:", err)
		} else {
			fmt.Printf("VerifySingleShare Gas Used for q=%d: %d\n", i, receipt.GasUsed)
		}
	}
}

func verifyAllMembersOffChain(vks []*RDKG.VerifKey, agg_coms [][]*bn256.G2, q int) {
	for i := 0; i < len(vks); i++ {
		vk := vks[i]
		allValid := true

		for j := 0; j <= q; j++ {
			var result bool
			var err error
			if j == 0 {
				result, err = vss.VerifySingleShare(i, vk.AX, agg_coms[j])
			} else {
				result, err = vss.VerifySingleShare(i, vk.BYs[j-1], agg_coms[j])
			}
			if !result {
				fmt.Printf("Off-chain verification failed: member %d attr %d: %v\n", i, j, err)
				allValid = false
			}
		}

		fmt.Printf("DAO member %d public key verification: %v\n", i, allValid)
	}
}

func testRDKGEvolution(SKs []*RDKG.SecretKey, t, n, tNew, nNew int) {
	I := make([]int, t)
	for i := 0; i < t; i++ {
		I[i] = i
	}
	J := make([]int, tNew)
	for i := 0; i < tNew; i++ {
		J[i] = i
	}
	pub, _ := sss.Setup(n, t)
	pubp, _ := sss.Setup(nNew, tNew)

	masterX, masterYs, _ := RDKG.GenSK(I, SKs, pub)

	newSKs, _, _, _, err := RDKG.Evolve(SKs, pub, pubp)
	if err != nil {
		panic("Evolve failed: " + err.Error())
	}

	recoveredX, recoveredYs, err := RDKG.GenSK(J, newSKs, pubp)
	if err != nil {
		panic("GenSK from new shares failed: " + err.Error())
	}

	fmt.Println("\n验证 RDKG Evolve 主密钥一致性：")
	fmt.Printf("Recovered X: %s\n", recoveredX.String())
	fmt.Printf("Expected X : %s\n", masterX.String())
	fmt.Println("Match X?   :", recoveredX.Cmp(masterX) == 0)

	for i := range masterYs {
		fmt.Printf("Recovered Y[%d]: %s\n", i, recoveredYs[i].String())
		fmt.Printf("Expected  Y[%d]: %s\n", i, masterYs[i].String())
		fmt.Println("Match?         :", recoveredYs[i].Cmp(masterYs[i]) == 0)
	}
}

// test operate cost on NI-VSS
func NI_TZK_TEST() {
	contractName := "DAC"
	rpcURL := "http://127.0.0.1:8545"
	privateKey := utils.GetENV("PRIVATE_KEY_1")
	ctc, client, _ := InitAndDeployContract(contractName, rpcURL, privateKey)
	order := bn256.Order
	rounds := 1000
	fmt.Println("验证不同阈值结构 (t, n=2t-1) 下每轮验证的平均时间开销：")
	for tVal := 2; tVal <= 6; tVal++ {
		nVal := 2*tVal - 1
		pub := &sss.PubPara{
			T:     tVal,
			N:     nVal,
			Order: order,
		}
		fmt.Printf("Threshold t=%d, n=%d:\n", tVal, nVal)

		type BroadcastMsg struct {
			C       [][]byte
			CPrime  [][]byte
			RCoeffs []*big.Int
			ProofY  [][2]*big.Int
			Shares  []*big.Int // 每个人的份额
		}

		N := pub.N
		messages := make([]*BroadcastMsg, N)

		share_cost := time.Duration(0)
		prove_cost := time.Duration(0)
		verify_cost := time.Duration(0)
		for k := 0; k < rounds; k++ {
			// 所有人生成各自的 VSS.Prove，广播给别人
			for i := 0; i < N; i++ {
				C, CPrime, rCoeffs, proofY, shares, t1, t2, _ := vss.Prove(pub)
				share_cost += t1
				prove_cost += t2
				messages[i] = &BroadcastMsg{
					C:       C,
					CPrime:  CPrime,
					RCoeffs: rCoeffs,
					ProofY:  proofY,
					Shares:  shares,
				}
			}
			if k == 0 {
				auth := utils.Transact(client, privateKey, big.NewInt(0))
				txt, _ := ctc.UploadCommitment(auth, big.NewInt(int64(tVal-1)), messages[int64(tVal-2)].C, messages[int64(tVal-2)].CPrime, messages[int64(tVal-2)].RCoeffs)
				receipt, err := bind.WaitMined(context.Background(), client, txt)
				if err != nil {
					fmt.Println("Tx receipt error:", err)
				} else {
					fmt.Printf("Gas Used for Upload commitments: %d\n", receipt.GasUsed)
				}
				d_offchain := vss.HashH(vss.ConcatBytes(append(messages[int64(tVal-2)].C, messages[int64(tVal-2)].CPrime...)), order)
				d_onchain, _ := ctc.HashH(nil, big.NewInt(int64(tVal-1)), order)
				fmt.Printf("Compute challenge on chain: %v\n", d_offchain.String() == d_onchain.String())

				auth1 := utils.Transact(client, privateKey, big.NewInt(0))
				txt, _ = ctc.TestHashH(auth1, big.NewInt(int64(tVal-1)), order)
				receipt, err = bind.WaitMined(context.Background(), client, txt)
				if err != nil {
					fmt.Println("Tx receipt error:", err)
				} else {
					fmt.Printf("Gas Used for Compute Challenge: %d\n", receipt.GasUsed)
				}

			}

			finalSecrets := make([]*big.Int, N)
			for i := 0; i < N; i++ {
				finalSecrets[i] = new(big.Int).Set(messages[i].Shares[i])
				for j := 0; j < N; j++ {
					if i == j {
						continue
					}
					msg := messages[j]
					ok, time_cost := vss.Single_verify(pub, i, msg.Shares[i], msg.C, msg.CPrime, msg.RCoeffs, msg.ProofY[i])
					verify_cost += time_cost
					if ok {
						finalSecrets[i].Add(finalSecrets[i], msg.Shares[i])
						finalSecrets[i].Mod(finalSecrets[i], pub.Order)
					} else {
						fmt.Printf("Party %d rejected share from Party %d\n", i+1, j+1)
					}
				}
			}
		}

		// 输出该 (t,n) 下每人每轮平均验证开销
		totalVerifications := time.Duration(N * rounds)

		fmt.Printf("每人每轮平均share时间 = %s\n", share_cost/totalVerifications)
		fmt.Printf("每人每轮平均prove时间 = %s\n", prove_cost/totalVerifications)
		fmt.Printf("每人每轮平均verify时间 = %s\n", verify_cost/totalVerifications)
	}
}

func RDKG_TEST() {
	contractName := "DAC"
	rpcURL := "http://127.0.0.1:8545"
	privateKey := utils.GetENV("PRIVATE_KEY_1")
	ctc, client, _ := InitAndDeployContract(contractName, rpcURL, privateKey)
	// === Parameter setup ===
	n := 11   // Original group size
	t := 6    // Original group threshold
	nNew := 8 // New group size
	tNew := 5 // New group threshold
	q := 1    // Number of attributes

	order := bn256.Order
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	//=== 1. Generate original key pairs ===
	SKs, vks, _, coms, time_cost, err := RDKG.GenPK(g2, order, q, t, n)
	if err != nil {
		panic("GenPK failed: " + err.Error())
	}
	fmt.Printf("Avg commitment generated time cost:%s\n", time_cost[0])
	fmt.Printf("Avg secret share generated time cost:%s\n", time_cost[1])

	// === 2. Upload commitments to chain ===
	uploadComsForAllMembers(client, ctc, privateKey, coms, q, t)

	// === 3. Aggregate commitments on chain ===
	auth2 := utils.Transact(client, privateKey, big.NewInt(0))
	txt, _ := ctc.AggregateAllComs(auth2, big.NewInt(int64(n)), big.NewInt(int64(q+1)), big.NewInt(int64(t)))
	receipt, err := bind.WaitMined(context.Background(), client, txt)
	if err != nil {
		fmt.Println("Tx receipt error:", err)
	} else {
		fmt.Printf("Gas Used for aggregated commitment: %d\n", receipt.GasUsed)
	}

	//agg_coms := AggregateComs(coms)

	// === 4. On-chain verify all attributes of a member ===
	verifyAllAttributesOnChain(client, ctc, privateKey, vks[2], q, t)

	// === 5. Upload PK to chain ===
	auth3 := utils.Transact(client, privateKey, big.NewInt(0))
	txt, _ = ctc.UploadPK(auth3, big.NewInt(int64(1)), big.NewInt(int64(0)), Convert.G2ToG2Point(vks[0].AX))
	receipt, err = bind.WaitMined(context.Background(), client, txt)
	if err != nil {
		fmt.Println("Tx receipt error:", err)
	} else {
		fmt.Printf("Gas Used for upload single PK: %d\n", receipt.GasUsed)
	}

	// === 5. Off-chain verify all members' PK ===
	//verifyAllMembersOffChain(vks, agg_coms, q)

	// === 6. RDKG evolution and test ===
	testRDKGEvolution(SKs, t, n, tNew, nNew)
}

func Evolv_timecost() {
	type Param struct {
		n int
		t int
	}

	params := []Param{
		{n: 5, t: 3},
		{n: 7, t: 4},
		{n: 9, t: 5},
	}

	q := 0          // Number of attributes
	rounds := 10000 // Number of test rounds
	order := bn256.Order
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	for _, p := range params {
		n := p.n
		t := p.t

		//=== Generate original key pairs ===
		SKs, _, _, _, _, _ := RDKG.GenPK(g2, order, q, t, n)
		pubOld, _ := sss.Setup(n, t)

		fmt.Printf("原始结构: n=%d, t=%d\n", n, t)
		fmt.Println("tNew, nNew, 平均Evolve时间(µs):")

		for tNew := 2; tNew <= 6; tNew++ {
			nNew := 2*tNew - 1
			pubNew, _ := sss.Setup(nNew, tNew)

			totalTime := time.Duration(0)

			for i := 0; i < rounds; i++ {
				_, _, _, t1, _ := RDKG.Evolve(SKs, pubOld, pubNew)
				totalTime += t1
			}

			avgTime := float64(totalTime.Microseconds()) / float64(rounds)
			fmt.Printf("tNew=%d, nNew=%d, %.3f µs\n", tNew, nNew, avgTime)
		}

		fmt.Println()
	}
}

func DAC_timecost() {
	fmt.Println("Run revised measurements with: go run ./cmd/revisedbench -out results/new-run")
}

func Complete_process() {
	f, err := benchfixture.New(3)
	if err != nil {
		log.Fatal(err)
	}
	theta, err := DAC.GenToken(f.P, f.MPK, f.Trace.D, f.Sig, f.Attrs, f.ID, []int{1})
	if err != nil {
		log.Fatal(err)
	}
	ok, err := DAC.VerifyTok(f.P, f.MPK, f.Trace.D, theta, theta.Disclosed)
	if err != nil || !ok {
		log.Fatal("invalid revised token", err)
	}
	shares := make([]*DAC.DecryptionShare, 0, len(f.I))
	for _, i := range f.I {
		s, err := DAC.ComputeDecryptionShare(f.P, f.Trace, theta.ElGamalCipher, i)
		if err != nil {
			log.Fatal(err)
		}
		if err = DAC.ProveDecryptionShare(f.P, f.Trace, theta.ElGamalCipher, s); err != nil {
			log.Fatal(err)
		}
		shares = append(shares, s)
	}
	u, err := DAC.Trace(f.P, f.Trace, theta.ElGamalCipher, shares)
	if err != nil {
		log.Fatal(err)
	}
	expected := new(bn256.G1).ScalarMult(f.P.G1, f.ID)
	fmt.Println("Revised token verified:", ok)
	fmt.Println("Threshold tracing matched registration:", u.String() == expected.String())
}

func BenchmarkBN256Ops(runs int) {
	order := bn256.Order
	var totalG1, totalG2, totalGT, totalPairing time.Duration

	// 存储 G1, G2 元素供 pairing 使用
	g1List := make([]*bn256.G1, runs)
	g2List := make([]*bn256.G2, runs)

	for i := 0; i < runs; i++ {
		// 生成随机标量
		s1, _ := rand.Int(rand.Reader, order)
		s2, _ := rand.Int(rand.Reader, order)

		// G1 ScalarBaseMult
		startG1 := time.Now()
		g1 := new(bn256.G1).ScalarBaseMult(s1)
		totalG1 += time.Since(startG1)
		g1List[i] = g1

		// G2 ScalarBaseMult
		startG2 := time.Now()
		g2 := new(bn256.G2).ScalarBaseMult(s2)
		totalG2 += time.Since(startG2)
		g2List[i] = g2

		// GT ScalarBaseMult
		startGT := time.Now()
		new(bn256.GT).ScalarBaseMult(s2)
		totalGT += time.Since(startGT)
	}

	// Pairing 计算
	for i := 0; i < runs; i++ {
		startPair := time.Now()
		bn256.Pair(g1List[i], g2List[i])
		totalPairing += time.Since(startPair)
	}

	fmt.Printf("Ran %d iterations:\n", runs)
	fmt.Printf("Average G1 ScalarBaseMult time: %v\n", totalG1/time.Duration(runs))
	fmt.Printf("Average G2 ScalarBaseMult time: %v\n", totalG2/time.Duration(runs))
	fmt.Printf("Average GT ScalarBaseMult time: %v\n", totalGT/time.Duration(runs))
	fmt.Printf("Average Pairing time:           %v\n", totalPairing/time.Duration(runs))
}

func main() {
	//RDKG_TEST()
	//DAC_timecost()
	//NI_TZK_TEST()
	//Evolv_timecost()
	Complete_process()
	//BenchmarkBN256Ops(100)
}
