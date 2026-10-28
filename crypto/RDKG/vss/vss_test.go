package vss

import (
	bn256 "EVOLV_DAO/bn256"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestVSS(t *testing.T) {
	n, threshold := 5, 3
	// VSS.Setup
	par, err := Setup(n, threshold)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Generate a random secret
	alpha0, _ := rand.Int(rand.Reader, par.Pub.Order)

	// VSS.Share
	s, com, _, _, err := Share(alpha0, par)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	shares := make([]*bn256.G2, n)
	for i := 0; i < n; i++ {
		shares[i] = new(bn256.G2).ScalarBaseMult(s[i])
	}

	I := make([]int, n)
	for i := 0; i < n; i++ {
		I[i] = i
	}

	// VSS.Verify
	valid, err := Verify(I, shares, com)
	if !valid || err != nil {
		t.Fatalf("Share validation failed. Error: %v", err)
	}
	fmt.Println("Verification result = ", valid)

	Ip := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		Ip[i] = i
	}

	Recovered, err := Recon(Ip, s, par)
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}
	if Recovered.Cmp(alpha0) != 0 {
		t.Errorf("Reconstruction failed. Expected %v, got %v", alpha0, Recovered)
	} else {
		fmt.Printf("Successfully reconstruct the secret!\n")
	}
	fmt.Println("recover secret = ", Recovered)
	fmt.Println("orignal secret = ", alpha0)

	// 聚合公钥测试
	pubKey, err := AggregatePubKey_G2(Ip, shares, par)
	if err != nil {
		t.Fatalf("AggregatePubKey_G2 failed: %v", err)
	}
	expected := new(bn256.G2).ScalarMult(par.G2, alpha0)

	if pubKey.String() != expected.String() {
		t.Errorf("Aggregated public key mismatch.\nExpected: %v\nGot: %v", expected, pubKey)
	} else {
		fmt.Println("Successfully recovered g2^alpha0 from public shares.")
	}
}
