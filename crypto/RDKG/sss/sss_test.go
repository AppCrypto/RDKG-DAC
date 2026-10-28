package sss

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSSS(t *testing.T) {
	n := 5         // The number of shares
	threshold := 3 // threshold

	pub, _ := Setup(n, threshold)

	// Generate a random secret
	s, _ := rand.Int(rand.Reader, pub.Order)

	shares, err := Share(pub, s)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i
	}

	secret, err := Recon(I, shares, pub)
	if err != nil {
		t.Fatalf("Error in Recon: %v", err)
	}
	fmt.Println("recover secret = ", secret)
	fmt.Println("orignal secret = ", s)

	if s.Cmp(secret) != 0 {
		t.Fatal("Recovered secret does not match the original secret")
	}
}
