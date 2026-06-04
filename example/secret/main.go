// Package main demonstrates the secret package functionality.
//
// Run: go run ./example/secret/main.go
package main

import (
	"fmt"
	"log"

	"github.com/unitsvc/otp/secret"
)

func main() {
	fmt.Println("=== Secret Package Examples ===")
	fmt.Println()

	// 1. Generate a random secret (default 20 bytes / 160 bits)
	s, err := secret.New(20)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Random Secret (20 bytes):\n")
	fmt.Printf("  Base32:          %s\n", s.Base32())
	fmt.Printf("  Base32 padded:   %s\n", s.Base32WithPadding())
	fmt.Printf("  Hex:             %s\n", s.Hex())
	fmt.Printf("  Length:          %d bytes\n", s.Len())
	fmt.Println()

	// 2. Import from various formats
	fmt.Println("--- Import from various formats ---")

	// From Base32 (must decode to >= 16 bytes)
	s2, err := secret.FromBase32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("FromBase32:  %s -> hex=%s, len=%d\n", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", s2.Hex()[:16]+"...", s2.Len())

	// From Hex (20 bytes)
	s3, err := secret.FromHex("0102030405060708090a0b0c0d0e0f1011121314")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("FromHex:     %s -> base32=%s, len=%d\n", "0102...1314", s3.Base32(), s3.Len())

	// From raw bytes (16 bytes minimum)
	raw := make([]byte, 20)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	s4, err := secret.FromBytes(raw)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("FromBytes:   [1..20] -> base32=%s, len=%d\n", s4.Base32(), s4.Len())
	fmt.Println()

	// 3. Bytes() returns an independent copy
	fmt.Println("--- Bytes() returns independent copy ---")
	b1 := s.Bytes()
	b1[0] = 0xFF // Modify the copy
	b2 := s.Bytes()
	fmt.Printf("  Modified copy[0]=0x%02X, but original[0]=0x%02X -> copy is independent\n", b1[0], b2[0])
	fmt.Println()

	// 4. Clear() zeros memory
	fmt.Println("--- Clear() zeros memory ---")
	s5, _ := secret.New(20)
	fmt.Printf("  Before Clear: len=%d, base32=%s\n", s5.Len(), s5.Base32())
	s5.Clear()
	fmt.Printf("  After Clear:  len=%d, bytes=%v\n", s5.Len(), s5.Bytes())
	fmt.Println()

	// 5. Error handling for invalid inputs
	fmt.Println("--- Error handling ---")
	_, err = secret.FromBase32("INVALID!@#$")
	if err != nil {
		fmt.Printf("  Invalid Base32 rejected: %v\n", err)
	}

	_, err = secret.FromHex("ZZ") // Invalid hex characters
	if err != nil {
		fmt.Printf("  Invalid Hex rejected: %v\n", err)
	}

	_, err = secret.New(15) // Too short (<16 bytes)
	if err != nil {
		fmt.Printf("  Too short (15 bytes) rejected: %v\n", err)
	}

	_, err = secret.New(65) // Too long (>64 bytes)
	if err != nil {
		fmt.Printf("  Too long (65 bytes) rejected: %v\n", err)
	}
}
