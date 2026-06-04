// Package main demonstrates HOTP (HMAC-based One-Time Password) functionality.
//
// Run: go run ./example/hotp/main.go
package main

import (
	"fmt"
	"log"

	"github.com/unitsvc/otp"
	"github.com/unitsvc/otp/hotp"
	"github.com/unitsvc/otp/secret"
)

const testSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // 32-char Base32 = 20 bytes

func main() {
	fmt.Println("=== HOTP Examples ===")
	fmt.Println()

	// --- 1. Basic Generation & Validation ---
	fmt.Println("--- 1. Basic Generate & Validate (SHA1, 6 digits) ---")
	code, err := hotp.GenerateCode(testSecret, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  GenerateCode(secret, counter=0): %s\n", code)

	valid := hotp.Validate(code, 0, testSecret)
	fmt.Printf("  Validate(code, counter=0):       %v\n", valid)

	valid = hotp.Validate(code, 1, testSecret)
	fmt.Printf("  Validate(code, counter=1):       %v (different counter)\n", valid)
	fmt.Println()

	// --- 2. Secure variants (SHA256) ---
	fmt.Println("--- 2. Secure variants (SHA256) ---")
	secureCode, err := hotp.GenerateCodeSecure(testSecret, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  GenerateCodeSecure(counter=0): %s (SHA256)\n", secureCode)
	fmt.Printf("  ValidateSecure(code, 0):       %v\n", hotp.ValidateSecure(secureCode, 0, testSecret))
	fmt.Println()

	// --- 3. Custom options ---
	fmt.Println("--- 3. Custom options (SHA512, 8 digits) ---")
	code8, err := hotp.GenerateCodeCustom(testSecret, 0, hotp.ValidateOpts{
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  SHA512, 8 digits, counter=0: %s\n", code8)

	valid, err = hotp.ValidateCustom(code8, 0, testSecret, hotp.ValidateOpts{
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})
	fmt.Printf("  ValidateCustom: valid=%v, err=%v\n", valid, err)
	fmt.Println()

	// --- 4. All supported algorithms ---
	fmt.Println("--- 4. All supported algorithms ---")
	algorithms := []otp.Algorithm{
		otp.AlgorithmSHA1, otp.AlgorithmSHA224, otp.AlgorithmSHA256,
		otp.AlgorithmSHA384, otp.AlgorithmSHA512,
		otp.AlgorithmSHA3_224, otp.AlgorithmSHA3_256, otp.AlgorithmSHA3_384, otp.AlgorithmSHA3_512,
		otp.AlgorithmMD5,
	}
	for _, alg := range algorithms {
		code, err := hotp.GenerateCodeCustom(testSecret, 0, hotp.ValidateOpts{Algorithm: alg})
		if err != nil {
			fmt.Printf("  %-12s -> ERROR: %v (digest too small)\n", alg.String(), err)
			continue
		}
		fmt.Printf("  %-12s -> %s (IsValid=%v)\n", alg.String(), code, alg.IsValid())
	}
	fmt.Println()

	// --- 5. Steam Guard encoder ---
	fmt.Println("--- 5. Steam Guard encoder ---")
	steamCode, err := hotp.GenerateCodeCustom(testSecret, 0, hotp.ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Steam Guard (5 chars): %s\n", steamCode)

	valid, err = hotp.ValidateCustom(steamCode, 0, testSecret, hotp.ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	fmt.Printf("  Validate Steam: valid=%v\n", valid)
	fmt.Println()

	// --- 6. Window validation ---
	fmt.Println("--- 6. Window validation ---")
	code100, _ := hotp.GenerateCode(testSecret, 100)

	// Exact match
	delta, found, err := hotp.ValidateCustomWindow(code100, 100, testSecret, hotp.ValidateOptsWithWindow{Window: 5})
	fmt.Printf("  Validate at counter=100, window=5: found=%v, delta=%d\n", found, delta)

	// Within window (past)
	delta, found, err = hotp.ValidateCustomWindow(code100, 102, testSecret, hotp.ValidateOptsWithWindow{Window: 5})
	fmt.Printf("  Validate at counter=102, window=5: found=%v, delta=%d (past match)\n", found, delta)

	// Outside window
	delta, found, _ = hotp.ValidateCustomWindow(code100, 110, testSecret, hotp.ValidateOptsWithWindow{Window: 5})
	fmt.Printf("  Validate at counter=110, window=5: found=%v (outside window)\n", found)
	fmt.Println()

	// --- 7. Replay protection ---
	fmt.Println("--- 7. Replay protection (AfterCounter) ---")
	code5, _ := hotp.GenerateCode(testSecret, 5)

	// Normal: counter=5 > AfterCounter=4 => accepted
	delta, found, _ = hotp.ValidateCustomWindow(code5, 5, testSecret, hotp.ValidateOptsWithWindow{
		Window:       2,
		AfterCounter: 4,
	})
	fmt.Printf("  counter=5, AfterCounter=4: found=%v, delta=%d (accepted)\n", found, delta)

	// Replay: counter=5 <= AfterCounter=5 => rejected
	delta, found, _ = hotp.ValidateCustomWindow(code5, 5, testSecret, hotp.ValidateOptsWithWindow{
		Window:       2,
		AfterCounter: 5,
	})
	fmt.Printf("  counter=5, AfterCounter=5: found=%v (replay rejected)\n", found)
	fmt.Println()

	// --- 8. Unicode NFKC normalization ---
	fmt.Println("--- 8. Unicode NFKC normalization ---")
	// Fullwidth digits "１２３４５６" normalize to "123456"
	codeNorm, _ := hotp.GenerateCode(testSecret, 0)
	// Note: fullwidth digits would need to match the actual code
	valid, err = hotp.ValidateCustomNormalized(codeNorm, 0, testSecret, hotp.ValidateOpts{})
	fmt.Printf("  ValidateCustomNormalized: valid=%v\n", valid)
	fmt.Println()

	// --- 9. URI generation ---
	fmt.Println("--- 9. HOTP URI generation ---")
	s, _ := secret.New(20)

	// Default parameters (SHA1, 6 digits) — omitted from URI for compactness
	key, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s.Bytes(),
		Counter:     0,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Default URI:  %s\n", key.URL())

	// Non-default parameters — included in URI
	key2, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s.Bytes(),
		Algorithm:   otp.AlgorithmSHA256,
		Digits:      otp.DigitsEight,
		Counter:     100,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Custom URI:   %s\n", key2.URL())

	// With HTTPS image URL
	key3, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s.Bytes(),
		ImageURL:    "https://example.com/logo.png",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  With image:   %s\n", key3.URL())
	fmt.Println()

	// --- 10. URI parsing ---
	fmt.Println("--- 10. URI parsing ---")
	parsed, err := otp.NewKeyFromURL(key.URL())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Type:         %s\n", parsed.Type())
	fmt.Printf("  Issuer:       %s\n", parsed.Issuer())
	fmt.Printf("  AccountName:  %s\n", parsed.AccountName())
	fmt.Printf("  Secret:       %s... (truncated)\n", parsed.Secret()[:8])
	fmt.Printf("  Algorithm:    %s\n", parsed.Algorithm().String())
	fmt.Printf("  Digits:       %d\n", parsed.Digits())
	fmt.Printf("  Counter:      %d\n", parsed.Counter())
	fmt.Println()

	// --- 11. ParseAlgorithm ---
	fmt.Println("--- 11. ParseAlgorithm (alias compatibility) ---")
	aliases := []string{"SHA1", "SHA-1", "SHA256", "SHA-256", "SHA2-256", "SSL3-SHA1", "MD5", "sha3-512"}
	for _, a := range aliases {
		alg, err := otp.ParseAlgorithm(a)
		if err != nil {
			fmt.Printf("  %q -> ERROR: %v\n", a, err)
		} else {
			fmt.Printf("  %q -> %s\n", a, alg.String())
		}
	}
	fmt.Println()

	// --- 12. ExtraParams (custom URI parameters) ---
	fmt.Println("--- 12. ExtraParams (custom URI parameters) ---")
	s2, _ := secret.New(20)
	keyEP, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s2.Bytes(),
		Counter:     0,
		ExtraParams: map[string]string{"source": "cli", "version": "2"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  URI with extras:\n    %s\n\n", keyEP.URL())
	fmt.Printf("  GetExtraParam(source):  %q\n", keyEP.GetExtraParam("source"))
	fmt.Printf("  GetExtraParam(version): %q\n", keyEP.GetExtraParam("version"))
	fmt.Println()

	// --- 13. IssuerInLabelOmit ---
	fmt.Println("--- 13. IssuerInLabelOmit ---")
	keyLabel, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:            "Example.com",
		AccountName:       "alice@example.com",
		Secret:            s2.Bytes(),
		Counter:           0,
		IssuerInLabelOmit: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Without issuer in label:\n    %s\n\n", keyLabel.URL())

	// --- 14. GoogleAuthenticatorCompat ---
	fmt.Println("--- 14. GoogleAuthenticatorCompat (trailing &) ---")
	keyGA, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:                    "Example.com",
		AccountName:               "alice@example.com",
		Secret:                    s2.Bytes(),
		Counter:                   0,
		GoogleAuthenticatorCompat: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  URI with trailing &:\n    %s\n\n", keyGA.URL())
}
