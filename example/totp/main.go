// Package main demonstrates TOTP (Time-based One-Time Password) functionality.
//
// Run: go run ./example/totp/main.go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/unitsvc/otp"
	"github.com/unitsvc/otp/secret"
	"github.com/unitsvc/otp/totp"
)

const testSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // 32-char Base32 = 20 bytes

func main() {
	now := time.Now().UTC()
	fmt.Println("=== TOTP Examples ===")
	fmt.Printf("Current time: %s\n\n", now.Format(time.RFC3339))

	// --- 1. Basic Generation & Validation ---
	fmt.Println("--- 1. Basic Generate & Validate (SHA1, 30s period) ---")
	code, err := totp.GenerateCode(testSecret, now)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  GenerateCode(secret, now): %s\n", code)

	valid := totp.Validate(code, testSecret)
	fmt.Printf("  Validate(code):            %v\n", valid)
	fmt.Println()

	// --- 2. Secure variants (SHA256) ---
	fmt.Println("--- 2. Secure variants (SHA256) ---")
	secureCode, err := totp.GenerateCodeSecure(testSecret, now)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  GenerateCodeSecure(now): %s\n", secureCode)
	fmt.Printf("  ValidateSecure(code):    %v\n", totp.ValidateSecure(secureCode, testSecret))
	fmt.Println()

	// --- 3. Custom options ---
	fmt.Println("--- 3. Custom options (SHA512, 60s period, 8 digits) ---")
	code8, err := totp.GenerateCodeCustom(testSecret, now, totp.ValidateOpts{
		Period:    60,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  SHA512, 60s, 8 digits: %s\n", code8)

	valid, err = totp.ValidateCustom(code8, testSecret, now, totp.ValidateOpts{
		Period:    60,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})
	fmt.Printf("  ValidateCustom: valid=%v\n", valid)
	fmt.Println()

	// --- 4. Steam Guard TOTP ---
	fmt.Println("--- 4. Steam Guard TOTP ---")
	steamCode, err := totp.GenerateCodeCustom(testSecret, now, totp.ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Steam Guard (5 chars): %s\n", steamCode)
	fmt.Println()

	// --- 5. Time utilities ---
	fmt.Println("--- 5. Time utilities ---")
	step := totp.Counter(30, now)
	remaining := totp.Remaining(30, now)
	remainingDefault := totp.RemainingDefault(now)
	fmt.Printf("  Counter(30, now):          %d\n", step)
	fmt.Printf("  Remaining(30, now):        %d ms (%.1f seconds)\n", remaining, float64(remaining)/1000)
	fmt.Printf("  RemainingDefault(now):      %d ms\n", remainingDefault)
	fmt.Println()

	// --- 6. Step-based validation (for replay protection) ---
	fmt.Println("--- 6. ValidateCustomStep (returns time step) ---")
	code, _ = totp.GenerateCode(testSecret, now)
	v6, s6, e6 := totp.ValidateCustomStep(code, testSecret, now, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	fmt.Printf("  Valid=%v, Step=%d, Err=%v\n", v6, s6, e6)

	// ValidateStep (convenience)
	v6b, s6b := totp.ValidateStep(code, testSecret)
	fmt.Printf("  ValidateStep: valid=%v, step=%d\n", v6b, s6b)
	fmt.Println()

	// --- 7. Asymmetric Skew Policy ---
	fmt.Println("--- 7. Asymmetric SkewPolicy ---")
	pastTime := now.Add(-30 * time.Second) // 1 period ago
	pastCode, _ := totp.GenerateCode(testSecret, pastTime)

	// RFC-compliant: only allow past periods
	v7, s7, d7, _ := totp.ValidateCustomSkewPolicy(pastCode, testSecret, now, totp.ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: totp.SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	fmt.Printf("  Past code, SkewPolicy{Past:1, Future:0}: valid=%v, step=%d, delta=%d\n", v7, s7, d7)

	// Symmetric: allow both past and future
	v7b, s7b, d7b, _ := totp.ValidateCustomSkewPolicy(pastCode, testSecret, now, totp.ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: totp.SkewPolicy{Past: 1, Future: 1},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	fmt.Printf("  Past code, SkewPolicy{Past:1, Future:1}: valid=%v, step=%d, delta=%d\n", v7b, s7b, d7b)
	fmt.Println()

	// --- 8. RFC-compliant validation ---
	fmt.Println("--- 8. ValidateRFCCompliant ---")
	v8, s8, e8 := totp.ValidateRFCCompliant(code, testSecret, now)
	fmt.Printf("  Valid=%v, Step=%d, Err=%v\n", v8, s8, e8)
	fmt.Println()

	// --- 9. Replay protection (AfterStep) ---
	fmt.Println("--- 9. Replay protection (AfterStep) ---")
	currentStep := totp.Counter(30, now)
	code, _ = totp.GenerateCode(testSecret, now)

	// Normal: current step > AfterStep => accepted
	v9a, _, _ := totp.ValidateCustomStep(code, testSecret, now, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		AfterStep: currentStep - 1,
	})
	fmt.Printf("  AfterStep=%d (current-1): valid=%v (accepted)\n", currentStep-1, v9a)

	// Replay: current step <= AfterStep => rejected
	v9b, _, _ := totp.ValidateCustomStep(code, testSecret, now, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		AfterStep: currentStep,
	})
	fmt.Printf("  AfterStep=%d (current):   valid=%v (replay rejected)\n", currentStep, v9b)
	fmt.Println()

	// --- 10. URI generation ---
	fmt.Println("--- 10. TOTP URI generation ---")
	s, _ := secret.New(20)

	// Default: SHA1, 6 digits, 30s — defaults omitted from URI
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s.Bytes(),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Default URI:\n    %s\n\n", key.URL())

	// Non-default: SHA256, 8 digits, 60s — all included
	key2, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s.Bytes(),
		Algorithm:   otp.AlgorithmSHA256,
		Digits:      otp.DigitsEight,
		Period:      60,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Custom URI:\n    %s\n\n", key2.URL())

	// Steam Guard URI
	key3, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Steam",
		AccountName: "playername",
		Secret:      s.Bytes(),
		Encoder:     otp.EncoderSteam,
		Digits:      otp.Digits(5),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Steam URI:\n    %s\n\n", key3.URL())

	// With HTTPS image
	key4, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Secret:      s.Bytes(),
		ImageURL:    "https://example.com/logo.png",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  With image:\n    %s\n\n", key4.URL())

	// Special characters in issuer/account name (properly escaped)
	key5, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "My App (v2)",
		AccountName: "user+tag@example.com",
		Secret:      s.Bytes(),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Special chars:\n    %s\n\n", key5.URL())

	// --- 11. URI parsing ---
	fmt.Println("--- 11. URI parsing ---")
	parsed, err := otp.NewKeyFromURL(key2.URL())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Type:         %s\n", parsed.Type())
	fmt.Printf("  Issuer:       %s\n", parsed.Issuer())
	fmt.Printf("  AccountName:  %s\n", parsed.AccountName())
	fmt.Printf("  Secret:       %s...\n", parsed.Secret()[:8])
	fmt.Printf("  Algorithm:    %s\n", parsed.Algorithm().String())
	fmt.Printf("  Digits:       %d\n", parsed.Digits())
	fmt.Printf("  Period:       %d\n", parsed.Period())
	fmt.Printf("  Encoder:      %s\n", parsed.Encoder())
	fmt.Println()

	// --- 12. QR code generation ---
	fmt.Println("--- 12. QR code generation ---")
	img, err := key.Image(200, 200)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  QR code generated: %dx%d pixels\n", img.Bounds().Dx(), img.Bounds().Dy())
	fmt.Println()

	// --- 13. Algorithm alias parsing from URI ---
	fmt.Println("--- 13. Algorithm alias parsing ---")
	uri := "otpauth://totp/Test:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA-256&digits=8"
	keyAlias, err := otp.NewKeyFromURL(uri)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  URI with SHA-256 alias -> Algorithm=%s, Digits=%d\n", keyAlias.Algorithm().String(), keyAlias.Digits())
}
