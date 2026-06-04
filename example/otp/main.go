// Package main demonstrates the core otp package functionality.
//
// Run: go run ./example/otp/main.go
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/unitsvc/otp"
)

func main() {
	fmt.Println("=== Core OTP Package Examples ===")
	fmt.Println()

	// --- 1. Algorithm types ---
	fmt.Println("--- 1. Algorithm types and constants ---")
	fmt.Printf("  AlgorithmCompat (SHA1):   %d -> %s\n", otp.AlgorithmCompat, otp.AlgorithmCompat.String())
	fmt.Printf("  AlgorithmSecure (SHA256): %d -> %s\n", otp.AlgorithmSecure, otp.AlgorithmSecure.String())

	allAlgs := []otp.Algorithm{
		otp.AlgorithmSHA1, otp.AlgorithmSHA224, otp.AlgorithmSHA256,
		otp.AlgorithmSHA384, otp.AlgorithmSHA512,
		otp.AlgorithmSHA3_224, otp.AlgorithmSHA3_256, otp.AlgorithmSHA3_384, otp.AlgorithmSHA3_512,
		otp.AlgorithmMD5,
	}
	fmt.Println("  All algorithms:")
	for _, a := range allAlgs {
		fmt.Printf("    %s (IsValid=%v)\n", a.String(), a.IsValid())
	}

	// Unknown algorithm
	unknown := otp.Algorithm(999)
	fmt.Printf("  Unknown: %s (IsValid=%v)\n", unknown.String(), unknown.IsValid())
	fmt.Println()

	// --- 2. ParseAlgorithm ---
	fmt.Println("--- 2. ParseAlgorithm (alias resolution) ---")
	aliases := []string{
		"SHA1", "SHA-1", "sha1",
		"SHA256", "SHA-256", "sha256", "SHA2-256",
		"SHA512", "SHA-512", "SHA2-512",
		"MD5", "md5",
		"SHA3-256", "sha3-512",
		"SSL3-SHA1",
	}
	for _, a := range aliases {
		alg, err := otp.ParseAlgorithm(a)
		if err != nil {
			fmt.Printf("  %q -> ERROR: %v\n", a, err)
		} else {
			fmt.Printf("  %q -> %s\n", a, alg.String())
		}
	}
	fmt.Println()

	// --- 3. Digits ---
	fmt.Println("--- 3. Digits ---")
	d6 := otp.DigitsSix
	d8 := otp.DigitsEight
	fmt.Printf("  DigitsSix:  length=%d, String=%s, Format(42)=%s\n", d6.Length(), d6.String(), d6.Format(42))
	fmt.Printf("  DigitsEight: length=%d, String=%s, Format(42)=%s\n", d8.Length(), d8.String(), d8.Format(42))
	fmt.Println()

	// --- 4. Encoder ---
	fmt.Println("--- 4. Encoder ---")
	fmt.Printf("  EncoderDefault: %q\n", otp.EncoderDefault)
	fmt.Printf("  EncoderSteam:   %q\n", otp.EncoderSteam)
	fmt.Println()

	// --- 5. Key URL parsing ---
	fmt.Println("--- 5. Key URL parsing ---")
	uris := []string{
		"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
		"otpauth://hotp/Example:bob@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=42&algorithm=SHA256&digits=8",
		"otpauth://totp/Test:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA-256&digits=8&period=60",
	}
	for _, uri := range uris {
		key, err := otp.NewKeyFromURL(uri)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			continue
		}
		fmt.Printf("  %s\n", key.Type())
		fmt.Printf("    Issuer:      %s\n", key.Issuer())
		fmt.Printf("    AccountName: %s\n", key.AccountName())
		fmt.Printf("    Algorithm:   %s\n", key.Algorithm().String())
		fmt.Printf("    Digits:      %d\n", key.Digits())
		fmt.Printf("    Period:      %d\n", key.Period())
		fmt.Printf("    Counter:     %d\n", key.Counter())
		fmt.Printf("    Encoder:     %s\n", key.Encoder())
		fmt.Printf("    Secret:      %s\n", key.Secret()[:8]+"...")
		if img := key.ImageURL(); img != "" {
			fmt.Printf("    ImageURL:    %s\n", img)
		}
		fmt.Println()
	}

	// --- 6. Error handling ---
	fmt.Println("--- 6. Error handling ---")
	errorTests := []struct {
		name string
		uri  string
	}{
		{"Missing scheme", "https://example.com"},
		{"Invalid type", "otpauth://invalid/Test:user?secret=JBSWY3DPEHPK3PXP"},
		{"Missing secret", "otpauth://totp/Test:user?issuer=Test"},
		{"Invalid algorithm", "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&algorithm=INVALID"},
		{"Invalid digits", "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&digits=abc"},
		{"Colon in issuer", "otpauth://totp/Issu:er:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=Issu%3Aer"},
	}
	for _, tt := range errorTests {
		_, err := otp.NewKeyFromURL(tt.uri)
		if err != nil {
			// Check if it's a known sentinel error
			isKnown := err == otp.ErrInvalidURIScheme || err == otp.ErrInvalidURIType ||
				err == otp.ErrMissingSecret || err == otp.ErrInvalidAlgorithm ||
				strings.Contains(err.Error(), "invalid")
			fmt.Printf("  %-20s -> %v (known=%v)\n", tt.name, err, isKnown)
		}
	}
	fmt.Println()

	// --- 7. QR code ---
	fmt.Println("--- 7. QR code generation ---")
	key, err := otp.NewKeyFromURL("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
	if err != nil {
		log.Fatal(err)
	}
	img, err := key.Image(256, 256)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  QR code: %dx%d pixels\n", img.Bounds().Dx(), img.Bounds().Dy())
	fmt.Println()

	// --- 8. HashChecked (safe hash accessor) ---
	fmt.Println("--- 8. HashChecked (safe hash accessor) ---")
	for _, alg := range []otp.Algorithm{otp.AlgorithmSHA256, otp.Algorithm(999)} {
		h, err := alg.HashChecked()
		if err != nil {
			fmt.Printf("  %s: ERROR %v\n", alg.String(), err)
		} else {
			fmt.Printf("  %s: hash size=%d bytes\n", alg.String(), h.Size())
		}
	}
	fmt.Println()

	// --- 9. GetExtraParam (reading custom URI parameters) ---
	fmt.Println("--- 9. GetExtraParam (custom URI parameters) ---")
	uriWithExtra := "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&source=web&lock=true"
	keyExtra, err := otp.NewKeyFromURL(uriWithExtra)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  source: %q\n", keyExtra.GetExtraParam("source"))
	fmt.Printf("  lock:   %q\n", keyExtra.GetExtraParam("lock"))
	fmt.Printf("  missing:%q\n", keyExtra.GetExtraParam("nonexistent"))
	fmt.Println()

	// --- 10. ValidationResult ---
	fmt.Println("--- 10. ValidationResult struct ---")
	vr := otp.ValidationResult{Valid: true, Delta: -1, Step: 12345}
	fmt.Printf("  Valid=%v, Delta=%d (past match), Step=%d\n", vr.Valid, vr.Delta, vr.Step)
}
