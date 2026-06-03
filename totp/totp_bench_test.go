package totp

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/unitsvc/otp"
)

// Benchmark secret: 20-byte key encoded as base32.
var benchSecret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

// BenchmarkGenerateCodeSHA1 benchmarks TOTP generation with SHA1.
func BenchmarkGenerateCodeSHA1(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	t := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(benchSecret, t, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateCodeSHA256 benchmarks TOTP generation with SHA256.
func BenchmarkGenerateCodeSHA256(b *testing.B) {
	b.ReportAllocs()
	secSHA256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	}
	t := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(secSHA256, t, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateCodeSHA512 benchmarks TOTP generation with SHA512.
func BenchmarkGenerateCodeSHA512(b *testing.B) {
	b.ReportAllocs()
	secSHA512 := base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	}
	t := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(secSHA512, t, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateCustom benchmarks TOTP validation with a valid code.
func BenchmarkValidateCustom(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	t := time.Now().UTC()
	// Pre-generate a valid code.
	code, err := GenerateCodeCustom(benchSecret, t, opts)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := ValidateCustom(code, benchSecret, t, opts)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("expected valid code")
		}
	}
}

// BenchmarkCounter benchmarks the Counter function.
func BenchmarkCounter(b *testing.B) {
	b.ReportAllocs()
	t := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Counter(30, t)
	}
}

// BenchmarkRemaining benchmarks the Remaining function.
func BenchmarkRemaining(b *testing.B) {
	b.ReportAllocs()
	t := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Remaining(30, t)
	}
}
