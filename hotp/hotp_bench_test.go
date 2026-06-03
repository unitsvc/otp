package hotp

import (
	"encoding/base32"
	"testing"

	"github.com/unitsvc/otp"
)

// Benchmark secret: 20-byte key encoded as base32.
var benchSecret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

// BenchmarkGenerateCodeSHA1 benchmarks HOTP generation with SHA1 (most common).
func BenchmarkGenerateCodeSHA1(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(benchSecret, uint64(i%1000000), opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateCodeSHA256 benchmarks HOTP generation with SHA256.
func BenchmarkGenerateCodeSHA256(b *testing.B) {
	b.ReportAllocs()
	secSHA256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	opts := ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	}
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(secSHA256, uint64(i%1000000), opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateCodeSHA512 benchmarks HOTP generation with SHA512.
func BenchmarkGenerateCodeSHA512(b *testing.B) {
	b.ReportAllocs()
	secSHA512 := base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
	opts := ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	}
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(secSHA512, uint64(i%1000000), opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateCodeSteam benchmarks HOTP generation with Steam encoder.
func BenchmarkGenerateCodeSteam(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	}
	for i := 0; i < b.N; i++ {
		_, err := GenerateCodeCustom(benchSecret, uint64(i%1000000), opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidate benchmarks HOTP validation with a valid code.
func BenchmarkValidate(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	// Pre-generate a valid code to use for validation.
	code, err := GenerateCodeCustom(benchSecret, 0, opts)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := ValidateCustom(code, 0, benchSecret, opts)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("expected valid code")
		}
	}
}

// BenchmarkValidateInvalid benchmarks HOTP validation with an invalid code.
func BenchmarkValidateInvalid(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := ValidateCustom("000000", 0, benchSecret, opts)
		if err != nil {
			b.Fatal(err)
		}
		if valid {
			b.Fatal("expected invalid code")
		}
	}
}

// BenchmarkValidateWindow benchmarks HOTP validation with a window of 5.
func BenchmarkValidateWindow(b *testing.B) {
	b.ReportAllocs()
	opts := ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    5,
	}
	// Pre-generate code at counter=100.
	code, err := GenerateCodeCustom(benchSecret, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, found, err := ValidateCustomWindow(code, 100, benchSecret, opts)
		if err != nil {
			b.Fatal(err)
		}
		if !found {
			b.Fatal("expected to find code in window")
		}
	}
}
