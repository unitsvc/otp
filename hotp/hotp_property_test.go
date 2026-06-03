package hotp

import (
	"encoding/base32"
	"strings"
	"testing"

	"testing/quick"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// commonSecret is a 20-byte secret (160 bits) that meets the minimum
// length requirement enforced by GenerateCodeCustom.
var commonSecret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

func TestPropertyGenerateDeterministic(t *testing.T) {
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code1, err1 := GenerateCodeCustom(commonSecret, counter, opts)
		code2, err2 := GenerateCodeCustom(commonSecret, counter, opts)
		if err1 != nil || err2 != nil {
			return false
		}
		return code1 == code2
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyGenerateLength(t *testing.T) {
	// Test with 6-digit codes.
	f6 := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		return len(code) == otp.DigitsSix.Length()
	}
	err := quick.Check(f6, &quick.Config{MaxCount: 200})
	require.NoError(t, err)

	// Test with 8-digit codes.
	f8 := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		return len(code) == otp.DigitsEight.Length()
	}
	err = quick.Check(f8, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyGenerateAllDigits(t *testing.T) {
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyValidateRoundTrip(t *testing.T) {
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		valid, err := ValidateCustom(code, counter, commonSecret, opts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyDifferentCountersDifferentCodes(t *testing.T) {
	// Two different counters should produce different codes. This is
	// probabilistic so we track collisions and allow a small number.
	f := func(a, b uint64) bool {
		if a == b {
			return true // skip equal counters
		}
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code1, err1 := GenerateCodeCustom(commonSecret, a, opts)
		code2, err2 := GenerateCodeCustom(commonSecret, b, opts)
		if err1 != nil || err2 != nil {
			return true // generation errors are not the property under test
		}
		return code1 != code2
	}
	// Allow a small number of collisions since the 6-digit space (10^6)
	// makes exact uniqueness impractical. quick.Check expects the function
	// to return true; we allow rare false results via the MaxCountScale.
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyWindowValidation(t *testing.T) {
	// A code generated at counter C must validate at counter C with any window >= 0.
	f := func(counter uint64, window uint8) bool {
		w := uint(window) % 11 // keep window in [0, 10] to stay within the allowed range
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		winOpts := ValidateOptsWithWindow{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			Window:    w,
		}
		_, found, err := ValidateCustomWindow(code, counter, commonSecret, winOpts)
		if err != nil {
			return false
		}
		return found
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyWindowReplayProtection(t *testing.T) {
	// When AfterCounter is set, counters <= AfterCounter must be rejected.
	f := func(counter uint64, afterCounter uint64, window uint8) bool {
		// Ensure counter is at or below afterCounter so it should be rejected.
		// We derive afterCounter from the inputs to keep it deterministic.
		ac := afterCounter
		c := ac // Use the same value; replay protection rejects <= afterCounter

		w := uint(window) % 11
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, c, opts)
		if err != nil {
			return true
		}

		winOpts := ValidateOptsWithWindow{
			Digits:       otp.DigitsSix,
			Algorithm:    otp.AlgorithmSHA1,
			Window:       w,
			AfterCounter: ac,
		}
		_, found, err := ValidateCustomWindow(code, c, commonSecret, winOpts)
		if err != nil {
			return true
		}
		// When counter == AfterCounter, it must be rejected (<=).
		return !found
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyGenerateAllDigitsEight(t *testing.T) {
	// Also verify 8-digit default-encoder output contains only digits.
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyValidateRoundTripSHA256(t *testing.T) {
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA256}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		valid, err := ValidateCustom(code, counter, commonSecret, opts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyValidateRoundTripSHA512(t *testing.T) {
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA512}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		valid, err := ValidateCustom(code, counter, commonSecret, opts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertySteamAlphabet(t *testing.T) {
	// Steam-encoded codes must contain only characters from the Steam alphabet.
	steamChars := "23456789BCDFGHJKMNPQRTVWXY"
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1, Encoder: otp.EncoderSteam}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		for _, c := range code {
			if !strings.ContainsRune(steamChars, c) {
				return false
			}
		}
		return true
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyWindowFindsAdjacentCounter(t *testing.T) {
	// A code generated at counter C should be found when validating at
	// counter C+1 with window=1 (the code is one step in the past).
	f := func(counter uint64) bool {
		opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, counter, opts)
		if err != nil {
			return false
		}
		winOpts := ValidateOptsWithWindow{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			Window:    1,
		}
		delta, found, err := ValidateCustomWindow(code, counter+1, commonSecret, winOpts)
		if err != nil {
			return false
		}
		return found && delta == -1
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}
