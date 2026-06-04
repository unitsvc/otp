/**
 * System Robustness Boundary Tests for HOTP
 *
 * Tests for input boundaries, special inputs, error handling, and concurrency.
 */

package hotp

import (
	"encoding/base32"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// =============================================================================
// 1. INPUT BOUNDARY TESTS
// =============================================================================

// ----- Secret Boundary Tests -----
// RFC 4226: Secret must be at least 128 bits (16 bytes), recommended 160 bits (20 bytes)
// Maximum: 64 bytes (512 bits) for practical HMAC key sizes

func TestSecretBoundary_15Bytes_Rejected(t *testing.T) {
	// 15 bytes secret (below minimum) should be rejected
	secret15 := make([]byte, 15)
	for i := range secret15 {
		secret15[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret15)

	_, err := GenerateCodeCustom(secretB32, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err, "15-byte secret should be rejected")
	require.Equal(t, otp.ErrSecretTooShort, err)
}

func TestSecretBoundary_16Bytes_Minimum(t *testing.T) {
	// 16 bytes secret (minimum) should be accepted
	secret16 := make([]byte, 16)
	for i := range secret16 {
		secret16[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret16)

	code, err := GenerateCodeCustom(secretB32, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err, "16-byte secret should be accepted")
	require.Len(t, code, 6)

	// Validation should also work
	valid, err := ValidateCustom(code, 0, secretB32, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestSecretBoundary_64Bytes_Maximum(t *testing.T) {
	// 64 bytes secret (maximum) should be accepted
	secret64 := make([]byte, 64)
	for i := range secret64 {
		secret64[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret64)

	code, err := GenerateCodeCustom(secretB32, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512, // Use SHA512 for larger secret
	})
	require.NoError(t, err, "64-byte secret should be accepted")
	require.Len(t, code, 6)

	// Validation should also work
	valid, err := ValidateCustom(code, 0, secretB32, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestSecretBoundary_65Bytes_Rejected(t *testing.T) {
	// 65 bytes secret (above maximum) should be rejected
	secret65 := make([]byte, 65)
	for i := range secret65 {
		secret65[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret65)

	_, err := GenerateCodeCustom(secretB32, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	})
	require.Error(t, err, "65-byte secret should be rejected")
	require.Equal(t, otp.ErrSecretTooLong, err)
}

// ----- Digits Boundary Tests -----
// Default encoder: 6-10 digits
// Steam encoder: 5-10 digits

func TestDigitsBoundary_5_DefaultEncoder_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	_, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderDefault,
	})
	require.Error(t, err, "5 digits with default encoder should be rejected")
	require.Equal(t, otp.ErrDigitsOutOfRange, err)
}

func TestDigitsBoundary_5_SteamEncoder_Minimum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	code, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderSteam,
	})
	require.NoError(t, err, "5 digits with Steam encoder should be accepted")
	require.Len(t, code, 5)
}

func TestDigitsBoundary_6_Default_Minimum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	code, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err, "6 digits should be accepted")
	require.Len(t, code, 6)
}

func TestDigitsBoundary_10_Maximum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	code, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.Digits(10),
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err, "10 digits should be accepted")
	require.Len(t, code, 10)
}

func TestDigitsBoundary_11_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	_, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.Digits(11),
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err, "11 digits should be rejected")
	require.Equal(t, otp.ErrDigitsOutOfRange, err)
}

// ----- Window Boundary Tests -----
// HOTP window: 0-10 (security limit for brute force prevention)

func TestWindowBoundary_0(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	code, err := GenerateCodeCustom(secret, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Window=0 should only match exact counter
	delta, found, err := ValidateCustomWindow(code, 100, secret, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    0,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 0, delta)

	// Should not match at counter=101
	delta, found, err = ValidateCustomWindow(code, 101, secret, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    0,
	})
	require.NoError(t, err)
	require.False(t, found)
}

func TestWindowBoundary_10_Maximum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	code, err := GenerateCodeCustom(secret, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Window=10 should match at counter=110 (delta=-10)
	delta, found, err := ValidateCustomWindow(code, 110, secret, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    10,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, -10, delta)
}

func TestWindowBoundary_11_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	code, err := GenerateCodeCustom(secret, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	_, _, err = ValidateCustomWindow(code, 100, secret, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    11,
	})
	require.Error(t, err, "Window=11 should be rejected")
	require.Equal(t, otp.ErrWindowTooLarge, err)
}

// =============================================================================
// 2. SPECIAL INPUT TESTS
// =============================================================================

func TestSpecialInput_EmptySecret(t *testing.T) {
	_, err := GenerateCodeCustom("", 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	// Empty secret decodes to 0 bytes, which triggers ErrSecretTooShort
	require.Equal(t, otp.ErrSecretTooShort, err)
}

func TestSpecialInput_InvalidBase32(t *testing.T) {
	// Invalid Base32 characters (0, 1, 8, 9 are not in Base32 alphabet)
	_, err := GenerateCodeCustom("INVALID0123456789", 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, err)
}

func TestSpecialInput_AllSpacesPasscode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	valid, err := ValidateCustom("      ", 0, secret, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateInputInvalidLength, err)
	require.False(t, valid)
}

func TestSpecialInput_SpecialCharsPasscode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Special characters in passcode (should fail character validation)
	valid, err := ValidateCustom("!@#$%^", 0, secret, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateInputInvalidChars, err)
	require.False(t, valid)
}

func TestSpecialInput_SpecialCharsPasscode_Steam(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Invalid characters for Steam alphabet (A, E, I, L, O, S, U, Z are not in Steam alphabet)
	valid, err := ValidateCustom("ABCDE", 0, secret, ValidateOpts{
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderSteam,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateInputInvalidChars, err)
	require.False(t, valid)
}

func TestSpecialInput_ExtraLongPasscode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Very long passcode (100 characters)
	longCode := "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	valid, err := ValidateCustom(longCode, 0, secret, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateInputInvalidLength, err)
	require.False(t, valid)
}

func TestSpecialInput_MD5Algorithm_Rejected(t *testing.T) {
	// MD5 produces 16-byte digest, which is too small for dynamic truncation
	// (requires >= 19 bytes for safety)
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	_, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmMD5,
	})
	require.Error(t, err, "MD5 should be rejected (digest too small)")
	require.Equal(t, otp.ErrDigestTooSmall, err)
}

// =============================================================================
// 3. ERROR PATH TESTS
// =============================================================================

func TestErrorPath_AllErrorTypes(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	tests := []struct {
		name      string
		err       error
		triggerFn func() error
	}{
		{
			name: "ErrValidateSecretInvalidBase32",
			err:  otp.ErrValidateSecretInvalidBase32,
			triggerFn: func() error {
				_, err := GenerateCodeCustom("INVALID!", 0, ValidateOpts{})
				return err
			},
		},
		{
			name: "ErrValidateInputInvalidLength",
			err:  otp.ErrValidateInputInvalidLength,
			triggerFn: func() error {
				_, err := ValidateCustom("123", 0, secret, ValidateOpts{Digits: otp.DigitsSix})
				return err
			},
		},
		{
			name: "ErrSecretTooShort",
			err:  otp.ErrSecretTooShort,
			triggerFn: func() error {
				shortSecret := base32.StdEncoding.EncodeToString([]byte("12345678901234")) // 14 bytes
				_, err := GenerateCodeCustom(shortSecret, 0, ValidateOpts{})
				return err
			},
		},
		{
			name: "ErrSecretTooLong",
			err:  otp.ErrSecretTooLong,
			triggerFn: func() error {
				longSecret := base32.StdEncoding.EncodeToString(make([]byte, 100))
				_, err := GenerateCodeCustom(longSecret, 0, ValidateOpts{})
				return err
			},
		},
		{
			name: "ErrDigitsOutOfRange",
			err:  otp.ErrDigitsOutOfRange,
			triggerFn: func() error {
				_, err := GenerateCodeCustom(secret, 0, ValidateOpts{Digits: otp.Digits(20)})
				return err
			},
		},
		{
			name: "ErrWindowTooLarge",
			err:  otp.ErrWindowTooLarge,
			triggerFn: func() error {
				_, _, err := ValidateCustomWindow("000000", 0, secret, ValidateOptsWithWindow{Window: 100})
				return err
			},
		},
		{
			name: "ErrDigestTooSmall",
			err:  otp.ErrDigestTooSmall,
			triggerFn: func() error {
				_, err := GenerateCodeCustom(secret, 0, ValidateOpts{Algorithm: otp.AlgorithmMD5})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.triggerFn()
			require.Error(t, err)
			require.Equal(t, tt.err, err, "Error type mismatch")
		})
	}
}

func TestErrorPath_ErrorMessagesClear(t *testing.T) {
	// Verify error messages are descriptive
	tests := []struct {
		err    error
		expect string
	}{
		{otp.ErrSecretTooShort, "secret too short"},
		{otp.ErrSecretTooLong, "secret too long"},
		{otp.ErrDigitsOutOfRange, "digits out of range"},
		{otp.ErrWindowTooLarge, "window exceeds maximum"},
		{otp.ErrDigestTooSmall, "digest size too small"},
		{otp.ErrValidateSecretInvalidBase32, "base32 failed"},
		{otp.ErrValidateInputInvalidLength, "input length unexpected"},
		{otp.ErrValidateInputInvalidChars, "invalid characters"},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			require.Contains(t, tt.err.Error(), tt.expect,
				"Error message should contain expected text")
		})
	}
}

func TestErrorPath_ErrorHandlingConsistency(t *testing.T) {
	// Both GenerateCodeCustom and ValidateCustom should return same error type
	// for invalid secret (non-base32 characters)
	_, genErr := GenerateCodeCustom("INVALID!", 0, ValidateOpts{})
	_, valErr := ValidateCustom("000000", 0, "INVALID!", ValidateOpts{Digits: otp.DigitsSix})

	require.Equal(t, genErr, valErr, "Errors should be consistent across functions")
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, genErr)
}

// =============================================================================
// 4. CONCURRENCY TESTS
// =============================================================================

func TestConcurrency_GenerateCode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	counter := uint64(1000)

	// Run 100 concurrent GenerateCode operations
	const numOps = 100
	var wg sync.WaitGroup
	errs := make([]error, numOps)
	codes := make([]string, numOps)

	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			code, err := GenerateCodeCustom(secret, counter, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			codes[idx] = code
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	// All operations should succeed
	for i := 0; i < numOps; i++ {
		require.NoError(t, errs[i], "Concurrent GenerateCode should not fail")
		require.Len(t, codes[i], 6)
	}

	// All codes should be identical (same counter, same secret)
	for i := 1; i < numOps; i++ {
		require.Equal(t, codes[0], codes[i], "All codes should be identical")
	}
}

func TestConcurrency_Validate(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	counter := uint64(1000)

	// Generate a valid code first
	code, err := GenerateCodeCustom(secret, counter, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Run 100 concurrent Validate operations
	const numOps = 100
	var wg sync.WaitGroup
	results := make([]bool, numOps)
	errs := make([]error, numOps)

	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			valid, err := ValidateCustom(code, counter, secret, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			results[idx] = valid
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	// All operations should succeed and return true
	for i := 0; i < numOps; i++ {
		require.NoError(t, errs[i], "Concurrent Validate should not fail")
		require.True(t, results[i], "All validations should succeed")
	}
}

func TestConcurrency_NoRaceCondition(t *testing.T) {
	// This test should be run with -race flag to detect race conditions
	// go test -race -run TestConcurrency_NoRaceCondition

	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Simulate real-world usage: multiple goroutines generating and validating
	const numGoroutines = 20
	const iterationsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < iterationsPerGoroutine; i++ {
				// Generate
				code, err := GenerateCodeCustom(secret, uint64(goroutineID*1000+i), ValidateOpts{
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
				if err != nil {
					t.Errorf("Goroutine %d iteration %d: Generate failed: %v", goroutineID, i, err)
					return
				}

				// Validate own code
				valid, err := ValidateCustom(code, uint64(goroutineID*1000+i), secret, ValidateOpts{
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
				if err != nil {
					t.Errorf("Goroutine %d iteration %d: Validate failed: %v", goroutineID, i, err)
					return
				}
				if !valid {
					t.Errorf("Goroutine %d iteration %d: Self-validation failed", goroutineID, i)
					return
				}
			}
		}(g)
	}

	wg.Wait()
}

// =============================================================================
// 5. EDGE CASE TESTS
// =============================================================================

func TestEdgeCase_CounterZero(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Counter=0 is valid (RFC 4226 test vectors use counter=0)
	code, err := GenerateCodeCustom(secret, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)

	valid, err := ValidateCustom(code, 0, secret, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestEdgeCase_LargeCounter(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Very large counter (near uint64 max, but not overflow)
	largeCounter := uint64(1e15)

	code, err := GenerateCodeCustom(secret, largeCounter, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)

	valid, err := ValidateCustom(code, largeCounter, secret, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestEdgeCase_AllSupportedAlgorithms(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	algorithms := []otp.Algorithm{
		otp.AlgorithmSHA1,
		otp.AlgorithmSHA224,
		otp.AlgorithmSHA256,
		otp.AlgorithmSHA384,
		otp.AlgorithmSHA512,
		otp.AlgorithmSHA3_224,
		otp.AlgorithmSHA3_256,
		otp.AlgorithmSHA3_384,
		otp.AlgorithmSHA3_512,
	}

	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			code, err := GenerateCodeCustom(secret, 0, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: alg,
			})
			require.NoError(t, err, "Algorithm %s should work", alg.String())
			require.Len(t, code, 6)

			valid, err := ValidateCustom(code, 0, secret, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: alg,
			})
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}

func TestEdgeCase_SteamEncoderAllValidChars(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// Generate Steam codes for multiple counters to verify alphabet coverage
	for counter := uint64(0); counter < 100; counter++ {
		code, err := GenerateCodeCustom(secret, counter, ValidateOpts{
			Digits:    otp.Digits(5),
			Algorithm: otp.AlgorithmSHA1,
			Encoder:   otp.EncoderSteam,
		})
		require.NoError(t, err)
		require.Len(t, code, 5)

		// Verify all characters are from Steam alphabet
		for _, c := range code {
			require.Contains(t, "23456789BCDFGHJKMNPQRTVWXY", string(c),
				"Character %c not in Steam alphabet", c)
		}
	}
}
