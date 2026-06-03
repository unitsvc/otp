/**
 * System Robustness Boundary Tests for TOTP
 *
 * Tests for input boundaries, special inputs, error handling, and concurrency.
 */

package totp

import (
	"encoding/base32"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// =============================================================================
// 1. INPUT BOUNDARY TESTS
// =============================================================================

// ----- Period Boundary Tests -----
// TOTP period: 1-300 seconds (RFC 6238 practical limits)

func TestPeriodBoundary_0_Default(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	// Period=0 should use default (30 seconds)
	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    0, // Should default to 30
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)
}

func TestPeriodBoundary_1_Minimum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err, "Period=1 should be accepted")
	require.Len(t, code, 6)
}

func TestPeriodBoundary_300_Maximum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    300,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err, "Period=300 should be accepted")
	require.Len(t, code, 6)
}

func TestPeriodBoundary_301_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    301,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err, "Period=301 should be rejected")
	require.Equal(t, otp.ErrPeriodOutOfRange, err)
}

// ----- Secret Boundary Tests (via TOTP) -----

func TestTOTPSecretBoundary_15Bytes_Rejected(t *testing.T) {
	secret15 := make([]byte, 15)
	for i := range secret15 {
		secret15[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret15)
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom(secretB32, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrSecretTooShort, err)
}

func TestTOTPSecretBoundary_16Bytes_Minimum(t *testing.T) {
	secret16 := make([]byte, 16)
	for i := range secret16 {
		secret16[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret16)
	ts := time.Now().UTC()

	code, err := GenerateCodeCustom(secretB32, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)
}

func TestTOTPSecretBoundary_64Bytes_Maximum(t *testing.T) {
	secret64 := make([]byte, 64)
	for i := range secret64 {
		secret64[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret64)
	ts := time.Now().UTC()

	code, err := GenerateCodeCustom(secretB32, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)
}

func TestTOTPSecretBoundary_65Bytes_Rejected(t *testing.T) {
	secret65 := make([]byte, 65)
	for i := range secret65 {
		secret65[i] = byte(i + 1)
	}
	secretB32 := base32.StdEncoding.EncodeToString(secret65)
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom(secretB32, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrSecretTooLong, err)
}

// ----- Digits Boundary Tests (via TOTP) -----

func TestTOTPDigitsBoundary_5_DefaultEncoder_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderDefault,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrDigitsOutOfRange, err)
}

func TestTOTPDigitsBoundary_5_SteamEncoder_Minimum(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderSteam,
	})
	require.NoError(t, err)
	require.Len(t, code, 5)
}

func TestTOTPDigitsBoundary_11_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.Digits(11),
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrDigitsOutOfRange, err)
}

// =============================================================================
// 2. SPECIAL INPUT TESTS
// =============================================================================

func TestTOTPSpecialInput_EmptySecret(t *testing.T) {
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom("", ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	// Empty secret decodes to 0 bytes, which triggers ErrSecretTooShort
	require.Equal(t, otp.ErrSecretTooShort, err)
}

func TestTOTPSpecialInput_InvalidBase32(t *testing.T) {
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom("INVALID0123456789", ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, err)
}

func TestTOTPSpecialInput_MD5Algorithm_Rejected(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	_, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmMD5,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrDigestTooSmall, err)
}

// =============================================================================
// 3. ERROR PATH TESTS
// =============================================================================

func TestTOTPErrorPath_AllErrorTypes(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	tests := []struct {
		name      string
		err       error
		triggerFn func() error
	}{
		{
			name: "ErrValidateSecretInvalidBase32",
			err:  otp.ErrValidateSecretInvalidBase32,
			triggerFn: func() error {
				_, err := GenerateCodeCustom("INVALID!", ts, ValidateOpts{})
				return err
			},
		},
		{
			name: "ErrSecretTooShort",
			err:  otp.ErrSecretTooShort,
			triggerFn: func() error {
				shortSecret := base32.StdEncoding.EncodeToString([]byte("12345678901234"))
				_, err := GenerateCodeCustom(shortSecret, ts, ValidateOpts{})
				return err
			},
		},
		{
			name: "ErrSecretTooLong",
			err:  otp.ErrSecretTooLong,
			triggerFn: func() error {
				longSecret := base32.StdEncoding.EncodeToString(make([]byte, 100))
				_, err := GenerateCodeCustom(longSecret, ts, ValidateOpts{})
				return err
			},
		},
		{
			name: "ErrDigitsOutOfRange",
			err:  otp.ErrDigitsOutOfRange,
			triggerFn: func() error {
				_, err := GenerateCodeCustom(secret, ts, ValidateOpts{Digits: otp.Digits(20)})
				return err
			},
		},
		{
			name: "ErrPeriodOutOfRange",
			err:  otp.ErrPeriodOutOfRange,
			triggerFn: func() error {
				_, err := GenerateCodeCustom(secret, ts, ValidateOpts{Period: 500})
				return err
			},
		},
		{
			name: "ErrDigestTooSmall",
			err:  otp.ErrDigestTooSmall,
			triggerFn: func() error {
				_, err := GenerateCodeCustom(secret, ts, ValidateOpts{Algorithm: otp.AlgorithmMD5})
				return err
			},
		},
		{
			name: "ErrGenerateMissingIssuer",
			err:  otp.ErrGenerateMissingIssuer,
			triggerFn: func() error {
				_, err := Generate(GenerateOpts{AccountName: "test"})
				return err
			},
		},
		{
			name: "ErrGenerateMissingAccountName",
			err:  otp.ErrGenerateMissingAccountName,
			triggerFn: func() error {
				_, err := Generate(GenerateOpts{Issuer: "test"})
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

func TestTOTPErrorPath_ErrorHandlingConsistency(t *testing.T) {
	ts := time.Now().UTC()

	// Both GenerateCodeCustom and ValidateCustom should return same error type
	// Use proper opts so ValidateCustom does not short-circuit on passcode length check
	opts := ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	_, genErr := GenerateCodeCustom("INVALID!", ts, opts)
	_, valErr := ValidateCustom("000000", "INVALID!", ts, opts)

	require.Equal(t, genErr, valErr, "Errors should be consistent")
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, genErr)
}

// =============================================================================
// 4. CONCURRENCY TESTS
// =============================================================================

func TestTOTPConcurrency_GenerateCode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	const numOps = 100
	var wg sync.WaitGroup
	errs := make([]error, numOps)
	codes := make([]string, numOps)

	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			codes[idx] = code
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i := 0; i < numOps; i++ {
		require.NoError(t, errs[i])
		require.Len(t, codes[i], 6)
	}

	// All codes should be identical (same timestamp, same secret)
	for i := 1; i < numOps; i++ {
		require.Equal(t, codes[0], codes[i])
	}
}

func TestTOTPConcurrency_Validate(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	const numOps = 100
	var wg sync.WaitGroup
	results := make([]bool, numOps)
	errs := make([]error, numOps)

	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			valid, err := ValidateCustom(code, secret, ts, ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			results[idx] = valid
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i := 0; i < numOps; i++ {
		require.NoError(t, errs[i])
		require.True(t, results[i])
	}
}

func TestTOTPConcurrency_GenerateAndValidate(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Now().UTC()

	// First generate a code
	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	const numOps = 50
	var wg sync.WaitGroup

	wg.Add(numOps * 2)
	genErrs := make([]error, numOps)
	valErrs := make([]error, numOps)
	valResults := make([]bool, numOps)

	// Concurrent Generate
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			_, err := GenerateCodeCustom(secret, ts, ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			genErrs[idx] = err
		}(i)
	}

	// Concurrent Validate
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			valid, err := ValidateCustom(code, secret, ts, ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			valResults[idx] = valid
			valErrs[idx] = err
		}(i)
	}

	wg.Wait()

	for i := 0; i < numOps; i++ {
		require.NoError(t, genErrs[i])
		require.NoError(t, valErrs[i])
		require.True(t, valResults[i])
	}
}

func TestTOTPConcurrency_NoRaceCondition(t *testing.T) {
	// This test should be run with -race flag
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	const numGoroutines = 20
	const iterationsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < iterationsPerGoroutine; i++ {
				ts := time.Now().UTC()
				code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
					Period:    30,
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
				if err != nil {
					t.Errorf("Goroutine %d: Generate failed: %v", goroutineID, err)
					return
				}

				valid, err := ValidateCustom(code, secret, ts, ValidateOpts{
					Period:    30,
					Skew:      0,
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
				if err != nil || !valid {
					t.Errorf("Goroutine %d: Validate failed", goroutineID)
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

func TestTOTPEdgeCase_TimestampEpoch(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	ts := time.Unix(0, 0).UTC()

	code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)

	require.Equal(t, uint64(0), Counter(30, ts))
}

func TestTOTPEdgeCase_TimestampFuture(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	futureTs := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	code, err := GenerateCodeCustom(secret, futureTs, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)
}

func TestTOTPEdgeCase_AllSupportedAlgorithms(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
	ts := time.Now().UTC()

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
			code, err := GenerateCodeCustom(secret, ts, ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: alg,
			})
			require.NoError(t, err)
			require.Len(t, code, 6)

			valid, err := ValidateCustom(code, secret, ts, ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: alg,
			})
			require.NoError(t, err)
			require.True(t, valid)
		})
	}
}

func TestTOTPEdgeCase_SkewPolicyBoundary(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))
	ts := time.Unix(59, 0).UTC()

	code, err := GenerateCode(secret, ts)
	require.NoError(t, err)

	// Test with Past=0, Future=0 (exact match only)
	valid, step, delta, err := ValidateCustomSkewPolicy(code, secret, ts, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 0, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)
	require.Equal(t, 0, delta)

	// Test with large skew values
	valid, _, _, err = ValidateCustomSkewPolicy(code, secret, ts, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 10, Future: 10},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestTOTPEdgeCase_CounterUnderflow(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("1234567890123456"))

	// At epoch with Skew > 0, should not panic on underflow
	ts := time.Unix(0, 0).UTC()
	valid, step, err := ValidateCustomStep("000000", secret, ts, ValidateOpts{
		Period:    30,
		Skew:      5,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.False(t, valid)
	require.Equal(t, uint64(0), step)
}
