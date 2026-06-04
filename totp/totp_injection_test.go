/**
 *  Copyright 2014 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package totp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// =============================================================================
// TOTP INPUT INJECTION ATTACK TESTS
// =============================================================================
// This test file validates TOTP-specific input injection handling,
// extending the HOTP tests with time-based scenarios.
// =============================================================================

// =============================================================================
// 1. PERIOD INJECTION TESTS
// =============================================================================

// TestTOTPPeriodInjection tests that period values are properly validated.
func TestTOTPPeriodInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	tests := []struct {
		name    string
		period  uint
		wantErr error
	}{
		{
			name:    "valid period 30",
			period:  30,
			wantErr: nil,
		},
		{
			name:    "valid period 60",
			period:  60,
			wantErr: nil,
		},
		{
			name:    "valid period 15",
			period:  15,
			wantErr: nil,
		},
		{
			name:    "valid period 1 (minimum)",
			period:  1,
			wantErr: nil,
		},
		{
			name:    "valid period 300 (maximum)",
			period:  300,
			wantErr: nil,
		},
		{
			name:    "invalid period 0",
			period:  0,
			wantErr: nil, // Defaults to 30
		},
		{
			name:    "invalid period 301",
			period:  301,
			wantErr: otp.ErrPeriodOutOfRange,
		},
		{
			name:    "invalid period 1000",
			period:  1000,
			wantErr: otp.ErrPeriodOutOfRange,
		},
		{
			name:    "invalid very large period",
			period:  1000000,
			wantErr: otp.ErrPeriodOutOfRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
				Period:    tt.period,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.Empty(t, code)
			} else {
				require.NoError(t, err)
				require.Len(t, code, 6)
			}
		})
	}
}

// =============================================================================
// 2. SKEW INJECTION TESTS
// =============================================================================

// TestTOTPSkewInjection tests skew parameter handling.
func TestTOTPSkewInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate a valid code at current time
	code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		skew      uint
		wantErr   error
		wantValid bool
	}{
		{
			name:      "valid skew 0",
			skew:      0,
			wantErr:   nil,
			wantValid: true, // Should match exact time
		},
		{
			name:      "valid skew 1",
			skew:      1,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "valid skew 5",
			skew:      5,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "skew exceeds maximum",
			skew:      100,
			wantErr:   otp.ErrWindowTooLarge, // Skew capped at 10
			wantValid: false,
		},
		{
			name:      "skew 0 default",
			skew:      0,
			wantErr:   nil,
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(code, secSha1, now, ValidateOpts{
				Period:    30,
				Skew:      tt.skew,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantValid, valid)
			}
		})
	}
}

// =============================================================================
// 3. SKEW POLICY INJECTION TESTS
// =============================================================================

// TestTOTPSkewPolicyInjection tests SkewPolicy parameter handling.
func TestTOTPSkewPolicyInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate a valid code at current time
	code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		past      uint
		future    uint
		wantErr   error
		wantValid bool
		wantDelta int
	}{
		{
			name:      "RFC compliant - past 1, future 0",
			past:      1,
			future:    0,
			wantErr:   nil,
			wantValid: true,
			wantDelta: 0, // Exact match
		},
		{
			name:      "symmetric - past 1, future 1",
			past:      1,
			future:    1,
			wantErr:   nil,
			wantValid: true,
			wantDelta: 0,
		},
		{
			name:      "past only - past 5, future 0",
			past:      5,
			future:    0,
			wantErr:   nil,
			wantValid: true,
			wantDelta: 0,
		},
		{
			name:      "future only - past 0, future 5",
			past:      0,
			future:    5,
			wantErr:   nil,
			wantValid: true,
			wantDelta: 0,
		},
		{
			name:      "skew policy exceeds maximum",
			past:      100,
			future:    100,
			wantErr:   otp.ErrWindowTooLarge, // SkewPolicy capped at 10
			wantValid: false,
			wantDelta: 0,
		},
		{
			name:      "zero skew policy",
			past:      0,
			future:    0,
			wantErr:   nil,
			wantValid: true, // Should match exact
			wantDelta: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, step, delta, err := ValidateCustomSkewPolicy(code, secSha1, now, ValidateOptsWithSkewPolicy{
				Period:     30,
				SkewPolicy: SkewPolicy{Past: tt.past, Future: tt.future},
				Digits:     otp.DigitsSix,
				Algorithm:  otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantValid, valid)
				if valid {
					require.NotZero(t, step)
					require.Equal(t, tt.wantDelta, delta)
				}
			}
		})
	}
}

// =============================================================================
// 4. TIME INJECTION TESTS
// =============================================================================

// TestTOTPTimeInjection tests handling of time input.
func TestTOTPTimeInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	tests := []struct {
		name    string
		time    time.Time
		wantErr error
	}{
		{
			name:    "valid current time",
			time:    time.Now().UTC(),
			wantErr: nil,
		},
		{
			name:    "valid past time",
			time:    time.Now().UTC().Add(-1 * time.Hour),
			wantErr: nil,
		},
		{
			name:    "valid future time",
			time:    time.Now().UTC().Add(1 * time.Hour),
			wantErr: nil,
		},
		{
			name:    "Unix epoch",
			time:    time.Unix(0, 0).UTC(),
			wantErr: nil,
		},
		{
			name:    "very old time",
			time:    time.Unix(-1000000000, 0).UTC(), // Before Unix epoch (negative)
			wantErr: nil,                             // Go handles negative Unix times
		},
		{
			name:    "very far future time",
			time:    time.Unix(10000000000, 0).UTC(),
			wantErr: nil,
		},
		{
			name:    "time with nanoseconds",
			time:    time.Now().UTC().Add(123456789 * time.Nanosecond),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(secSha1, tt.time, ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.Empty(t, code)
			} else {
				require.NoError(t, err)
				require.Len(t, code, 6)
			}
		})
	}
}

// =============================================================================
// 5. PASSCODE INJECTION TESTS (Inherits from HOTP)
// =============================================================================

// TestTOTPPasscodeInjection tests passcode validation for TOTP.
func TestTOTPPasscodeInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate a valid code
	validCode, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		passcode string
		wantErr  error
	}{
		{
			name:     "valid passcode format",
			passcode: validCode,
			wantErr:  nil,
		},
		{
			name:     "invalid passcode with letters",
			passcode: "12345A",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid passcode too short",
			passcode: "12345",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "invalid passcode too long",
			passcode: "1234567",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "invalid passcode with SQL injection",
			passcode: "123';D",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid passcode with command injection",
			passcode: "123|rm",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "passcode with spaces",
			passcode: "123 456",
			wantErr:  nil, // Spaces removed
		},
		{
			name:     "passcode with all spaces",
			passcode: "      ",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "empty passcode",
			passcode: "",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "very long passcode",
			passcode: "123456789012345678901234567890",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, secSha1, now, ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// 6. SECRET INJECTION TESTS (Inherits from HOTP)
// =============================================================================

// TestTOTPSecretInjection tests secret validation for TOTP.
func TestTOTPSecretInjection(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name    string
		secret  string
		wantErr error
	}{
		{
			name:    "valid secret",
			secret:  "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			wantErr: nil,
		},
		{
			name:    "secret with spaces",
			secret:  "GEZD GNBV GY3T QOJQ GEZD GNBV GY",
			wantErr: nil,
		},
		{
			name:    "secret with lowercase",
			secret:  "gezdgnbvgy3tqojqgezdgnbvgy",
			wantErr: nil,
		},
		{
			name:    "invalid Base32 characters",
			secret:  "GEZDGNBVGY3TQOJQGEZDGNBVG!",
			wantErr: otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:    "secret too short",
			secret:  "ABCD",
			wantErr: otp.ErrSecretTooShort,
		},
		{
			name:    "empty secret",
			secret:  "",
			wantErr: otp.ErrSecretTooShort, // Empty string decodes OK but fails length check
		},
		{
			name:    "SQL injection in secret",
			secret:  "GEZD'DROP;NBVGY3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(tt.secret, now, ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.Empty(t, code)
			} else {
				require.NoError(t, err)
				require.Len(t, code, 6)
			}
		})
	}
}

// =============================================================================
// 7. GENERATE OPTIONS INJECTION TESTS
// =============================================================================

// TestTOTPGenerateOptionsInjection tests GenerateOpts validation.
func TestTOTPGenerateOptionsInjection(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		accountName string
		period      uint
		secretSize  uint
		imageURL    string
		wantErr     error
	}{
		{
			name:        "valid options",
			issuer:      "Example",
			accountName: "alice@example.com",
			period:      30,
			secretSize:  20,
			wantErr:     nil,
		},
		{
			name:        "missing issuer",
			issuer:      "",
			accountName: "alice@example.com",
			wantErr:     otp.ErrGenerateMissingIssuer,
		},
		{
			name:        "missing account name",
			issuer:      "Example",
			accountName: "",
			wantErr:     otp.ErrGenerateMissingAccountName,
		},
		{
			name:        "issuer with colon",
			issuer:      "Evil:Example",
			accountName: "alice@example.com",
			wantErr:     otp.ErrColonInIssuer,
		},
		{
			name:        "account name with colon",
			issuer:      "Example",
			accountName: "alice:evil@example.com",
			wantErr:     otp.ErrColonInAccountName,
		},
		{
			name:        "issuer with special chars",
			issuer:      "Example;DROP",
			accountName: "alice@example.com",
			wantErr:     nil, // Special chars allowed in issuer
		},
		{
			name:        "account name with special chars",
			issuer:      "Example",
			accountName: "alice';DROP--@example.com",
			wantErr:     nil, // Special chars allowed in account name
		},
		{
			name:        "issuer with newline",
			issuer:      "Example\nEvil",
			accountName: "alice@example.com",
			wantErr:     nil, // Newline allowed (URL encoded)
		},
		{
			name:        "account name with null",
			issuer:      "Example",
			accountName: "alice\x00@example.com",
			wantErr:     nil, // Null allowed (URL encoded)
		},
		{
			name:        "issuer with unicode",
			issuer:      "中文公司",
			accountName: "alice@example.com",
			wantErr:     nil, // Unicode allowed
		},
		{
			name:        "very long issuer",
			issuer:      "A" + string(make([]byte, 1000)),
			accountName: "alice@example.com",
			wantErr:     nil, // No length limit
		},
		{
			name:        "very long account name",
			issuer:      "Example",
			accountName: "alice@" + string(make([]byte, 1000)) + ".com",
			wantErr:     nil, // No length limit
		},
		{
			name:        "image URL with javascript",
			issuer:      "Example",
			accountName: "alice@example.com",
			imageURL:    "javascript:alert(1)",
			wantErr:     ErrInvalidImageURL, // Now validated: must be HTTPS
		},
		{
			name:        "image URL with file protocol",
			issuer:      "Example",
			accountName: "alice@example.com",
			imageURL:    "file:///etc/passwd",
			wantErr:     ErrInvalidImageURL, // Now validated: must be HTTPS
		},
		{
			name:        "invalid period",
			issuer:      "Example",
			accountName: "alice@example.com",
			period:      301,
			wantErr:     nil, // Generate() does not validate period range
		},
		{
			name:        "invalid secret size",
			issuer:      "Example",
			accountName: "alice@example.com",
			secretSize:  0,
			wantErr:     nil, // Defaults to 20
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := Generate(GenerateOpts{
				Issuer:      tt.issuer,
				AccountName: tt.accountName,
				Period:      tt.period,
				SecretSize:  tt.secretSize,
				ImageURL:    tt.imageURL,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.Nil(t, k)
			} else {
				require.NoError(t, err)
				require.NotNil(t, k)
			}
		})
	}
}

// =============================================================================
// 8. RFC COMPLIANT VALIDATION TESTS
// =============================================================================

// TestTOTPRFCCompliantInjection tests ValidateRFCCompliant function.
func TestTOTPRFCCompliantInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate a valid code
	code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		passcode  string
		wantErr   error
		wantValid bool
	}{
		{
			name:      "valid code at current time",
			passcode:  code,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "invalid passcode format",
			passcode:  "ABCDEF",
			wantErr:   otp.ErrValidateInputInvalidChars,
			wantValid: false,
		},
		{
			name:      "passcode with injection",
			passcode:  "123';D",
			wantErr:   otp.ErrValidateInputInvalidChars,
			wantValid: false,
		},
		{
			name:      "wrong length",
			passcode:  "12345",
			wantErr:   otp.ErrValidateInputInvalidLength,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, step, err := ValidateRFCCompliant(tt.passcode, secSha1, now)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
				require.Zero(t, step)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantValid, valid)
				if valid {
					require.NotZero(t, step)
				}
			}
		})
	}
}

// =============================================================================
// 9. VALIDATE STEP TESTS
// =============================================================================

// TestTOTPValidateStepInjection tests ValidateStep and ValidateCustomStep.
func TestTOTPValidateStepInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	// Generate a valid code
	code, err := GenerateCode(secSha1, time.Now().UTC())
	require.NoError(t, err)

	tests := []struct {
		name     string
		passcode string
		wantErr  error
	}{
		{
			name:     "valid passcode",
			passcode: code,
			wantErr:  nil,
		},
		{
			name:     "invalid format",
			passcode: "ABCDEF",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "wrong length",
			passcode: "12345",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, step, err := ValidateCustomStep(tt.passcode, secSha1, time.Now().UTC(), ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
				require.Zero(t, step)
			} else {
				require.NoError(t, err)
				// valid may be true or false
			}
		})
	}
}

// =============================================================================
// 10. ENCODER INJECTION TESTS
// =============================================================================

// TestTOTPEncoderInjection tests encoder parameter handling.
func TestTOTPEncoderInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	tests := []struct {
		name    string
		encoder otp.Encoder
		digits  otp.Digits
		wantErr error
	}{
		{
			name:    "valid default encoder",
			encoder: otp.EncoderDefault,
			digits:  otp.DigitsSix,
			wantErr: nil,
		},
		{
			name:    "valid Steam encoder",
			encoder: otp.EncoderSteam,
			digits:  otp.Digits(5),
			wantErr: nil,
		},
		{
			name:    "Steam encoder with 6 digits",
			encoder: otp.EncoderSteam,
			digits:  otp.DigitsSix,
			wantErr: nil,
		},
		{
			name:    "invalid encoder",
			encoder: otp.Encoder("evil"),
			digits:  otp.DigitsSix,
			wantErr: otp.ErrInvalidEncoder, // Unknown encoder is rejected
		},
		{
			name:    "default encoder with invalid digits",
			encoder: otp.EncoderDefault,
			digits:  otp.Digits(5),
			wantErr: otp.ErrDigitsOutOfRange,
		},
		{
			name:    "Steam encoder with invalid digits",
			encoder: otp.EncoderSteam,
			digits:  otp.Digits(4),
			wantErr: otp.ErrDigitsOutOfRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
				Period:    30,
				Digits:    tt.digits,
				Algorithm: otp.AlgorithmSHA1,
				Encoder:   tt.encoder,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.Empty(t, code)
			} else {
				require.NoError(t, err)
				expectedLen := int(tt.digits)
				if expectedLen == 0 {
					expectedLen = 6
				}
				if tt.encoder == otp.Encoder("evil") {
					require.Empty(t, code)
				} else {
					require.Len(t, code, expectedLen)
				}
			}
		})
	}
}

// =============================================================================
// 11. STEAM ENCODER PASSCODE INJECTION TESTS
// =============================================================================

// TestTOTPSteamPasscodeInjection tests Steam encoder passcode validation.
func TestTOTPSteamPasscodeInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate a valid Steam code
	code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.Digits(5),
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.EncoderSteam,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		passcode string
		wantErr  error
	}{
		{
			name:     "valid Steam passcode",
			passcode: code,
			wantErr:  nil,
		},
		{
			name:     "valid Steam characters",
			passcode: "23BCD",
			wantErr:  nil, // Format valid
		},
		{
			name:     "invalid digit 0",
			passcode: "23BC0",
			wantErr:  otp.ErrValidateInputInvalidChars, // 0 not in Steam alphabet
		},
		{
			name:     "invalid digit 1",
			passcode: "23BC1",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid letter A",
			passcode: "23BCA",
			wantErr:  otp.ErrValidateInputInvalidChars, // A not in Steam alphabet
		},
		{
			name:     "invalid letter E",
			passcode: "23BCE",
			wantErr:  otp.ErrValidateInputInvalidChars, // E not in Steam alphabet
		},
		{
			name:     "lowercase letters",
			passcode: "23bcd",
			wantErr:  otp.ErrValidateInputInvalidChars, // Steam requires uppercase
		},
		{
			name:     "special character",
			passcode: "23BC!",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "wrong length",
			passcode: "23BC",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "SQL injection pattern",
			passcode: "23';D",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "spaces in Steam code",
			passcode: "2 3BCD",
			wantErr:  nil, // Spaces removed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, secSha1, now, ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.Digits(5),
				Algorithm: otp.AlgorithmSHA1,
				Encoder:   otp.EncoderSteam,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// 12. REPLAY ATTACK PREVENTION DOCUMENTATION
// =============================================================================

// TestTOTPReplayAttackPrevention documents replay attack handling for TOTP.
func TestTOTPReplayAttackPrevention(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate a valid code
	code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Validate and get the step
	valid, step, err := ValidateCustomStep(code, secSha1, now, ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.NotZero(t, step)

	// Note: The library provides the step for replay prevention
	// Application must track used steps to prevent replay attacks

	t.Log("TOTP library provides time step for replay prevention")
	t.Log("Application must track used time steps and reject duplicates")

	// RFC-compliant validation returns step info
	valid2, step2, err := ValidateRFCCompliant(code, secSha1, now)
	require.NoError(t, err)
	require.True(t, valid2)
	require.NotZero(t, step2)
	require.Equal(t, step, step2)

	// SkewPolicy validation returns delta info
	valid3, step3, delta, err := ValidateCustomSkewPolicy(code, secSha1, now, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid3)
	require.NotZero(t, step3)
	require.Equal(t, 0, delta) // Exact match
}

// =============================================================================
// 13. COMBINED INJECTION TESTS
// =============================================================================

// TestTOTPCombinedInjection tests multiple injection vectors combined.
func TestTOTPCombinedInjection(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		passcode string
		secret   string
		period   uint
		digits   otp.Digits
		wantErr  error
	}{
		{
			name:     "invalid passcode and secret",
			passcode: "ABCDEF",
			secret:   "INVALID!",
			period:   30,
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:     "valid secret, invalid passcode",
			passcode: "12;DROP",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			period:   30,
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "invalid period with valid others",
			passcode: "123456",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			period:   301,
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrPeriodOutOfRange,
		},
		{
			name:     "invalid digits with valid others",
			passcode: "12345",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			period:   30,
			digits:   otp.Digits(5),
			wantErr:  otp.ErrDigitsOutOfRange,
		},
		{
			name:     "all valid",
			passcode: "123456",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			period:   30,
			digits:   otp.DigitsSix,
			wantErr:  nil, // Format valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First test generation
			_, genErr := GenerateCodeCustom(tt.secret, now, ValidateOpts{
				Period:    tt.period,
				Digits:    tt.digits,
				Algorithm: otp.AlgorithmSHA1,
			})

			// If generation error expected, check that
			if tt.wantErr == otp.ErrValidateSecretInvalidBase32 ||
				tt.wantErr == otp.ErrPeriodOutOfRange ||
				tt.wantErr == otp.ErrDigitsOutOfRange {
				require.Error(t, genErr)
				require.Equal(t, tt.wantErr, genErr)
				return
			}

			// If generation succeeded, test validation
			if genErr == nil {
				valid, valErr := ValidateCustom(tt.passcode, tt.secret, now, ValidateOpts{
					Period:    tt.period,
					Skew:      1,
					Digits:    tt.digits,
					Algorithm: otp.AlgorithmSHA1,
				})

				if tt.wantErr == otp.ErrValidateInputInvalidLength || tt.wantErr == otp.ErrValidateInputInvalidChars {
					require.Error(t, valErr)
					require.Equal(t, tt.wantErr, valErr)
					require.False(t, valid)
				} else {
					require.NoError(t, valErr)
				}
			}
		})
	}
}

// =============================================================================
// 14. VALIDATE SHORTCUT FUNCTION TESTS
// =============================================================================

// TestTOTPValidateShortcuts tests Validate and ValidateSecure shortcut functions.
func TestTOTPValidateShortcuts(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	secSha256 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // 24 bytes

	// Generate codes
	codeSha1, err := GenerateCode(secSha1, time.Now().UTC())
	require.NoError(t, err)

	codeSha256, err := GenerateCodeSecure(secSha256, time.Now().UTC())
	require.NoError(t, err)

	// Test Validate shortcut
	valid := Validate(codeSha1, secSha1)
	require.True(t, valid, "Validate should accept valid SHA1 code")

	// Test ValidateSecure shortcut
	valid = ValidateSecure(codeSha256, secSha256)
	require.True(t, valid, "ValidateSecure should accept valid SHA256 code")

	// Test wrong secret
	valid = Validate(codeSha1, "WRONGSECRET")
	require.False(t, valid, "Validate should reject wrong secret")

	// Test injection patterns - these should be caught by validation
	// Note: Validate() returns bool only, no error info
	valid = Validate("ABCDEF", secSha1) // Invalid characters
	require.False(t, valid, "Validate should reject invalid characters")

	valid = Validate("12345", secSha1) // Wrong length
	require.False(t, valid, "Validate should reject wrong length")

	valid = Validate("123';D", secSha1) // SQL injection pattern
	require.False(t, valid, "Validate should reject injection pattern")
}

// =============================================================================
// 15. GENERATE SHORTCUT FUNCTION TESTS
// =============================================================================

// TestTOTPGenerateShortcuts tests GenerateCode and GenerateCodeSecure shortcuts.
func TestTOTPGenerateShortcuts(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	secSha256 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Now().UTC()

	// Test GenerateCode shortcut
	code, err := GenerateCode(secSha1, now)
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Verify it's SHA1
	codeManual, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Equal(t, codeManual, code)

	// Test GenerateCodeSecure shortcut
	codeSecure, err := GenerateCodeSecure(secSha256, now)
	require.NoError(t, err)
	require.Len(t, codeSecure, 6)

	// Verify it's SHA256
	codeSecureManual, err := GenerateCodeCustom(secSha256, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	require.NoError(t, err)
	require.Equal(t, codeSecureManual, codeSecure)

	// Test invalid secret
	_, err = GenerateCode("INVALID!", now)
	require.Error(t, err)
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, err)

	// Test secret too short
	_, err = GenerateCode("ABCD", now)
	require.Error(t, err)
	require.Equal(t, otp.ErrSecretTooShort, err)
}

// =============================================================================
// 16. EDGE CASE INJECTION TESTS
// =============================================================================

// TestTOTPEdgeCaseInjection tests edge cases for TOTP.
func TestTOTPEdgeCaseInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	now := time.Now().UTC()

	// Generate valid code
	_, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		passcode string
		time     time.Time
		wantErr  error
	}{
		{
			name:     "passcode at Unix epoch",
			passcode: "123456",
			time:     time.Unix(0, 0).UTC(),
			wantErr:  nil, // Valid format
		},
		{
			name:     "passcode before Unix epoch",
			passcode: "123456",
			time:     time.Unix(-1000, 0).UTC(),
			wantErr:  nil, // Go handles negative time
		},
		{
			name:     "passcode with leading zeros",
			passcode: "000001",
			time:     now,
			wantErr:  nil, // Valid format
		},
		{
			name:     "passcode all zeros",
			passcode: "000000",
			time:     now,
			wantErr:  nil, // Valid format
		},
		{
			name:     "passcode all nines",
			passcode: "999999",
			time:     now,
			wantErr:  nil, // Valid format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, secSha1, tt.time, ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
