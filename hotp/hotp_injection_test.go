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

package hotp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// =============================================================================
// PASSCODE INPUT INJECTION ATTACK TESTS
// =============================================================================
// This test file validates that passcode input is properly sanitized and
// prevents various injection attacks during OTP validation.
// =============================================================================

// =============================================================================
// 1. NON-DIGIT CHARACTER TESTS (Default Encoder)
// =============================================================================

// TestPasscodeInjection_NonDigitCharacters tests that only digits 0-9 are
// accepted for the default encoder.
func TestPasscodeInjection_NonDigitCharacters(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY" // 16-byte secret (Base32)

	tests := []struct {
		name     string
		passcode string
		wantErr  error
	}{
		{
			name:     "valid digits only",
			passcode: "123456",
			wantErr:  nil, // Valid format
		},
		{
			name:     "letter in passcode",
			passcode: "12345A",
			wantErr:  otp.ErrValidateInputInvalidChars, // Invalid character
		},
		{
			name:     "all letters",
			passcode: "ABCDEF",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "mixed alphanumeric",
			passcode: "12AB34",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "special character - hyphen",
			passcode: "123-456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - underscore",
			passcode: "123_456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - dot",
			passcode: "123.456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - slash",
			passcode: "123/456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - colon",
			passcode: "123:456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - semicolon",
			passcode: "123;456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - pipe",
			passcode: "123|456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - ampersand",
			passcode: "123&456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - equals",
			passcode: "123=456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - plus",
			passcode: "123+456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - asterisk",
			passcode: "123*456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - percent",
			passcode: "123%456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - dollar",
			passcode: "123$456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - hash",
			passcode: "123#456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - at",
			passcode: "123@456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - exclamation",
			passcode: "123!456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - question",
			passcode: "123?456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - bracket",
			passcode: "123[456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - parenthesis",
			passcode: "123(456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - angle bracket",
			passcode: "123<456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - quote",
			passcode: "123'456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - double quote",
			passcode: "123\"456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - backslash",
			passcode: "123\\456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "special character - backtick",
			passcode: "123`456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "null byte",
			passcode: "123\x00456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "tab character",
			passcode: "123\t456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "newline character",
			passcode: "123\n456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "carriage return",
			passcode: "123\r456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "form feed",
			passcode: "123\f456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "vertical tab",
			passcode: "123\v456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "delete character",
			passcode: "123\x7f456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "escape character",
			passcode: "123\x1b456",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "control character sequence",
			passcode: "\x01\x02\x03\x04\x05\x06",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "SQL injection pattern",
			passcode: "123';D",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "command injection pattern",
			passcode: "123|rm",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "unicode character",
			passcode: "123\u4e2d6",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "emoji in passcode",
			passcode: "123😀56",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, 0, secSha1, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
				// valid may be true or false depending on actual OTP match
			}
		})
	}
}

// =============================================================================
// 2. STEAM ENCODER CHARACTER TESTS
// =============================================================================

// TestPasscodeInjection_SteamEncoderCharacters tests that only Steam alphabet
// characters (23456789BCDFGHJKMNPQRTVWXY) are accepted for Steam encoder.
func TestPasscodeInjection_SteamEncoderCharacters(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY" // 16-byte secret (Base32)

	tests := []struct {
		name     string
		passcode string
		wantErr  error
	}{
		{
			name:     "valid Steam characters",
			passcode: "2B3C4",
			wantErr:  nil, // Valid format (may not match but format OK)
		},
		{
			name:     "all valid Steam digits",
			passcode: "23456",
			wantErr:  nil,
		},
		{
			name:     "all valid Steam letters",
			passcode: "BCDFG",
			wantErr:  nil,
		},
		{
			name:     "invalid digit 0",
			passcode: "12340",
			wantErr:  otp.ErrValidateInputInvalidChars, // 0 not in Steam alphabet
		},
		{
			name:     "invalid digit 1",
			passcode: "12341",
			wantErr:  otp.ErrValidateInputInvalidChars, // 1 not in Steam alphabet
		},
		{
			name:     "invalid digit 8",
			passcode: "23458",
			wantErr:  nil, // 8 IS in Steam alphabet: 23456789
		},
		{
			name:     "invalid digit 9",
			passcode: "23459",
			wantErr:  nil, // 9 IS in Steam alphabet: 23456789
		},
		{
			name:     "invalid letter A",
			passcode: "ABCDE",
			wantErr:  otp.ErrValidateInputInvalidChars, // A not in Steam alphabet
		},
		{
			name:     "invalid letter E",
			passcode: "BCDEF",
			wantErr:  otp.ErrValidateInputInvalidChars, // E not in Steam alphabet
		},
		{
			name:     "invalid letter I",
			passcode: "BCDGI", // I not in Steam alphabet (only H)
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid letter L",
			passcode: "BCDKL", // L not in Steam alphabet
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid letter O",
			passcode: "BCDNO", // O not in Steam alphabet (only N)
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid letter S",
			passcode: "BCDPS", // S not in Steam alphabet (only P)
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid letter U",
			passcode: "BCDTU", // U not in Steam alphabet (only T)
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "invalid letter Z",
			passcode: "BCDYZ", // Z not in Steam alphabet (only Y)
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "lowercase letters",
			passcode: "bcdfg",
			wantErr:  otp.ErrValidateInputInvalidChars, // Steam encoder requires uppercase
		},
		{
			name:     "special character in Steam",
			passcode: "2B3C!",
			wantErr:  otp.ErrValidateInputInvalidChars,
		},
		{
			name:     "space in Steam code",
			passcode: "2B 3C",                           // 5 chars with space, after removing space becomes 4 chars
			wantErr:  otp.ErrValidateInputInvalidLength, // Length mismatch after removing spaces
		},
		{
			name:     "unicode in Steam",
			passcode: "2B3\u4e2d",
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, 0, secSha1, ValidateOpts{
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
// 3. LENGTH VALIDATION TESTS
// =============================================================================

// TestPasscodeInjection_LengthValidation tests that passcode length is
// strictly validated.
func TestPasscodeInjection_LengthValidation(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	tests := []struct {
		name     string
		passcode string
		digits   otp.Digits
		wantErr  error
	}{
		{
			name:     "correct length 6",
			passcode: "123456",
			digits:   otp.DigitsSix,
			wantErr:  nil,
		},
		{
			name:     "correct length 8",
			passcode: "12345678",
			digits:   otp.DigitsEight,
			wantErr:  nil,
		},
		{
			name:     "too short - 5 chars for 6 digits",
			passcode: "12345",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "too short - 1 char",
			passcode: "1",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "too short - empty",
			passcode: "",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "too long - 7 chars for 6 digits",
			passcode: "1234567",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "too long - 10 chars for 6 digits",
			passcode: "1234567890",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "very long input",
			passcode: "1234567890123456789012345678901234567890",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "extremely long input - potential buffer attack",
			passcode: strings.Repeat("1", 10000),
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "too short for 8 digits",
			passcode: "123456",
			digits:   otp.DigitsEight,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "too long for 8 digits",
			passcode: "123456789",
			digits:   otp.DigitsEight,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, 0, secSha1, ValidateOpts{
				Digits:    tt.digits,
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
// 4. SPACE HANDLING TESTS
// =============================================================================

// TestPasscodeInjection_SpaceHandling tests that spaces are properly removed.
func TestPasscodeInjection_SpaceHandling(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	// Generate a valid code first
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
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
			name:      "single internal space",
			passcode:  code[:3] + " " + code[3:],
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "multiple internal spaces",
			passcode:  code[:2] + " " + code[2:4] + " " + code[4:],
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "leading space",
			passcode:  " " + code,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "trailing space",
			passcode:  code + " ",
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "both leading and trailing spaces",
			passcode:  "  " + code + "  ",
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "all spaces (invalid)",
			passcode:  "      ",
			wantErr:   otp.ErrValidateInputInvalidLength, // After removing spaces, empty
			wantValid: false,
		},
		{
			name:      "too many spaces making code too short",
			passcode:  "1 2 3", // Only 3 digits after removing spaces
			wantErr:   otp.ErrValidateInputInvalidLength,
			wantValid: false,
		},
		{
			name:      "tab character (not removed)",
			passcode:  code[:3] + "\t" + code[3:],
			wantErr:   otp.ErrValidateInputInvalidLength, // Tab not handled like space
			wantValid: false,
		},
		{
			name:      "non-breaking space (not removed)",
			passcode:  code[:3] + "\u00a0" + code[3:], // NBSP
			wantErr:   otp.ErrValidateInputInvalidLength,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, 0, secSha1, ValidateOpts{
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
// 5. UNICODE FULLWIDTH CHARACTER TESTS
// =============================================================================

// TestPasscodeInjection_UnicodeFullwidth tests fullwidth digit handling.
func TestPasscodeInjection_UnicodeFullwidth(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	// Generate a valid code first
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Fullwidth digit mapping: ASCII -> Fullwidth
	fullwidthDigits := map[rune]rune{
		'0': '０', '1': '１', '2': '２', '3': '３',
		'4': '４', '5': '５', '6': '６', '7': '７',
		'8': '８', '9': '９',
	}

	// Create fullwidth version of code
	fullwidthCode := ""
	for _, c := range code {
		if fw, ok := fullwidthDigits[c]; ok {
			fullwidthCode += string(fw)
		} else {
			fullwidthCode += string(c)
		}
	}

	tests := []struct {
		name      string
		passcode  string
		useNorm   bool
		wantErr   error
		wantValid bool
	}{
		{
			name:      "ASCII digits - normal validation",
			passcode:  code,
			useNorm:   false,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "Fullwidth digits - normal validation fails",
			passcode:  fullwidthCode,
			useNorm:   false,
			wantErr:   otp.ErrValidateInputInvalidLength, // Length mismatch
			wantValid: false,
		},
		{
			name:      "Fullwidth digits - normalized validation succeeds",
			passcode:  fullwidthCode,
			useNorm:   true,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "Mixed ASCII and fullwidth",
			passcode:  string(code[0]) + string(fullwidthDigits[rune(code[1])]) + code[2:],
			useNorm:   false,
			wantErr:   otp.ErrValidateInputInvalidLength,
			wantValid: false,
		},
		{
			name:      "Mixed - normalized succeeds",
			passcode:  string(code[0]) + string(fullwidthDigits[rune(code[1])]) + code[2:],
			useNorm:   true,
			wantErr:   nil,
			wantValid: true,
		},
		{
			name:      "Invalid fullwidth character",
			passcode:  "１２３４５Ａ", // Fullwidth A
			useNorm:   true,
			wantErr:   otp.ErrValidateInputInvalidChars, // A is not digit
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var valid bool
			var err error

			if tt.useNorm {
				valid, err = ValidateCustomNormalized(tt.passcode, 0, secSha1, ValidateOpts{
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
			} else {
				valid, err = ValidateCustom(tt.passcode, 0, secSha1, ValidateOpts{
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})
			}

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
// 6. SECRET INJECTION TESTS
// =============================================================================

// TestSecretInjection tests that secret input is properly validated.
func TestSecretInjection(t *testing.T) {
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
			wantErr: nil, // Spaces removed
		},
		{
			name:    "secret with lowercase",
			secret:  "gezdgnbvgy3tqojqgezdgnbvgy",
			wantErr: nil, // Converted to uppercase
		},
		{
			name:    "invalid Base32 characters",
			secret:  "GEZDGNBVGY3TQOJQGEZDGNBVG!",
			wantErr: otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:    "digit 0 in secret",
			secret:  "GEZD0NBVGY3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32, // 0 not in Base32
		},
		{
			name:    "digit 1 in secret",
			secret:  "GEZD1NBVGY3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32, // 1 not in Base32
		},
		{
			name:    "digit 8 in secret",
			secret:  "GEZD8NBVGY3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32, // 8 not in Base32
		},
		{
			name:    "digit 9 in secret",
			secret:  "GEZD9NBVGY3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32, // 9 not in Base32
		},
		{
			name:    "valid digits 2-7 in secret",
			secret:  "GEZD234567NBVGY3TQOJQGEZDGNBV",
			wantErr: nil, // 2-7 are valid
		},
		{
			name:    "secret too short",
			secret:  "ABCD",
			wantErr: otp.ErrSecretTooShort, // After decode, less than 16 bytes
		},
		{
			name:    "empty secret",
			secret:  "",
			wantErr: otp.ErrSecretTooShort, // After decode, less than 16 bytes
		},
		{
			name:    "null byte in secret",
			secret:  "GEZDGNBVGY\x003TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:    "newline in secret",
			secret:  "GEZDGNBVGY\n3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:    "SQL injection in secret",
			secret:  "GEZD'DROP;NBVGY3TQOJQGEZDGNBVGY",
			wantErr: otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:    "very long secret",
			secret:  "GEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBVGEZDGNBVGY3TQOJQGEZDGNBV",
			wantErr: otp.ErrSecretTooLong, // More than 64 bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(tt.secret, 0, ValidateOpts{
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
// 7. DIGITS RANGE INJECTION TESTS
// =============================================================================

// TestDigitsRangeInjection tests digits parameter validation.
func TestDigitsRangeInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	tests := []struct {
		name    string
		digits  otp.Digits
		encoder otp.Encoder
		wantErr error
	}{
		{
			name:    "valid 6 digits default",
			digits:  otp.DigitsSix,
			encoder: otp.EncoderDefault,
			wantErr: nil,
		},
		{
			name:    "valid 8 digits default",
			digits:  otp.DigitsEight,
			encoder: otp.EncoderDefault,
			wantErr: nil,
		},
		{
			name:    "valid 7 digits default",
			digits:  otp.Digits(7),
			encoder: otp.EncoderDefault,
			wantErr: nil,
		},
		{
			name:    "valid 9 digits default",
			digits:  otp.Digits(9),
			encoder: otp.EncoderDefault,
			wantErr: nil,
		},
		{
			name:    "valid 10 digits default",
			digits:  otp.Digits(10),
			encoder: otp.EncoderDefault,
			wantErr: nil,
		},
		{
			name:    "invalid 5 digits default",
			digits:  otp.Digits(5),
			encoder: otp.EncoderDefault,
			wantErr: otp.ErrDigitsOutOfRange,
		},
		{
			name:    "invalid 11 digits default",
			digits:  otp.Digits(11),
			encoder: otp.EncoderDefault,
			wantErr: otp.ErrDigitsOutOfRange,
		},
		{
			name:    "zero digits defaults to six",
			digits:  otp.Digits(0),
			encoder: otp.EncoderDefault,
			wantErr: nil, // Zero defaults to DigitsSix, code length should be 6
		},
		{
			name:    "invalid negative digits",
			digits:  otp.Digits(-1),
			encoder: otp.EncoderDefault,
			wantErr: otp.ErrDigitsOutOfRange, // Negative digits are invalid
		},
		{
			name:    "valid 5 digits Steam",
			digits:  otp.Digits(5),
			encoder: otp.EncoderSteam,
			wantErr: nil,
		},
		{
			name:    "valid 6 digits Steam",
			digits:  otp.Digits(6),
			encoder: otp.EncoderSteam,
			wantErr: nil,
		},
		{
			name:    "valid 10 digits Steam",
			digits:  otp.Digits(10),
			encoder: otp.EncoderSteam,
			wantErr: nil,
		},
		{
			name:    "invalid 4 digits Steam",
			digits:  otp.Digits(4),
			encoder: otp.EncoderSteam,
			wantErr: otp.ErrDigitsOutOfRange,
		},
		{
			name:    "invalid 11 digits Steam",
			digits:  otp.Digits(11),
			encoder: otp.EncoderSteam,
			wantErr: otp.ErrDigitsOutOfRange,
		},
		{
			name:    "invalid unknown encoder",
			digits:  otp.DigitsSix,
			encoder: otp.Encoder("evil"),
			wantErr: otp.ErrInvalidEncoder, // Unknown encoder is rejected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
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
				// When digits is 0, it defaults to DigitsSix (length 6)
				expectedLen := int(tt.digits)
				if expectedLen == 0 {
					expectedLen = 6
				}
				// Unknown encoder produces empty code (switch has no match)
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
// 8. WINDOW VALIDATION INJECTION TESTS
// =============================================================================

// TestWindowValidationInjection tests window parameter validation.
func TestWindowValidationInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	// Generate a valid code
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		window  uint
		wantErr error
	}{
		{
			name:    "valid window 0",
			window:  0,
			wantErr: nil,
		},
		{
			name:    "valid window 1",
			window:  1,
			wantErr: nil,
		},
		{
			name:    "valid window 5",
			window:  5,
			wantErr: nil,
		},
		{
			name:    "valid window 10 (max)",
			window:  10,
			wantErr: nil,
		},
		{
			name:    "invalid window 11",
			window:  11,
			wantErr: otp.ErrWindowTooLarge,
		},
		{
			name:    "invalid window 100",
			window:  100,
			wantErr: otp.ErrWindowTooLarge,
		},
		{
			name:    "invalid window 1000",
			window:  1000,
			wantErr: otp.ErrWindowTooLarge,
		},
		{
			name:    "invalid very large window",
			window:  1000000,
			wantErr: otp.ErrWindowTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delta, found, err := ValidateCustomWindow(code, 0, secSha1, ValidateOptsWithWindow{
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
				Window:    tt.window,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, found)
			} else {
				require.NoError(t, err)
				// delta may be 0 if not found, or the delta value if found
				_ = delta
			}
		})
	}
}

// =============================================================================
// 9. ALGORITHM INJECTION TESTS
// =============================================================================

// TestAlgorithmInjection tests algorithm parameter handling.
func TestAlgorithmInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"                                      // 16 bytes
	secSha256 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                              // 24 bytes
	secSha512 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQ" // 40 bytes

	tests := []struct {
		name    string
		secret  string
		alg     otp.Algorithm
		wantErr error
	}{
		{
			name:    "valid SHA1",
			secret:  secSha1,
			alg:     otp.AlgorithmSHA1,
			wantErr: nil,
		},
		{
			name:    "valid SHA256",
			secret:  secSha256,
			alg:     otp.AlgorithmSHA256,
			wantErr: nil,
		},
		{
			name:    "valid SHA512",
			secret:  secSha512,
			alg:     otp.AlgorithmSHA512,
			wantErr: nil,
		},
		{
			name:    "SHA256 with short secret",
			secret:  secSha1,
			alg:     otp.AlgorithmSHA256,
			wantErr: nil, // Secret length validated, not algorithm-specific
		},
		{
			name:    "MD5 algorithm",
			secret:  secSha1,
			alg:     otp.AlgorithmMD5,
			wantErr: otp.ErrDigestTooSmall, // MD5 produces 16 bytes, need 19
		},
		{
			name:    "SHA224 algorithm",
			secret:  secSha1,
			alg:     otp.AlgorithmSHA224,
			wantErr: nil, // SHA224 produces 28 bytes
		},
		{
			name:    "SHA384 algorithm",
			secret:  secSha1,
			alg:     otp.AlgorithmSHA384,
			wantErr: nil, // SHA384 produces 48 bytes
		},
		{
			name:    "SHA3-256 algorithm",
			secret:  secSha1,
			alg:     otp.AlgorithmSHA3_256,
			wantErr: nil,
		},
		{
			name:    "SHA3-512 algorithm",
			secret:  secSha1,
			alg:     otp.AlgorithmSHA3_512,
			wantErr: nil,
		},
		{
			name:    "zero algorithm defaults to SHA1",
			secret:  secSha1,
			alg:     otp.Algorithm(0),
			wantErr: nil,
		},
		{
			name:    "invalid algorithm number",
			secret:  secSha1,
			alg:     otp.Algorithm(999),
			wantErr: otp.ErrInvalidAlgorithm,
		},
		{
			name:    "invalid negative algorithm",
			secret:  secSha1,
			alg:     otp.Algorithm(-1),
			wantErr: otp.ErrInvalidAlgorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := GenerateCodeCustom(tt.secret, 0, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tt.alg,
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
// 10. COMBINED INJECTION TESTS
// =============================================================================

// TestCombinedInjection tests multiple injection vectors combined.
func TestCombinedInjection(t *testing.T) {
	tests := []struct {
		name     string
		passcode string
		secret   string
		digits   otp.Digits
		wantErr  error
	}{
		{
			name:     "invalid passcode and secret",
			passcode: "ABCDEF",
			secret:   "INVALID!",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateSecretInvalidBase32,
		},
		{
			name:     "valid secret, invalid passcode",
			passcode: "12;DROP",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength,
		},
		{
			name:     "invalid digits with valid others",
			passcode: "12345",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			digits:   otp.Digits(5), // Invalid for default encoder
			wantErr:  otp.ErrDigitsOutOfRange,
		},
		{
			name:     "all valid",
			passcode: "123456",
			secret:   "GEZDGNBVGY3TQOJQGEZDGNBVGY",
			digits:   otp.DigitsSix,
			wantErr:  nil, // Format valid, may not match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First test GenerateCodeCustom with secret and digits
			_, genErr := GenerateCodeCustom(tt.secret, 0, ValidateOpts{
				Digits:    tt.digits,
				Algorithm: otp.AlgorithmSHA1,
			})

			// If generation error expected, check that
			if tt.wantErr == otp.ErrValidateSecretInvalidBase32 ||
				tt.wantErr == otp.ErrDigitsOutOfRange {
				require.Error(t, genErr)
				require.Equal(t, tt.wantErr, genErr)
				return
			}

			// If generation succeeded, test ValidateCustom with passcode
			if genErr == nil {
				valid, valErr := ValidateCustom(tt.passcode, 0, tt.secret, ValidateOpts{
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
// 11. REPLAY ATTACK PREVENTION TESTS
// =============================================================================

// TestReplayAttackPrevention documents expected replay attack handling.
func TestReplayAttackPrevention(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	// Generate a valid code
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Test that the same code validates at counter 0
	valid, err := ValidateCustom(code, 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid, "Code should validate at correct counter")

	// Note: The library doesn't track used counters internally.
	// Replay attack prevention must be implemented by the application
	// by tracking used counters/steps and rejecting duplicates.

	t.Log("Library provides step/counter info for replay prevention")
	t.Log("Application must track used counters to prevent replay attacks")

	// Verify that ValidateCustomWindow returns counter info
	delta, found, err := ValidateCustomWindow(code, 0, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    5,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 0, delta, "Should match at exact counter")
}

// =============================================================================
// 12. EDGE CASE INJECTION TESTS
// =============================================================================

// TestEdgeCaseInjection tests edge cases that might bypass validation.
func TestEdgeCaseInjection(t *testing.T) {
	secSha1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY"

	tests := []struct {
		name     string
		passcode string
		digits   otp.Digits
		wantErr  error
	}{
		{
			name:     "passcode with leading zeros",
			passcode: "000001",
			digits:   otp.DigitsSix,
			wantErr:  nil, // Valid format
		},
		{
			name:     "all zeros",
			passcode: "000000",
			digits:   otp.DigitsSix,
			wantErr:  nil, // Valid format
		},
		{
			name:     "all nines",
			passcode: "999999",
			digits:   otp.DigitsSix,
			wantErr:  nil, // Valid format
		},
		{
			name:     "binary string as passcode",
			passcode: "\x31\x32\x33\x34\x35\x36", // Binary representation of "123456"
			digits:   otp.DigitsSix,
			wantErr:  nil, // Should be treated as string "123456"
		},
		{
			name:     "passcode with unicode escape",
			passcode: "\\u0031\\u0032\\u0033\\u0034\\u0035\\u0036",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength, // Not interpreted
		},
		{
			name:     "passcode with HTML entities",
			passcode: "&#49;&#50;&#51;&#52;&#53;&#54;",
			digits:   otp.DigitsSix,
			wantErr:  otp.ErrValidateInputInvalidLength, // Not interpreted
		},
		{
			name:     "passcode with octal escape",
			passcode: "\061\062\063\064\065\066", // Octal representation of "123456"
			digits:   otp.DigitsSix,
			wantErr:  nil, // Should be treated as string "123456"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.passcode, 0, secSha1, ValidateOpts{
				Digits:    tt.digits,
				Algorithm: otp.AlgorithmSHA1,
			})
			if tt.wantErr != nil {
				require.Error(t, err)
				require.Equal(t, tt.wantErr, err)
				require.False(t, valid)
			} else {
				require.NoError(t, err)
				// valid may be true or false depending on match
			}
		})
	}
}
