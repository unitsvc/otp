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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
	"github.com/unitsvc/otp/internal"

	"encoding/base32"
	"strings"
	"testing"
)

type tc struct {
	Counter uint64
	TOTP    string
	Mode    otp.Algorithm
	Secret  string
}

var (
	secSha1 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	rfcMatrixTCs = []tc{
		{0, "755224", otp.AlgorithmSHA1, secSha1},
		{1, "287082", otp.AlgorithmSHA1, secSha1},
		{2, "359152", otp.AlgorithmSHA1, secSha1},
		{3, "969429", otp.AlgorithmSHA1, secSha1},
		{4, "338314", otp.AlgorithmSHA1, secSha1},
		{5, "254676", otp.AlgorithmSHA1, secSha1},
		{6, "287922", otp.AlgorithmSHA1, secSha1},
		{7, "162583", otp.AlgorithmSHA1, secSha1},
		{8, "399871", otp.AlgorithmSHA1, secSha1},
		{9, "520489", otp.AlgorithmSHA1, secSha1},
	}
)

// Test values from http://tools.ietf.org/html/rfc4226#appendix-D
func TestValidateRFCMatrix(t *testing.T) {

	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Counter, tx.Secret,
			ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
	}
}

func TestGenerateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, tx.Counter,
			ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tx.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, tx.TOTP, passcode)
	}
}

func TestGenerateCodeCustom(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	code, err := GenerateCodeCustom("foo", 1, ValidateOpts{})
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, err, "Decoding of secret as base32 failed.")
	require.Equal(t, "", code, "Code should be empty string when we have an error.")

	code, err = GenerateCodeCustom(secSha1, 1, ValidateOpts{})
	require.Equal(t, 6, len(code), "Code should be 6 digits when we have not an error.")
	require.NoError(t, err, "Expected no error.")
}

func TestValidateInvalid(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	valid, err := ValidateCustom("foo", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err, "Expected Invalid length error.")
	require.Equal(t, false, valid, "Valid should be false when we have an error.")

	valid, err = ValidateCustom("foo", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err, "Expected Invalid length error.")
	require.Equal(t, false, valid, "Valid should be false when we have an error.")

	valid, err = ValidateCustom("000000", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.Equal(t, false, valid, "Valid should be false.")

	valid = Validate("000000", 11, secSha1)
	require.Equal(t, false, valid, "Valid should be false.")
}

// This tests for issue #10 - secrets without padding
// Uses 16-byte secret (minimum RFC requirement) encoded as 26-char base32 (no padding)
func TestValidatePadding(t *testing.T) {
	valid, err := ValidateCustom("504023", 0, "GEZDGNBVGY3TQOJQGEZDGNBVGY",
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.Equal(t, true, valid, "Valid should be true.")
}

// Tests lowercase secret handling with 16-byte secret
func TestValidateLowerCaseSecret(t *testing.T) {
	valid, err := ValidateCustom("504023", 0, "gezdgnbvgy3tqojqgezdgnbvgy",
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.Equal(t, true, valid, "Valid should be true.")
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "generate basic HOTP")
	require.Equal(t, "SnakeOil", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@example.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 chars long as base32 (20 bytes).")

	k, err = Generate(GenerateOpts{
		Issuer:      "Snake Oil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "issuer with a space in the name")
	require.Contains(t, k.String(), "issuer=Snake%20Oil")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "generate larger HOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "",
		AccountName: "alice@example.com",
	})
	require.Equal(t, otp.ErrGenerateMissingIssuer, err, "generate missing issuer")
	require.Nil(t, k, "key should be nil on error.")

	k, err = Generate(GenerateOpts{
		Issuer:      "Foobar, Inc",
		AccountName: "",
	})
	require.Equal(t, otp.ErrGenerateMissingAccountName, err, "generate missing account name.")
	require.Nil(t, k, "key should be nil on error.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  17, // anything that is not divisible by 5, really
	})
	require.NoError(t, err, "Secret size is valid when length not divisible by 5.")
	require.NotContains(t, k.Secret(), "=", "Secret has no escaped characters.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	require.NoError(t, err, "Secret generation failed")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err, "Secret was not valid base32")
	require.Equal(t, sec, []byte("helloworld"), "Specified Secret was not kept")
}

func TestGenerateWithCounter(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Counter:     5,
	})
	require.NoError(t, err)
	require.Contains(t, k.String(), "counter=5")
}

func TestGenerateWithImageURL(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		ImageURL:    "https://example.com/logo.png",
	})
	require.NoError(t, err)
	require.Contains(t, k.String(), "image=")
	require.Equal(t, "https://example.com/logo.png", k.ImageURL())
}

func TestGenerateWithoutImageURL(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err)
	require.NotContains(t, k.String(), "image=")
}

func TestGenerateCode(t *testing.T) {
	// Test the simple GenerateCode wrapper function
	code, err := GenerateCode(secSha1, 0)
	require.NoError(t, err)
	require.Len(t, code, 6)
}

func TestGenerateCodeSteam(t *testing.T) {
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	require.NoError(t, err)
	require.Len(t, code, 5)
	// Verify all characters are from Steam alphabet
	for _, c := range code {
		require.True(t, strings.ContainsRune("23456789BCDFGHJKMNPQRTVWXY", c), "invalid char: %c", c)
	}
}

func TestGenerateCodeEightDigits(t *testing.T) {
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits: otp.DigitsEight,
	})
	require.NoError(t, err)
	require.Len(t, code, 8)
}

func TestValidateCustomAllSpaces(t *testing.T) {
	valid, err := ValidateCustom("   ", 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err)
	require.False(t, valid)
}

func TestValidateSpaces(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate a valid code first
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	tests := []struct {
		name  string
		input string
	}{
		{"single space", code[:3] + " " + code[3:]},
		{"multiple spaces", code[:2] + " " + code[2:4] + " " + code[4:]},
		{"leading space", " " + code},
		{"trailing space", code + " "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ValidateCustom(tt.input, 0, secSha1, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			require.NoError(t, err)
			require.True(t, valid, "Passcode with %s should validate", tt.name)
		})
	}
}

// ===== Window Validation Tests =====

func TestValidateCustomWindowExact(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate code at counter=100
	code, err := GenerateCodeCustom(secSha1, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Validate at exact counter with window=10
	delta, found, err := ValidateCustomWindow(code, 100, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    10,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 0, delta)
}

func TestValidateCustomWindowPast(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate code at counter=100
	code, err := GenerateCodeCustom(secSha1, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Validate at counter=90 with window=10 (should find delta=10)
	delta, found, err := ValidateCustomWindow(code, 90, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    10,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 10, delta)
}

func TestValidateCustomWindowFuture(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate code at counter=100
	code, err := GenerateCodeCustom(secSha1, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Validate at counter=110 with window=10 (should find delta=-10)
	delta, found, err := ValidateCustomWindow(code, 110, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    10,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, -10, delta)
}

func TestValidateCustomWindowNotFound(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate code at counter=100
	code, err := GenerateCodeCustom(secSha1, 100, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Validate at counter=120 with window=10 (outside window)
	_, found, err := ValidateCustomWindow(code, 120, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    10,
	})
	require.NoError(t, err)
	require.False(t, found)
}

func TestValidateCustomWindowLargeCounter(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Test with large counter (1e10)
	largeCounter := uint64(10000000000)
	code, err := GenerateCodeCustom(secSha1, largeCounter, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Validate at largeCounter-5 with window=5 (within security limit)
	delta, found, err := ValidateCustomWindow(code, largeCounter-5, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    5,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 5, delta)

	// Test that window > 10 returns error (security guardrail)
	_, _, err = ValidateCustomWindow(code, largeCounter-100, secSha1, ValidateOptsWithWindow{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Window:    100,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrWindowTooLarge, err)
}

func TestSecretWithInternalSpaces(t *testing.T) {
	// 16-byte secret with spaces for readability: "GEZD GNBV GY3T QOJQ GEZD GNBV GY"
	code, err := GenerateCodeCustom("GEZD GNBV GY3T QOJQ GEZD GNBV GY", 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)
}

// ===== NFKC Normalization Tests =====

func TestValidateCustomNormalized(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate a valid code
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Test that normal validation works
	valid, err := ValidateCustom(code, 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)

	// Test that normalized validation also works
	valid, err = ValidateCustomNormalized(code, 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateCustomNormalizedFullwidth(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate a valid code (ASCII digits)
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Use actual Japanese fullwidth digits from test file
	// These are the fullwidth digits: ０１２３４５６７８９
	fullwidthMap := map[rune]rune{
		'0': '０', '1': '１', '2': '２', '3': '３',
		'4': '４', '5': '５', '6': '６', '7': '７',
		'8': '８', '9': '９',
	}

	fullwidthCode := ""
	for _, c := range code {
		if mapped, ok := fullwidthMap[c]; ok {
			fullwidthCode += string(mapped)
		} else {
			fullwidthCode += string(c)
		}
	}

	// Debug: Check what NFKC does
	normalized := internal.NormalizeNFKC(fullwidthCode)
	t.Logf("Code: %s, Fullwidth: %s (len=%d), Normalized: %s (len=%d)",
		code, fullwidthCode, len(fullwidthCode), normalized, len(normalized))

	// Verify fullwidthCode was created correctly
	require.Equal(t, 6, len([]rune(fullwidthCode)), "Fullwidth code should have 6 rune characters")
	require.Equal(t, 6, len(normalized), "Normalized code should have 6 bytes")

	// Normal validation should fail with fullwidth due to length mismatch
	// (fullwidth bytes != ASCII bytes)
	valid, err := ValidateCustom(fullwidthCode, 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err, "Should return length error for fullwidth")
	require.False(t, valid, "Should not be valid")

	// Normalized validation should succeed (NFKC converts fullwidth to ASCII)
	valid, err = ValidateCustomNormalized(fullwidthCode, 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid, "Normalized validation should succeed with fullwidth characters")
}

func TestValidateCustomNormalizedMixed(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate a valid code
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// Create mixed fullwidth/ASCII input using proper fullwidth digits
	fullwidthDigits := []rune{'０', '１', '２', '３', '４', '５', '６', '７', '８', '９'}
	mixedCode := string(code[0]) + // ASCII first digit
		string(fullwidthDigits[int(code[1]-'0')]) + // Fullwidth second digit
		string(code[2:]) // ASCII rest

	// Normalized validation should handle this
	valid, err := ValidateCustomNormalized(mixedCode, 0, secSha1, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid, "Normalized validation should handle mixed characters")
}

// ===== Secure Functions Tests =====

func TestValidateSecure(t *testing.T) {
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))

	// Generate SHA256 code
	code, err := GenerateCodeCustom(secSha256, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	require.NoError(t, err)

	// ValidateSecure should validate SHA256 code
	valid := ValidateSecure(code, 0, secSha256)
	require.True(t, valid, "ValidateSecure should validate SHA256 code")
}

func TestGenerateCodeSecure(t *testing.T) {
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))

	// GenerateCodeSecure should produce SHA256 code
	code, err := GenerateCodeSecure(secSha256, 0)
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Verify it matches manual SHA256 generation
	codeManual, err := GenerateCodeCustom(secSha256, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	require.NoError(t, err)
	require.Equal(t, codeManual, code)
}

func TestAlgorithmAliases(t *testing.T) {
	// Verify aliases are correct
	require.Equal(t, otp.AlgorithmCompat, otp.AlgorithmSHA1)
	require.Equal(t, otp.AlgorithmSecure, otp.AlgorithmSHA256)

	// Test using aliases
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))

	codeCompat, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Algorithm: otp.AlgorithmCompat,
	})
	require.NoError(t, err)

	codeSecure, err := GenerateCodeCustom(secSha256, 0, ValidateOpts{
		Algorithm: otp.AlgorithmSecure,
	})
	require.NoError(t, err)

	require.Len(t, codeCompat, 6)
	require.Len(t, codeSecure, 6)
}

// ===== Coverage Improvement Tests =====

func TestIsValidPasscodeChars(t *testing.T) {
	// Test default encoder - valid digits
	valid, err := ValidateCustom("123456", 0, secSha1, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)
	_ = valid // valid may be false since "123456" is not the correct OTP code
	// Invalid digits should fail character check
	valid, err = ValidateCustom("abcdef", 0, secSha1, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.Error(t, err) // Character validation fails
	require.False(t, valid)

	// Test Steam encoder - valid Steam chars
	secSteam := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	steamCode, err := GenerateCodeCustom(secSteam, 0, ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	require.NoError(t, err)

	// Validate Steam code
	valid, err = ValidateCustom(steamCode, 0, secSteam, ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	require.NoError(t, err)
	require.True(t, valid)

	// Invalid Steam chars (contains 'A' and 'E' which are not in Steam alphabet)
	valid, err = ValidateCustom("ABCDE", 0, secSteam, ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	require.Error(t, err)
	require.False(t, valid)

	// Test unknown encoder rejection
	valid, err = ValidateCustom("123456", 0, secSha1, ValidateOpts{
		Digits:  otp.DigitsSix,
		Encoder: otp.Encoder("unknown"),
	})
	require.Error(t, err)
	require.False(t, valid)
}

func TestSteamCharValidation(t *testing.T) {
	secSteam := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate valid Steam codes and validate each character
	for counter := uint64(0); counter < 10; counter++ {
		code, err := GenerateCodeCustom(secSteam, counter, ValidateOpts{
			Digits:  otp.Digits(5),
			Encoder: otp.EncoderSteam,
		})
		require.NoError(t, err)
		require.Len(t, code, 5)

		// Verify each char is in Steam alphabet
		for _, c := range code {
			// Steam alphabet: 23456789BCDFGHJKMNPQRTVWXY
			validChar := c >= '2' && c <= '9' ||
				c == 'B' || c == 'C' || c == 'D' || c == 'F' ||
				c == 'G' || c == 'H' || c == 'J' || c == 'K' ||
				c == 'M' || c == 'N' || c == 'P' || c == 'Q' ||
				c == 'R' || c == 'T' || c == 'V' || c == 'W' ||
				c == 'X' || c == 'Y'
			require.True(t, validChar, "Character %c should be valid Steam char", c)
		}
	}
}

func TestGenerateCodeCustomAllEncoders(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Test default encoder
	codeDefault, err := GenerateCodeCustom(sec, 0, ValidateOpts{
		Digits:  otp.DigitsSix,
		Encoder: otp.EncoderDefault,
	})
	require.NoError(t, err)
	require.Len(t, codeDefault, 6)

	// Test empty encoder (same as default)
	codeEmpty, err := GenerateCodeCustom(sec, 0, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)
	require.Equal(t, codeDefault, codeEmpty)

	// Test Steam encoder
	codeSteam, err := GenerateCodeCustom(sec, 0, ValidateOpts{
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	require.NoError(t, err)
	require.Len(t, codeSteam, 5)

	// Test 8 digits with default encoder
	codeEight, err := GenerateCodeCustom(sec, 0, ValidateOpts{
		Digits: otp.DigitsEight,
	})
	require.NoError(t, err)
	require.Len(t, codeEight, 8)
}

func TestValidateCustomInvalidInputs(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Empty passcode
	valid, err := ValidateCustom("", 0, sec, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.Error(t, err)
	require.False(t, valid)

	// Wrong length
	valid, err = ValidateCustom("12345", 0, sec, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.Error(t, err)
	require.False(t, valid)

	// Too long
	valid, err = ValidateCustom("1234567", 0, sec, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.Error(t, err)
	require.False(t, valid)

	// Contains special characters
	valid, err = ValidateCustom("123!56", 0, sec, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.Error(t, err)
	require.False(t, valid)
}

func TestValidateCustomWindowMoreCases(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Test window=0 (exact match only)
	code0, err := GenerateCodeCustom(sec, 100, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)

	delta, found, err := ValidateCustomWindow(code0, 100, sec, ValidateOptsWithWindow{
		Digits: otp.DigitsSix,
		Window: 0,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 0, delta)

	// Code at different counter should not match with window=0
	code1, err := GenerateCodeCustom(sec, 101, ValidateOpts{
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)

	delta, found, err = ValidateCustomWindow(code1, 100, sec, ValidateOptsWithWindow{
		Digits: otp.DigitsSix,
		Window: 0,
	})
	require.NoError(t, err)
	require.False(t, found) // No match

	// Test window edge case: window=10 (max allowed)
	delta, found, err = ValidateCustomWindow(code1, 100, sec, ValidateOptsWithWindow{
		Digits: otp.DigitsSix,
		Window: 10,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 1, delta)
}
