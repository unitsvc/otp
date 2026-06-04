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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"

	"encoding/base32"
	"io"
	"math"
	"testing"
	"time"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   otp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "46119246", otp.AlgorithmSHA256, secSha256},
		{59, "90693936", otp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", otp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", otp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", otp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", otp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", otp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", otp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", otp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", otp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", otp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", otp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", otp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", otp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", otp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", otp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", otp.AlgorithmSHA512, secSha512},
	}
)

// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
// NOTE -- the test vectors are documented as having the SAME
// secret -- this is WRONG -- they have a variable secret
// depending upon the hmac algorithm:
//
//	http://www.rfc-editor.org/errata_search.php?rfc=6238
//
// this only took a few hours of head/desk interaction to figure out.
func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, tx.TOTP, passcode)
	}
}

func TestValidateSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tc{
		{29, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{61, "94287082", otp.AlgorithmSHA1, secSha1},
	}

	for _, tx := range tests {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "generate basic TOTP")
	require.Equal(t, "SnakeOil", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@example.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

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
	require.NoError(t, err, "generate larger TOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  17, // valid (>=16), not divisible by 5
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
	require.NoError(t, err, "Secret wa not valid base32")
	require.Equal(t, sec, []byte("helloworld"), "Specified Secret was not kept")
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", sec)

	n := time.Now().UTC()
	code, err := GenerateCode(w.Secret(), n)
	require.NoError(t, err)

	valid := Validate(code, w.Secret())
	require.True(t, valid)
}

func TestSteamSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/username%20steam:username?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&period=30&digits=5&issuer=username%20steam&encoder=steam`)
	require.NoError(t, err)
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", w.Secret())
	require.Equal(t, otp.EncoderSteam, w.Encoder())
	require.Equal(t, 5, w.Digits().Length())

	n := time.Now().UTC()
	opts := ValidateOpts{
		Period:  uint(w.Period()),
		Digits:  w.Digits(),
		Encoder: w.Encoder(),
	}
	code, err := GenerateCodeCustom(w.Secret(), n, opts)
	require.NoError(t, err)

	require.Len(t, code, w.Digits().Length())

	valid, err := ValidateCustom(code, w.Secret(), n, opts)
	require.NoError(t, err)
	require.True(t, valid)
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

func TestValidateStep(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	n := time.Now().UTC()

	code, err := GenerateCodeCustom(secSha1, n, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	valid, step, err := ValidateCustomStep(code, secSha1, n, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(n.Unix())/30, step)
}

func TestValidateStepInvalid(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	n := time.Now().UTC()

	valid, step, err := ValidateCustomStep("000000", secSha1, n, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.False(t, valid)
	require.Equal(t, uint64(0), step)
}

func TestValidateCustomStepUnderflow(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Test at unix epoch boundary (counter = 0) with Skew > 0
	// Should not panic or produce incorrect results
	valid, _, err := ValidateCustomStep("000000", secSha1, time.Unix(0, 0).UTC(), ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.False(t, valid)
}

func TestValidateStepSimple(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	code, err := GenerateCode(secSha1, time.Now().UTC())
	require.NoError(t, err)
	require.NotEmpty(t, code)

	valid, step := ValidateStep(code, secSha1)
	require.True(t, valid)
	require.Greater(t, step, uint64(0))
}

func TestGenerateWithCustomRand(t *testing.T) {
	// Test with a custom Rand reader
	k, err := Generate(GenerateOpts{
		Issuer:      "TestOrg",
		AccountName: "user@example.com",
		Rand:        customReader{},
	})
	require.NoError(t, err)
	require.Equal(t, "TestOrg", k.Issuer())
}

func TestGenerateWithCustomRandError(t *testing.T) {
	// Test that error from Rand reader is propagated
	_, err := Generate(GenerateOpts{
		Issuer:      "TestOrg",
		AccountName: "user@example.com",
		Rand:        errorReader{},
	})
	require.Error(t, err)
}

func TestGenerateDefaultPeriod(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "TestOrg",
		AccountName: "user@example.com",
	})
	require.NoError(t, err)
	require.Equal(t, uint64(30), k.Period())
}

func TestGenerateCustomPeriod(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "TestOrg",
		AccountName: "user@example.com",
		Period:      60,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(60), k.Period())
}

func TestGenerateMissingIssuer(t *testing.T) {
	_, err := Generate(GenerateOpts{
		AccountName: "user@example.com",
	})
	require.Equal(t, otp.ErrGenerateMissingIssuer, err)
}

func TestGenerateMissingAccountName(t *testing.T) {
	_, err := Generate(GenerateOpts{
		Issuer: "TestOrg",
	})
	require.Equal(t, otp.ErrGenerateMissingAccountName, err)
}

func TestGenerateWithCustomRandSecret(t *testing.T) {
	// Test with a custom secret provided
	k, err := Generate(GenerateOpts{
		Issuer:      "TestOrg",
		AccountName: "user@example.com",
		Secret:      []byte("mysecret"),
	})
	require.NoError(t, err)
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err)
	require.Equal(t, []byte("mysecret"), sec)
}

func TestValidateCustomStepSkewZero(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	// Generate code at ts=59 (counter=1)
	code, err := GenerateCodeCustom(sec, time.Unix(59, 0).UTC(), ValidateOpts{
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	// At Skew=0, code should validate at exact time
	valid, step, err := ValidateCustomStep(code, sec, time.Unix(59, 0).UTC(), ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)

	// At Skew=0, code should NOT validate at adjacent period (ts=90, counter=3)
	valid, _, err = ValidateCustomStep(code, sec, time.Unix(90, 0).UTC(), ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.False(t, valid)
}

// Custom reader that returns zero bytes
type customReader struct{}

func (customReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

// Error reader that always fails
type errorReader struct{}

func (errorReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// ===== Counter and Remaining Tests =====

func TestCounter(t *testing.T) {
	// Test at timestamp=1451606400 (2016-01-01 00:00:00 UTC)
	ts := time.Unix(1451606400, 0).UTC()

	// With period=30, counter = 1451606400 / 30 = 48386880
	counter := Counter(30, ts)
	require.Equal(t, uint64(48386880), counter)

	// With period=60, counter = 1451606400 / 60 = 24193440
	counter = Counter(60, ts)
	require.Equal(t, uint64(24193440), counter)
}

func TestCounterDefault(t *testing.T) {
	ts := time.Now().UTC()
	counter := Counter(0, ts) // Should use default period=30
	require.Equal(t, uint64(ts.Unix())/30, counter)
}

func TestRemaining(t *testing.T) {
	// Test at timestamp=1451606415 (15 seconds into period)
	ts := time.Unix(1451606415, 0).UTC()
	rem := Remaining(30, ts)
	require.Equal(t, uint64(15000), rem) // 15 seconds = 15000 ms remaining

	// Test at timestamp=1451606429 (29 seconds into period)
	ts2 := time.Unix(1451606429, 0).UTC()
	rem = Remaining(30, ts2)
	require.Equal(t, uint64(1000), rem) // 1 second remaining

	// Test at timestamp=1451606430 (exact boundary, start of new period)
	// At exactly period boundary, remaining should be full period (30000ms)
	ts3 := time.Unix(1451606430, 0).UTC()
	rem = Remaining(30, ts3)
	require.Equal(t, uint64(30000), rem) // At boundary, full period remaining
}

func TestRemainingDefault(t *testing.T) {
	ts := time.Now().UTC()
	rem := RemainingDefault(ts)
	// Should be <= 30000 (max for 30 second period)
	require.LessOrEqual(t, rem, uint64(30000))
	require.Greater(t, rem, uint64(0))
}

func TestRemainingCustomPeriod(t *testing.T) {
	// Test with 60-second period
	ts := time.Unix(1451606415, 0).UTC() // 15 seconds into minute
	rem := Remaining(60, ts)
	require.Equal(t, uint64(45000), rem) // 45 seconds remaining
}

func TestCounterBoundary(t *testing.T) {
	// Test at exact period boundaries
	period := uint(30)

	// At 0 seconds (epoch), counter=0
	ts0 := time.Unix(0, 0).UTC()
	require.Equal(t, uint64(0), Counter(period, ts0))

	// At 29 seconds, counter=0 (still in first period)
	ts29 := time.Unix(29, 0).UTC()
	require.Equal(t, uint64(0), Counter(period, ts29))

	// At 30 seconds, counter=1 (second period)
	ts30 := time.Unix(30, 0).UTC()
	require.Equal(t, uint64(1), Counter(period, ts30))

	// At 59 seconds, counter=1 (still in second period)
	ts59 := time.Unix(59, 0).UTC()
	require.Equal(t, uint64(1), Counter(period, ts59))

	// At 60 seconds, counter=2
	ts60 := time.Unix(60, 0).UTC()
	require.Equal(t, uint64(2), Counter(period, ts60))
}

// ===== TOTP Secure Functions Tests =====

func TestValidateSecure(t *testing.T) {
	// SHA256 secret (32 bytes for SHA256)
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	n := time.Now().UTC()

	// Generate code using SHA256
	code, err := GenerateCodeSecure(secSha256, n)
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Validate using SHA256
	valid := ValidateSecure(code, secSha256)
	require.True(t, valid)

	// Validate using default (SHA1) should fail
	valid = Validate(code, secSha256)
	require.False(t, valid)
}

func TestGenerateCodeSecure(t *testing.T) {
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	n := time.Now().UTC()

	code, err := GenerateCodeSecure(secSha256, n)
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Verify it's using SHA256 by comparing with GenerateCodeCustom
	codeCustom, err := GenerateCodeCustom(secSha256, n, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	require.NoError(t, err)
	require.Equal(t, code, codeCustom)
}

// ===== SkewPolicy Tests =====

func TestValidateCustomSkewPolicy(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Generate code at timestamp 59 (counter=1)
	ts := time.Unix(59, 0).UTC()
	code, err := GenerateCode(sec, ts)
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Test 1: Past-only tolerance (RFC recommended)
	// At ts=59 (counter=1), code should validate with Past=1
	valid, step, delta, err := ValidateCustomSkewPolicy(code, sec, ts, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)
	require.Equal(t, 0, delta) // Exact match

	// Test 2: Future code should be rejected with Future=0
	futureTs := time.Unix(90, 0).UTC() // counter=3
	futureCode, err := GenerateCode(sec, futureTs)
	require.NoError(t, err)

	valid, _, _, err = ValidateCustomSkewPolicy(futureCode, sec, ts, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.False(t, valid) // Future code rejected

	// Test 3: Past code should be accepted with Past=1
	pastTs := time.Unix(30, 0).UTC()    // counter=1, but we validate at counter=2
	currentTs := time.Unix(60, 0).UTC() // counter=2
	pastCode, err := GenerateCode(sec, pastTs)
	require.NoError(t, err)

	valid, step, delta, err = ValidateCustomSkewPolicy(pastCode, sec, currentTs, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step) // Matched at counter=1
	require.Equal(t, -1, delta)       // Past by 1

	// Test 4: Symmetric tolerance (equivalent to Skew: 1)
	valid, _, _, err = ValidateCustomSkewPolicy(code, sec, ts, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 1},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateRFCCompliant(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	ts := time.Unix(59, 0).UTC()
	code, err := GenerateCode(sec, ts)
	require.NoError(t, err)

	// RFC compliant should accept past codes
	valid, step, err := ValidateRFCCompliant(code, sec, ts)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)

	// RFC compliant should reject future codes
	futureTs := time.Unix(90, 0).UTC()
	futureCode, err := GenerateCode(sec, futureTs)
	require.NoError(t, err)

	valid, _, err = ValidateRFCCompliant(futureCode, sec, ts)
	require.NoError(t, err)
	require.False(t, valid)
}

// ===== Coverage Improvement Tests =====

func TestGenerateCodeCustomAllOptions(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	ts := time.Now().UTC()

	// Test default encoder
	codeDefault, err := GenerateCodeCustom(sec, ts, ValidateOpts{
		Period:  30,
		Digits:  otp.DigitsSix,
		Encoder: otp.EncoderDefault,
	})
	require.NoError(t, err)
	require.Len(t, codeDefault, 6)

	// Test Steam encoder
	secSteam := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	codeSteam, err := GenerateCodeCustom(secSteam, ts, ValidateOpts{
		Period:  30,
		Digits:  otp.Digits(5),
		Encoder: otp.EncoderSteam,
	})
	require.NoError(t, err)
	require.Len(t, codeSteam, 5)

	// Test custom period
	codeCustomPeriod, err := GenerateCodeCustom(sec, ts, ValidateOpts{
		Period: 60,
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)
	require.Len(t, codeCustomPeriod, 6)

	// Test 8 digits
	codeEight, err := GenerateCodeCustom(sec, ts, ValidateOpts{
		Period: 30,
		Digits: otp.DigitsEight,
	})
	require.NoError(t, err)
	require.Len(t, codeEight, 8)

	// Test SHA256
	secSha256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	codeSha256, err := GenerateCodeCustom(secSha256, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	require.NoError(t, err)
	require.Len(t, codeSha256, 6)
}

func TestRemainingAllCases(t *testing.T) {
	// Test at various timestamps
	testCases := []struct {
		period   uint
		ts       time.Time
		expected uint64
	}{
		{30, time.Unix(15, 0).UTC(), 15000}, // 15 seconds into period
		{30, time.Unix(29, 0).UTC(), 1000},  // 29 seconds into period
		{30, time.Unix(0, 0).UTC(), 30000},  // At epoch
		{60, time.Unix(30, 0).UTC(), 30000}, // 30 seconds into 60s period
		{15, time.Unix(10, 0).UTC(), 5000},  // 10 seconds into 15s period
	}

	for _, tc := range testCases {
		remaining := Remaining(tc.period, tc.ts)
		require.Equal(t, tc.expected, remaining, "Period=%d, Ts=%d", tc.period, tc.ts.Unix())
	}
}

func TestValidateCustomSkewPolicyAllCases(t *testing.T) {
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Test case 1: Exact match (delta=0)
	ts := time.Unix(59, 0).UTC() // counter=1
	code, err := GenerateCode(sec, ts)
	require.NoError(t, err)

	valid, step, delta, err := ValidateCustomSkewPolicy(code, sec, ts, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 1},
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)
	require.Equal(t, 0, delta)

	// Test case 2: Past match (delta=-1)
	currentTs := time.Unix(90, 0).UTC() // counter=3
	pastTs := time.Unix(59, 0).UTC()    // counter=1
	pastCode, err := GenerateCode(sec, pastTs)
	require.NoError(t, err)

	valid, step, delta, err = ValidateCustomSkewPolicy(pastCode, sec, currentTs, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 2, Future: 0},
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)
	require.Equal(t, -2, delta) // 2 periods in the past

	// Test case 3: Future match (delta=+1)
	currentTs2 := time.Unix(30, 0).UTC() // counter=1
	futureTs := time.Unix(60, 0).UTC()   // counter=2
	futureCode, err := GenerateCode(sec, futureTs)
	require.NoError(t, err)

	valid, step, delta, err = ValidateCustomSkewPolicy(futureCode, sec, currentTs2, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 0, Future: 1},
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(2), step)
	require.Equal(t, 1, delta) // 1 period in the future

	// Test case 4: No match - outside skew range
	veryPastTs := time.Unix(0, 0).UTC() // counter=0
	veryPastCode, err := GenerateCode(sec, veryPastTs)
	require.NoError(t, err)

	valid, _, _, err = ValidateCustomSkewPolicy(veryPastCode, sec, time.Unix(90, 0).UTC(), ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0}, // Only 1 period past tolerance
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.False(t, valid) // counter=0 is 3 periods away from counter=3

	// Test case 5: Past=0, Future=0 (exact match only)
	codeExact, err := GenerateCode(sec, time.Unix(30, 0).UTC())
	require.NoError(t, err)

	valid, step, delta, err = ValidateCustomSkewPolicy(codeExact, sec, time.Unix(30, 0).UTC(), ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 0, Future: 0},
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), step)
	require.Equal(t, 0, delta)

	// Same code at adjacent time should fail
	valid, _, _, err = ValidateCustomSkewPolicy(codeExact, sec, time.Unix(60, 0).UTC(), ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 0, Future: 0},
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.False(t, valid)
}

// ===== ValidateCustomResult tests =====

func TestValidateCustomResult(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Unix(60, 0).UTC() // counter = 2

	code, err := GenerateCode(sec, now)
	require.NoError(t, err)

	// Exact match: Delta should be 0
	result, err := ValidateCustomResult(code, sec, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Valid)
	require.Equal(t, uint64(2), result.Step)
	require.Equal(t, 0, result.Delta)

	// Past match: Delta should be negative
	pastCode, err := GenerateCode(sec, time.Unix(30, 0).UTC())
	require.NoError(t, err)
	result2, err := ValidateCustomResult(pastCode, sec, now, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, result2.Valid)
	require.Equal(t, int(-1), result2.Delta)

	// Invalid code
	result3, err := ValidateCustomResult("000000", sec, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.False(t, result3.Valid)

	// Error path: bad secret causes error
	result4, err := ValidateCustomResult("000000", "SHORT", now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Nil(t, result4)
}

// ===== CounterWithT0 edge cases =====

func TestCounterWithT0Overflow(t *testing.T) {
	now := time.Unix(1704067200, 0).UTC()

	// Normal negative T0: counter should be larger than Counter()
	normal := Counter(30, now)
	withNegT0 := CounterWithT0(30, -1000, now)
	require.Greater(t, withNegT0, normal, "negative T0 should produce larger counter")

	// Extreme negative T0 (MinInt64): should not panic, should clamp
	withMinT0 := CounterWithT0(30, math.MinInt64, now)
	require.Greater(t, withMinT0, uint64(0), "MinInt64 T0 should not produce 0 counter")

	// Future T0 (positive, larger than timestamp): ts < 0 => counter = 0
	withFutureT0 := CounterWithT0(30, math.MaxInt64, now)
	require.Equal(t, uint64(0), withFutureT0, "future T0 should produce counter 0")

	// Period 0 defaults to 30
	withPeriod0 := CounterWithT0(0, 0, now)
	require.Equal(t, Counter(30, now), withPeriod0)
}

// ===== RemainingWithT0 edge cases =====

func TestRemainingWithT0NegativeElapsed(t *testing.T) {
	now := time.Unix(1704067200, 0).UTC()

	// T0 far in the future: t0*1000 overflows, but elapsedMs < 0 => clamped to 0 => remaining = full period
	// Use a large but non-overflowing T0 to test the negative elapsed path
	remaining := RemainingWithT0(30, now.Unix()+100, now)
	require.Equal(t, uint64(30000), remaining, "future T0 should give full period remaining")

	// Normal T0=0: should equal Remaining()
	require.Equal(t, Remaining(30, now), RemainingWithT0(30, 0, now))

	// Period 0 defaults to 30
	require.Equal(t, Remaining(30, now), RemainingWithT0(0, 0, now))
}

// ===== ValidateCustomResult error paths =====

func TestValidateCustomResultErrorPath(t *testing.T) {
	// Bad secret (too short) triggers error from GenerateCodeCustom inside ValidateCustomStep
	result, err := ValidateCustomResult("000000", "SHORT", time.Now().UTC(), ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.Error(t, err)
	require.Nil(t, result)
}

// ===== ValidateCustomSkewPolicy error paths =====

func TestValidateCustomSkewPolicyWindowTooLarge(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Now().UTC()
	_, _, _, err := ValidateCustomSkewPolicy("000000", sec, now, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 11},
		Digits:     otp.DigitsSix,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrWindowTooLarge, err)
}

func TestValidateCustomSkewPolicyFutureTooLarge(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Now().UTC()
	_, _, _, err := ValidateCustomSkewPolicy("000000", sec, now, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Future: 11},
		Digits:     otp.DigitsSix,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrWindowTooLarge, err)
}

func TestValidateCustomSkewPolicyInvalidSecret(t *testing.T) {
	now := time.Now().UTC()
	_, _, _, err := ValidateCustomSkewPolicy("000000", "SHORT", now, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1},
		Digits:     otp.DigitsSix,
	})
	require.Error(t, err)
}

func TestValidateCustomSkewPolicyErrorInPastCheck(t *testing.T) {
	now := time.Now().UTC()
	// Invalid secret triggers error in past step check
	_, _, _, err := ValidateCustomSkewPolicy("000000", "SHORT", now, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
	})
	require.Error(t, err)
}

func TestValidateCustomSkewPolicyErrorInFutureCheck(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Now().UTC()
	// Generate code and use SkewPolicy with Future=1, no match => exercises future check loop
	code, _ := GenerateCode(sec, now)
	valid, _, _, err := ValidateCustomSkewPolicy(code, sec, now, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 0, Future: 1},
		Digits:     otp.DigitsSix,
	})
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateCustomResultWithSkew(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	ts := time.Unix(60, 0).UTC()
	pastCode, _ := GenerateCode(sec, time.Unix(30, 0).UTC())

	result, err := ValidateCustomResult(pastCode, sec, ts, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		T0:        0,
	})
	require.NoError(t, err)
	require.True(t, result.Valid)
	require.Equal(t, int(-1), result.Delta)
	require.Equal(t, uint64(1), result.Step)
}

func TestValidateCustomResultWithT0(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	t0 := int64(100)
	ts := time.Unix(60, 0).UTC()

	code, err := GenerateCodeCustom(sec, ts, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		T0:        t0,
	})
	require.NoError(t, err)

	result, err := ValidateCustomResult(code, sec, ts, ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		T0:        t0,
	})
	require.NoError(t, err)
	require.True(t, result.Valid)
	require.Equal(t, 0, result.Delta)
}

// ===== Zero-value opts to trigger default paths =====

func TestValidateCustomResultZeroOpts(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	ts := time.Unix(60, 0).UTC()

	code, err := GenerateCode(sec, ts) // uses defaults
	require.NoError(t, err)

	// Zero-value ValidateOpts triggers Period/Digits/Algorithm defaults
	result, err := ValidateCustomResult(code, sec, ts, ValidateOpts{})
	require.NoError(t, err)
	require.True(t, result.Valid)
	require.Equal(t, 0, result.Delta)
}

func TestValidateCustomSkewPolicyZeroOpts(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	ts := time.Unix(60, 0).UTC()

	code, err := GenerateCode(sec, ts)
	require.NoError(t, err)

	// Zero-value opts triggers default paths (Period, Digits, Algorithm)
	valid, step, delta, err := ValidateCustomSkewPolicy(code, sec, ts, ValidateOptsWithSkewPolicy{})
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(2), step)
	require.Equal(t, 0, delta)
}

func TestValidateCustomStepSkewTooLarge(t *testing.T) {
	sec := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	_, _, err := ValidateCustomStep("000000", sec, time.Now().UTC(), ValidateOpts{
		Skew: 11,
	})
	require.Error(t, err)
	require.Equal(t, otp.ErrWindowTooLarge, err)
}

func TestGenerateZeroOpts(t *testing.T) {
	// Zero-value GenerateOpts triggers SecretSize/Digits/Rand defaults
	key, err := Generate(GenerateOpts{
		Issuer:      "Test",
		AccountName: "user@test.com",
	})
	require.NoError(t, err)
	require.NotEmpty(t, key.Secret())
	require.Equal(t, otp.DigitsSix, key.Digits())
}
