package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"testing/quick"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// commonSecret is a 20-byte secret (160 bits) that meets the minimum
// length requirement enforced by the underlying HOTP generation.
var commonSecret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

// validUnixSeconds constrains generated time values to a reasonable range
// that avoids negative Unix timestamps and far-future dates. testing/quick
// generates uint64 values which we map into a practical window.
func makeTime(unixSec uint64) time.Time {
	// Clamp to [0, 2^31-1] which covers 1970-01-01 through 2038-01-19.
	secs := unixSec % (1 << 31)
	return time.Unix(int64(secs), 0).UTC()
}

func TestPropertyGenerateDeterministic(t *testing.T) {
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code1, err1 := GenerateCodeCustom(commonSecret, t, opts)
		code2, err2 := GenerateCodeCustom(commonSecret, t, opts)
		if err1 != nil || err2 != nil {
			return false
		}
		return code1 == code2
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyGenerateLength(t *testing.T) {
	// Six-digit codes.
	f6 := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
		if err != nil {
			return false
		}
		return len(code) == otp.DigitsSix.Length()
	}
	err := quick.Check(f6, &quick.Config{MaxCount: 200})
	require.NoError(t, err)

	// Eight-digit codes.
	f8 := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
		if err != nil {
			return false
		}
		return len(code) == otp.DigitsEight.Length()
	}
	err = quick.Check(f8, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyValidateRoundTrip(t *testing.T) {
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
		if err != nil {
			return false
		}
		valid, err := ValidateCustom(code, commonSecret, t, opts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyDifferentTimesDifferentCodes(t *testing.T) {
	// Different time periods should produce different codes.
	f := func(a, b uint64) bool {
		ta := makeTime(a)
		tb := makeTime(b)
		// Ensure the two times are in different periods (at least 30s apart).
		if ta.Unix()/30 == tb.Unix()/30 {
			return true // same period, skip
		}
		opts := ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code1, err1 := GenerateCodeCustom(commonSecret, ta, opts)
		code2, err2 := GenerateCodeCustom(commonSecret, tb, opts)
		if err1 != nil || err2 != nil {
			return true // generation errors are not the property under test
		}
		return code1 != code2
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyCounterMonotonic(t *testing.T) {
	// Counter(period, t2) > Counter(period, t1) when t2 > t1 + period.
	f := func(unixSecA uint64, delta uint64) bool {
		ta := makeTime(unixSecA)
		// delta of at least 1 period (30s), plus the original offset.
		// We add 31..60 seconds to guarantee a full period has elapsed.
		offset := 31 + (delta % 30)
		tb := ta.Add(time.Duration(offset) * time.Second)

		ca := Counter(30, ta)
		cb := Counter(30, tb)
		return cb > ca
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyRemainingBounded(t *testing.T) {
	// 0 < Remaining(period, t) <= period*1000 for any t.
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		period := uint(30)
		r := Remaining(period, t)
		return r > 0 && r <= uint64(period)*1000
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyReplayProtection(t *testing.T) {
	// When AfterStep is set, the exact step that equals AfterStep should be rejected.
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
		if err != nil {
			return true
		}

		step := Counter(30, t)

		// Set AfterStep to the current step; the code should be rejected.
		replayOpts := ValidateOpts{
			Period:    30,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			AfterStep: step,
		}
		valid, _, err := ValidateCustomStep(code, commonSecret, t, replayOpts)
		if err != nil {
			return true
		}
		// With AfterStep == current step, the code must be rejected.
		return !valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyValidateRoundTripSHA256(t *testing.T) {
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA256}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
		if err != nil {
			return false
		}
		valid, err := ValidateCustom(code, commonSecret, t, opts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyValidateRoundTripSHA512(t *testing.T) {
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA512}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
		if err != nil {
			return false
		}
		valid, err := ValidateCustom(code, commonSecret, t, opts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyGenerateAllDigits(t *testing.T) {
	// Default encoder produces only ASCII digits [0-9].
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
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

func TestPropertySteamAlphabet(t *testing.T) {
	// Steam-encoded codes must contain only characters from the Steam alphabet.
	steamChars := "23456789BCDFGHJKMNPQRTVWXY"
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		opts := ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			Encoder:   otp.EncoderSteam,
		}
		code, err := GenerateCodeCustom(commonSecret, t, opts)
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

func TestPropertySkewAllowsAdjacentPeriod(t *testing.T) {
	// A code generated at time T should validate at time T-30s when Skew >= 1.
	f := func(unixSec uint64) bool {
		t := makeTime(unixSec)
		genOpts := ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		code, err := GenerateCodeCustom(commonSecret, t, genOpts)
		if err != nil {
			return false
		}

		// Validate from one period in the future.
		futureT := t.Add(30 * time.Second)
		valOpts := ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		valid, err := ValidateCustom(code, commonSecret, futureT, valOpts)
		if err != nil {
			return false
		}
		return valid
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

func TestPropertyRemainingReachesPeriod(t *testing.T) {
	// At the very start of a period (timestamp % period == 0),
	// Remaining should equal period*1000.
	period := uint(30)
	// Pick timestamps that are exact multiples of the period.
	f := func(mult uint64) bool {
		ts := int64(mult%100000) * int64(period)
		t := time.Unix(ts, 0).UTC()
		r := Remaining(period, t)
		return r == uint64(period)*1000
	}
	err := quick.Check(f, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}
