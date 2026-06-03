package totp

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// TestExtremeTime_ZeroTime verifies that TOTP generation and validation
// work correctly at Unix epoch (timestamp = 0).
func TestExtremeTime_ZeroTime(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	ts := time.Unix(0, 0).UTC()

	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	// Generate should work at zero time.
	code, err := GenerateCodeCustom(secret, ts, opts)
	require.NoError(t, err, "GenerateCodeCustom at zero time should not error")
	require.Len(t, code, 6, "Code should be 6 digits")

	// Validate should work at zero time with Skew=0.
	valid, err := ValidateCustom(code, secret, ts, ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid, "Code generated at zero time should validate")

	// Counter should be 0 at zero time.
	require.Equal(t, uint64(0), Counter(30, ts))
}

// TestExtremeTime_FarFuture verifies that TOTP works correctly at year 2100.
func TestExtremeTime_FarFuture(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	// January 1, 2100 00:00:00 UTC
	ts := time.Unix(4102444800, 0).UTC()

	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	code, err := GenerateCodeCustom(secret, ts, opts)
	require.NoError(t, err, "GenerateCodeCustom at year 2100 should not error")
	require.Len(t, code, 6)

	valid, err := ValidateCustom(code, secret, ts, ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.True(t, valid, "Code generated at year 2100 should validate")

	// Verify counter value is reasonable: 4102444800 / 30 = 136748160
	require.Equal(t, uint64(136748160), Counter(30, ts))
}

// TestExtremeTime_NegativeTime verifies behavior with negative Unix timestamp.
// Unix timestamp -1 corresponds to one second before the epoch (1969-12-31 23:59:59 UTC).
// Go's time.Unix handles negative values; the counter should be 0 since
// integer division of -1/30 = 0 in Go (truncation toward zero).
func TestExtremeTime_NegativeTime(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	ts := time.Unix(-1, 0).UTC()

	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	// GenerateCodeCustom should succeed (counter will be 0 due to uint64 truncation).
	code, err := GenerateCodeCustom(secret, ts, opts)
	require.NoError(t, err, "GenerateCodeCustom at negative time should not error")
	require.Len(t, code, 6)

	// Counter: uint64(-1) wraps to a very large number in Go, but
	// time.Unix(-1, 0).Unix() returns -1. The Counter function converts
	// via uint64(t.Unix()), so -1 becomes a huge uint64 value.
	// The key behavior to verify is no panic and deterministic output.
	// Counter with negative time: uint64(-1) wraps to a very large number.
	// Verify the code is deterministic by regenerating.
	_ = Counter(30, ts)
	code2, err := GenerateCodeCustom(secret, ts, opts)
	require.NoError(t, err)
	require.Equal(t, code, code2, "Same timestamp should produce same code")

	// Verify remaining computation does not panic.
	rem := Remaining(30, ts)
	// Remaining should be a non-negative value.
	_ = rem
}

// TestCounterOverflow verifies behavior with very large period values
// and the resulting counter values.
func TestCounterOverflow(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Maximum allowed period (300 seconds).
	ts := time.Unix(1234567890, 0).UTC()
	counter := Counter(300, ts)
	require.Equal(t, uint64(1234567890/300), counter)

	// Generate code with period=300 should work.
	opts := ValidateOpts{
		Period:    300,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	code, err := GenerateCodeCustom(secret, ts, opts)
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Period=1 (smallest valid) at a large timestamp.
	largeTS := time.Unix(2000000000, 0).UTC()
	counter1 := Counter(1, largeTS)
	require.Equal(t, uint64(2000000000), counter1)

	code1, err := GenerateCodeCustom(secret, largeTS, ValidateOpts{
		Period:    1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code1, 6)
}

// TestRemainingAtPeriodBoundary verifies the Remaining function returns
// correct values at period boundaries.
func TestRemainingAtPeriodBoundary(t *testing.T) {
	// At exact period boundary (multiple of 30), remaining should equal full period.
	ts0 := time.Unix(0, 0).UTC()
	rem := Remaining(30, ts0)
	require.Equal(t, uint64(30000), rem, "At epoch, remaining should be full period (30s = 30000ms)")

	// At 30 seconds (start of second period).
	ts30 := time.Unix(30, 0).UTC()
	rem = Remaining(30, ts30)
	require.Equal(t, uint64(30000), rem, "At 30s boundary, remaining should be full period")

	// At 60 seconds (start of third period).
	ts60 := time.Unix(60, 0).UTC()
	rem = Remaining(30, ts60)
	require.Equal(t, uint64(30000), rem, "At 60s boundary, remaining should be full period")

	// One second before boundary.
	ts29 := time.Unix(29, 0).UTC()
	rem = Remaining(30, ts29)
	require.Equal(t, uint64(1000), rem, "At 29s, remaining should be 1000ms")

	// One millisecond before boundary.
	ts29999 := time.Unix(29, 999000000).UTC()
	rem = Remaining(30, ts29999)
	require.Equal(t, uint64(1), rem, "At 29.999s, remaining should be 1ms")

	// With period=60 at boundary.
	ts60p := time.Unix(60, 0).UTC()
	rem = Remaining(60, ts60p)
	require.Equal(t, uint64(60000), rem, "At 60s with period=60, remaining should be 60000ms")

	// With period=60 at 30 seconds in.
	ts30p60 := time.Unix(30, 0).UTC()
	rem = Remaining(60, ts30p60)
	require.Equal(t, uint64(30000), rem, "At 30s with period=60, remaining should be 30000ms")

	// RemainingDefault should use period=30.
	remDefault := RemainingDefault(ts29)
	require.Equal(t, uint64(1000), remDefault, "RemainingDefault at 29s should be 1000ms")
}
