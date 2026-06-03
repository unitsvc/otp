package totp

import (
	"encoding/base32"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// TestConcurrentGenerate verifies that concurrent TOTP code generation
// does not cause data races, panics, or corrupted output.
// 100 goroutines each generate 100 codes at different timestamps.
func TestConcurrentGenerate(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	const goroutines = 100
	const codesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			opts := ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			}
			for i := 0; i < codesPerGoroutine; i++ {
				// Use distinct timestamps per goroutine to exercise different counters.
				ts := time.Unix(int64(goroutineID*codesPerGoroutine+i)*30, 0).UTC()
				code, err := GenerateCodeCustom(secret, ts, opts)
				require.NoError(t, err, "goroutine %d, iteration %d", goroutineID, i)
				require.Len(t, code, 6, "goroutine %d, iteration %d", goroutineID, i)
			}
		}(g)
	}

	wg.Wait()
}

// TestConcurrentValidate verifies that concurrent TOTP validation
// does not cause data races, panics, or incorrect results.
// 100 goroutines each validate 100 codes.
func TestConcurrentValidate(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	const goroutines = 100
	const validationsPerGoroutine = 100

	// Pre-generate codes for distinct timestamps.
	type codeEntry struct {
		code string
		ts   time.Time
	}
	entries := make([]codeEntry, goroutines*validationsPerGoroutine)
	opts := ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	for i := range entries {
		ts := time.Unix(int64(i)*30, 0).UTC()
		code, err := GenerateCodeCustom(secret, ts, opts)
		require.NoError(t, err)
		entries[i] = codeEntry{code: code, ts: ts}
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < validationsPerGoroutine; i++ {
				idx := goroutineID*validationsPerGoroutine + i
				valid, err := ValidateCustom(entries[idx].code, secret, entries[idx].ts, opts)
				require.NoError(t, err, "goroutine %d, index %d", goroutineID, idx)
				require.True(t, valid, "goroutine %d, index %d: code should be valid", goroutineID, idx)
			}
		}(g)
	}

	wg.Wait()
}
