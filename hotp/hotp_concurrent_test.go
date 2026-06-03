package hotp

import (
	"encoding/base32"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unitsvc/otp"
)

// TestConcurrentGenerate verifies that concurrent HOTP code generation
// does not cause data races, panics, or corrupted output.
// 100 goroutines each generate 100 codes across different counters.
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
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			}
			for i := 0; i < codesPerGoroutine; i++ {
				counter := uint64(goroutineID*codesPerGoroutine + i)
				code, err := GenerateCodeCustom(secret, counter, opts)
				require.NoError(t, err, "goroutine %d, counter %d", goroutineID, counter)
				require.Len(t, code, 6, "goroutine %d, counter %d", goroutineID, counter)
			}
		}(g)
	}

	wg.Wait()
}

// TestConcurrentValidate verifies that concurrent HOTP validation
// does not cause data races, panics, or incorrect results.
// 100 goroutines each validate 100 codes.
func TestConcurrentValidate(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	const goroutines = 100
	const validationsPerGoroutine = 100

	// Pre-generate codes for each counter.
	codes := make([]string, goroutines*validationsPerGoroutine)
	opts := ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	for i := range codes {
		code, err := GenerateCodeCustom(secret, uint64(i), opts)
		require.NoError(t, err)
		codes[i] = code
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < validationsPerGoroutine; i++ {
				idx := goroutineID*validationsPerGoroutine + i
				valid, err := ValidateCustom(codes[idx], uint64(idx), secret, opts)
				require.NoError(t, err, "goroutine %d, index %d", goroutineID, idx)
				require.True(t, valid, "goroutine %d, index %d: code should be valid", goroutineID, idx)
			}
		}(g)
	}

	wg.Wait()
}
