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
	"io"

	"github.com/unitsvc/otp"
	"github.com/unitsvc/otp/hotp"
	"github.com/unitsvc/otp/internal"

	"crypto/rand"
	"encoding/base32"
	"net/url"
	"strconv"
	"time"
)

// ErrInvalidImageURL indicates the image URL is not a valid HTTPS URL.
// Deprecated: Use otp.ErrInvalidImageURL instead.
var ErrInvalidImageURL = otp.ErrInvalidImageURL

// Validate a TOTP using the current time.
// A shortcut for ValidateCustom, Validate uses a configuration
// that is compatible with Google-Authenticator and most clients.
func Validate(passcode string, secret string) bool {
	rv, _ := ValidateCustom(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return rv
}

// GenerateCode creates a TOTP token using the current time.
// A shortcut for GenerateCodeCustom, GenerateCode uses a configuration
// that is compatible with Google-Authenticator and most clients.
func GenerateCode(secret string, t time.Time) (string, error) {
	return GenerateCodeCustom(secret, t, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// ValidateSecure validates a TOTP using SHA256 (security recommended).
// Use this for new deployments where all clients support SHA256.
// For maximum compatibility with all authenticator apps, use Validate instead.
func ValidateSecure(passcode string, secret string) bool {
	rv, _ := ValidateCustom(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
		},
	)
	return rv
}

// GenerateCodeSecure generates a TOTP token using SHA256 (security recommended).
// Use this for new deployments where all clients support SHA256.
// For maximum compatibility with all authenticator apps, use GenerateCode instead.
func GenerateCodeSecure(secret string, t time.Time) (string, error) {
	return GenerateCodeCustom(secret, t, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
}

// ValidateOpts provides options for ValidateCustom().
type ValidateOpts struct {
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Periods before or after the current time to allow.  Value of 1 allows up to Period
	// of either side of the specified time.  The zero value (0) allows no skew, meaning
	// only the exact current time window is validated.  Note: Validate() uses Skew: 1
	// by default.  Values greater than 1 are likely sketchy.
	Skew uint
	// Digits as part of the input. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Encoder to use for output code.
	Encoder otp.Encoder
	// AfterStep is the last successfully validated time step for replay protection.
	// If set (non-zero), any time step <= AfterStep is rejected.
	// Zero value means no replay protection (default).
	// Use this to prevent reuse of previously validated codes within the same period.
	AfterStep uint64
}

// SkewPolicy defines asymmetric tolerance for time-based validation.
// This allows fine-grained control over how many periods in the past
// and future are accepted during validation.
//
// RFC 6238 Section 5.2 recommends validating against past periods only
// (not future) for better security. Use SkewPolicy{Past: 1, Future: 0}
// for RFC-compliant behavior.
//
// The default symmetric Skew in ValidateOpts is equivalent to:
// SkewPolicy{Past: Skew, Future: Skew}
type SkewPolicy struct {
	// Past is the number of periods before the current time to accept.
	// RFC 6238 recommends allowing at least one past period for clock drift.
	Past uint
	// Future is the number of periods after the current time to accept.
	// Setting this to 0 is more secure (prevents future code acceptance).
	Future uint
}

// ValidateOptsWithSkewPolicy provides options for asymmetric time window validation.
type ValidateOptsWithSkewPolicy struct {
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Asymmetric skew policy for past/future period tolerance.
	SkewPolicy SkewPolicy
	// Digits as part of the input. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Encoder to use for output code.
	Encoder otp.Encoder
}

// GenerateCodeCustom takes a timepoint and produces a passcode using a
// secret and the provided opts. (Under the hood, this is making an adapted
// call to hotp.GenerateCodeCustom)
func GenerateCodeCustom(secret string, t time.Time, opts ValidateOpts) (passcode string, err error) {
	// Set default values (Go convention: make zero value useful)
	if opts.Period == 0 {
		opts.Period = 30
	}
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1 // Explicit default for clarity
	}

	// Security guardrails per RFC 6238
	if opts.Period < 1 || opts.Period > 300 {
		return "", otp.ErrPeriodOutOfRange
	}

	counter := Counter(opts.Period, t)
	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
		Encoder:   opts.Encoder,
	})
	if err != nil {
		return "", err
	}
	return passcode, nil
}

// Counter calculates the time step counter for a given timestamp.
// This is the number of time periods that have elapsed since Unix epoch.
// counter = floor(timestamp_seconds / period)
func Counter(period uint, t time.Time) uint64 {
	if period == 0 {
		period = 30
	}
	return uint64(t.Unix()) / uint64(period)
}

// Remaining returns the remaining time in milliseconds until the next TOTP
// is generated. This is useful for displaying countdown timers in UI.
//
// For example, with period=30 and timestamp at 15 seconds into the period,
// Remaining returns 15000 (15 seconds remaining).
func Remaining(period uint, t time.Time) uint64 {
	if period == 0 {
		period = 30
	}
	periodMs := uint64(period) * 1000
	timestampMs := uint64(t.UnixMilli())
	return periodMs - (timestampMs % periodMs)
}

// RemainingDefault returns remaining time with default period (30 seconds).
func RemainingDefault(t time.Time) uint64 {
	return Remaining(30, t)
}

// ValidateCustom validates a TOTP given a user specified time and custom options.
// Most users should use Validate() to provide an interpolatable TOTP experience.
func ValidateCustom(passcode string, secret string, t time.Time, opts ValidateOpts) (bool, error) {
	valid, _, err := ValidateCustomStep(passcode, secret, t, opts)
	return valid, err
}

// ValidateStep validates a TOTP using the current time and returns the
// time step used for validation. This is similar to Validate, but returns
// the step value which can be used to prevent replay attacks by recording
// which steps have already been used.
func ValidateStep(passcode string, secret string) (bool, uint64) {
	valid, step, _ := ValidateCustomStep(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return valid, step
}

// ValidateCustomStep validates a TOTP given a user specified time and custom
// options, returning the time step used for validation. The step can be used
// to prevent replay attacks by recording which steps have already been used
// and rejecting codes from previously-used steps.
func ValidateCustomStep(passcode string, secret string, t time.Time, opts ValidateOpts) (bool, uint64, error) {
	// Set default values (consistent with GenerateCodeCustom)
	if opts.Period == 0 {
		opts.Period = 30
	}
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1
	}

	// Security guardrail: limit Skew to prevent DoS (matches HOTP Window cap)
	if opts.Skew > 10 {
		return false, 0, otp.ErrWindowTooLarge
	}

	// Pre-allocate steps slice: 1 (current) + 2*Skew (past + future for each skew level)
	maxSteps := 1 + 2*opts.Skew
	steps := make([]uint64, 0, maxSteps)
	step := Counter(opts.Period, t)

	steps = append(steps, step)
	for i := uint64(1); i <= uint64(opts.Skew); i++ {
		steps = append(steps, step+i)
		if step >= i {
			steps = append(steps, step-i)
		}
	}

	for _, currentStep := range steps {
		// Replay protection: reject steps at or before the last used step
		if opts.AfterStep > 0 && currentStep <= opts.AfterStep {
			continue
		}

		rv, err := hotp.ValidateCustom(passcode, currentStep, secret, hotp.ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
			Encoder:   opts.Encoder,
		})
		if err != nil {
			return false, 0, err
		}

		if rv {
			return true, currentStep, nil
		}
	}

	return false, 0, nil
}

// ValidateCustomSkewPolicy validates a TOTP with asymmetric time window tolerance.
// This provides fine-grained control over past and future period acceptance.
//
// RFC 6238 Section 5.2 recommends:
// "We RECOMMEND a default time-step size of 30 seconds. We also RECOMMEND
// allowing a validation window of one time step before and after the current
// time step."
//
// For RFC-compliant behavior (past only):
//
//	SkewPolicy{Past: 1, Future: 0}
//
// For symmetric tolerance (equivalent to Skew: 1):
//
//	SkewPolicy{Past: 1, Future: 1}
//
// Returns:
// - valid: whether the passcode was accepted
// - step: the time step that matched (for replay prevention)
// - delta: offset from expected step (0=exact, negative=past, positive=future)
func ValidateCustomSkewPolicy(passcode string, secret string, t time.Time, opts ValidateOptsWithSkewPolicy) (bool, uint64, int, error) {
	// Set default values (consistent with GenerateCodeCustom)
	if opts.Period == 0 {
		opts.Period = 30
	}
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1
	}

	// Security guardrail: limit SkewPolicy to prevent DoS
	if opts.SkewPolicy.Past > 10 || opts.SkewPolicy.Future > 10 {
		return false, 0, 0, otp.ErrWindowTooLarge
	}

	step := Counter(opts.Period, t)

	// Check exact step first
	rv, err := hotp.ValidateCustom(passcode, step, secret, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
		Encoder:   opts.Encoder,
	})
	if err != nil {
		return false, 0, 0, err
	}
	if rv {
		return true, step, 0, nil
	}

	// Check past steps (more secure - RFC recommended)
	for i := uint64(1); i <= uint64(opts.SkewPolicy.Past); i++ {
		if step >= i {
			rv, err = hotp.ValidateCustom(passcode, step-i, secret, hotp.ValidateOpts{
				Digits:    opts.Digits,
				Algorithm: opts.Algorithm,
				Encoder:   opts.Encoder,
			})
			if err != nil {
				return false, 0, 0, err
			}
			if rv {
				return true, step - i, -int(i), nil
			}
		}
	}

	// Check future steps (less secure - use sparingly)
	for i := uint64(1); i <= uint64(opts.SkewPolicy.Future); i++ {
		rv, err = hotp.ValidateCustom(passcode, step+i, secret, hotp.ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
			Encoder:   opts.Encoder,
		})
		if err != nil {
			return false, 0, 0, err
		}
		if rv {
			return true, step + i, int(i), nil
		}
	}

	return false, 0, 0, nil
}

// ValidateRFCCompliant validates a TOTP with RFC 6238 recommended settings.
// This only allows past periods (not future) for better security.
//
// Default: Past: 1, Future: 0 (one period tolerance for clock drift)
func ValidateRFCCompliant(passcode string, secret string, t time.Time) (bool, uint64, error) {
	valid, step, _, err := ValidateCustomSkewPolicy(passcode, secret, t, ValidateOptsWithSkewPolicy{
		Period:     30,
		SkewPolicy: SkewPolicy{Past: 1, Future: 0},
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	return valid, step, err
}

// GenerateOpts provides options for Generate().  The default values
// are compatible with Google-Authenticator.
type GenerateOpts struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Size in bytes of the generated Secret. Defaults to 20 bytes.
	SecretSize uint
	// Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
	Secret []byte
	// Digits to request. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Reader to use for generating TOTP Key.
	Rand io.Reader
	// ImageURL is an optional URL to an image (icon/logo) for this key.
	// Only supported by FreeOTP/FreeOTP+; other authenticator apps ignore it.
	ImageURL string
	// Encoder to use for output code. Only EncoderSteam is currently supported
	// as a non-default option. Most authenticator apps do not support the Steam
	// encoder.
	Encoder otp.Encoder
	// GoogleAuthenticatorCompat enables workarounds for Google Authenticator
	// compatibility issues. When true, appends a trailing '&' to the URI query
	// string to work around a GA parsing bug. Default is false.
	// See: https://github.com/pquerna/otp/issues/94
	GoogleAuthenticatorCompat bool
}

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Generate a new TOTP Key.
func Generate(opts GenerateOpts) (*otp.Key, error) {
	// url encode the Issuer/AccountName
	if opts.Issuer == "" {
		return nil, otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, otp.ErrGenerateMissingAccountName
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 20
	}

	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}

	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}

	// Validate ImageURL if provided
	if opts.ImageURL != "" {
		imgURL, err := url.Parse(opts.ImageURL)
		if err != nil || imgURL.Scheme != "https" || imgURL.Host == "" || imgURL.Path == "" {
			return nil, ErrInvalidImageURL
		}
	}

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	v := url.Values{}
	if len(opts.Secret) != 0 {
		v.Set("secret", b32NoPadding.EncodeToString(opts.Secret))
	} else {
		secret := make([]byte, opts.SecretSize)
		defer internal.ZeroBytes(secret)
		_, err := io.ReadFull(opts.Rand, secret)
		if err != nil {
			return nil, err
		}
		v.Set("secret", b32NoPadding.EncodeToString(secret))
	}

	v.Set("issuer", opts.Issuer)

	// Only include non-default parameters to keep URI (and QR code) compact
	if opts.Period != 30 {
		v.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	}
	if opts.Algorithm != otp.AlgorithmSHA1 {
		v.Set("algorithm", opts.Algorithm.String())
	}
	if opts.Digits != otp.DigitsSix {
		v.Set("digits", opts.Digits.String())
	}

	if opts.ImageURL != "" {
		v.Set("image", opts.ImageURL)
	}

	if opts.Encoder != "" {
		v.Set("encoder", string(opts.Encoder))
	}

	rawPath := "/" + url.PathEscape(opts.Issuer) + ":" + url.PathEscape(opts.AccountName)
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawPath:  rawPath,
		RawQuery: internal.EncodeQueryTrailing(v, opts.GoogleAuthenticatorCompat),
	}

	return otp.NewKeyFromURL(u.String())
}
