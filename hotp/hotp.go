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
	"io"

	"github.com/unitsvc/otp"
	"github.com/unitsvc/otp/internal"

	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// ErrInvalidImageURL indicates the image URL is not a valid HTTPS URL.
// Deprecated: Use otp.ErrInvalidImageURL instead.
var ErrInvalidImageURL = otp.ErrInvalidImageURL

// steamAlphabet is the character set used by Steam Guard codes.
// Defined as package-level variable to avoid repeated allocation.
// Alphabet: 23456789BCDFGHJKMNPQRTVWXY (26 characters, no ambiguous letters)
var steamAlphabet = []byte{
	'2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C',
	'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q',
	'R', 'T', 'V', 'W', 'X', 'Y',
}

// steamRadix is the number of characters in the Steam alphabet
const steamRadix = 26

// Validate a HOTP passcode given a counter and secret.
// This is a shortcut for ValidateCustom, with parameters that
// are compatible with Google-Authenticator.
func Validate(passcode string, counter uint64, secret string) bool {
	rv, _ := ValidateCustom(
		passcode,
		counter,
		secret,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return rv
}

// ValidateOpts provides options for ValidateCustom().
type ValidateOpts struct {
	// Digits as part of the input. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Encoder to use for output code.
	Encoder otp.Encoder
}

// ValidateOptsWithWindow provides options for ValidateCustomWindow().
type ValidateOptsWithWindow struct {
	// Digits as part of the input. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Encoder to use for output code.
	Encoder otp.Encoder
	// Window is the number of counters to check on each side of the expected counter.
	// A window of 1 checks counters: [expected-1, expected, expected+1].
	// This helps account for counter synchronization issues.
	Window uint
	// AfterCounter is the last successfully used counter value for replay protection.
	// If set (non-zero), counters <= AfterCounter are rejected.
	// Zero value means no replay protection (default).
	AfterCounter uint64
}

// GenerateCode creates a HOTP passcode given a counter and secret.
// This is a shortcut for GenerateCodeCustom, with parameters that
// are compatible with Google-Authenticator.
func GenerateCode(secret string, counter uint64) (string, error) {
	return GenerateCodeCustom(secret, counter, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// ValidateSecure validates a HOTP passcode using SHA256 (security recommended).
// Use this for new deployments where all clients support SHA256.
// For maximum compatibility with all authenticator apps, use Validate instead.
func ValidateSecure(passcode string, counter uint64, secret string) bool {
	rv, _ := ValidateCustom(
		passcode,
		counter,
		secret,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
		},
	)
	return rv
}

// GenerateCodeSecure generates a HOTP passcode using SHA256 (security recommended).
// Use this for new deployments where all clients support SHA256.
// For maximum compatibility with all authenticator apps, use GenerateCode instead.
func GenerateCodeSecure(secret string, counter uint64) (string, error) {
	return GenerateCodeCustom(secret, counter, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
}

// GenerateCodeCustom uses a counter and secret value and options struct to
// create a passcode.
func GenerateCodeCustom(secret string, counter uint64, opts ValidateOpts) (passcode string, err error) {
	// Set default values (Go convention: make zero value useful)
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1 // Explicit default for clarity
	}

	// Validate algorithm
	if !opts.Algorithm.IsValid() {
		return "", otp.ErrInvalidAlgorithm
	}

	// Security guardrails per RFC 4226
	// RFC recommends 6-10 digits for standard encoding.
	// Steam encoder uses 5 characters by convention.
	digitsVal := int(opts.Digits)
	if opts.Encoder == otp.EncoderDefault || opts.Encoder == "" {
		if digitsVal < 6 || digitsVal > 10 {
			return "", otp.ErrDigitsOutOfRange
		}
	} else if opts.Encoder == otp.EncoderSteam {
		// Steam Guard uses 5 characters; allow 5-10 for flexibility
		if digitsVal < 5 || digitsVal > 10 {
			return "", otp.ErrDigitsOutOfRange
		}
	} else {
		return "", otp.ErrInvalidEncoder
	}

	// As noted in issue #10 and #17 this adds support for TOTP secrets that are
	// missing their padding.
	secret = strings.TrimSpace(secret)
	// Remove all internal spaces for better usability (handles formatted secrets like "JBSW Y3DP EHPK 3PXP")
	secret = strings.ReplaceAll(secret, " ", "")
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	// As noted in issue #24 Google has started producing base32 in lower case,
	// but the StdEncoding (and the RFC), expect a dictionary of only upper case letters.
	secret = strings.ToUpper(secret)

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", otp.ErrValidateSecretInvalidBase32
	}
	defer internal.ZeroBytes(secretBytes)

	// RFC 4226 Section 4: "The length of the shared secret must be at least 128 bits (16 bytes)"
	// and "We recommend a shared secret length of at least 160 bits (20 bytes)"
	if len(secretBytes) < 16 {
		return "", otp.ErrSecretTooShort
	}
	if len(secretBytes) > 64 {
		return "", otp.ErrSecretTooLong
	}

	buf := make([]byte, 8)
	defer internal.ZeroBytes(buf)
	mac := hmac.New(opts.Algorithm.Hash, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)

	mac.Write(buf)
	sum := mac.Sum(nil)
	defer internal.ZeroBytes(sum)

	// Validate digest size for dynamic truncation safety.
	// Dynamic truncation accesses sum[offset] through sum[offset+3] where max offset = 15.
	// Maximum index needed is 18, requiring len(sum) >= 19.
	// All supported algorithms produce >= 20 bytes (SHA1=20, SHA224=28, SHA256=32, etc.)
	// MD5 (16 bytes) is correctly rejected by this check.
	if len(sum) < 19 {
		return "", otp.ErrDigestTooSmall
	}

	// "Dynamic truncation" in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	l := opts.Digits.Length()
	switch opts.Encoder {
	case otp.EncoderDefault:
		mod := int32(value % int64(math.Pow10(l)))
		passcode = opts.Digits.Format(mod)
	case otp.EncoderSteam:
		// Use pre-allocated byte slice for efficiency
		// Steam codes are generated from least significant digit
		result := make([]byte, l)
		for i := 0; i < l; i++ {
			digit := value % steamRadix
			value /= steamRadix
			result[l-1-i] = steamAlphabet[digit]
		}
		passcode = string(result)
	}

	return
}

// ValidateCustom validates an HOTP with customizable options. Most users should
// use Validate().
func ValidateCustom(passcode string, counter uint64, secret string, opts ValidateOpts) (bool, error) {
	// Set default values (consistent with GenerateCodeCustom)
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1
	}

	passcode = strings.TrimSpace(passcode)
	// Strip internal spaces to handle authenticator apps that display codes
	// with spaces for readability (e.g., "123 456" or "12 34 56").
	passcode = strings.ReplaceAll(passcode, " ", "")

	if len(passcode) != opts.Digits.Length() {
		return false, otp.ErrValidateInputInvalidLength
	}

	// Validate passcode characters match expected encoder alphabet
	if !isValidPasscodeChars(passcode, opts.Encoder) {
		return false, otp.ErrValidateInputInvalidChars
	}

	otpstr, err := GenerateCodeCustom(secret, counter, opts)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(otpstr), []byte(passcode)) == 1 {
		return true, nil
	}

	return false, nil
}

// isValidPasscodeChars validates that passcode contains only characters
// from the expected encoder alphabet.
func isValidPasscodeChars(passcode string, encoder otp.Encoder) bool {
	switch encoder {
	case otp.EncoderSteam:
		// Steam alphabet: 23456789BCDFGHJKMNPQRTVWXY
		for _, c := range passcode {
			if !isSteamChar(c) {
				return false
			}
		}
		return true
	case otp.EncoderDefault:
		// Default: digits 0-9
		for _, c := range passcode {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	default:
		// Unknown encoder: be conservative, reject
		return false
	}
}

// isSteamChar checks if a character is in the Steam Guard alphabet.
func isSteamChar(c rune) bool {
	// Steam alphabet: 23456789BCDFGHJKMNPQRTVWXY (26 characters)
	switch c {
	case '2', '3', '4', '5', '6', '7', '8', '9',
		'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K',
		'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y':
		return true
	default:
		return false
	}
}

// ValidateCustomNormalized validates an HOTP with Unicode NFKC normalization
// applied to the passcode. This is useful for handling fullwidth characters
// and other Unicode compatibility variants that users might input.
//
// For example, Japanese fullwidth characters like "ｊｓ１２３４５" are normalized
// to "js12345" before comparison.
//
// Note: This function is optional and should be used when supporting
// international users who may input codes via different input methods.
func ValidateCustomNormalized(passcode string, counter uint64, secret string, opts ValidateOpts) (bool, error) {
	// Apply NFKC normalization for international character support
	passcode = internal.NormalizeNFKC(passcode)
	return ValidateCustom(passcode, counter, secret, opts)
}

// ValidateCustomWindow validates an HOTP with a window of counters, returning
// the delta (counter difference) if valid. This helps handle counter
// synchronization issues between client and server.
//
// Returns:
//   - delta: 0 for exact match, positive for future counter, negative for past
//   - found: true if a matching counter was found within the window
//
// Security note: A large window increases vulnerability to brute force attacks.
// RFC 4226 recommends keeping window as small as possible and implementing
// throttling mechanisms. Maximum allowed window is 10.
func ValidateCustomWindow(passcode string, counter uint64, secret string, opts ValidateOptsWithWindow) (int, bool, error) {
	// Set default values (consistent with GenerateCodeCustom)
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1
	}

	passcode = strings.TrimSpace(passcode)
	passcode = strings.ReplaceAll(passcode, " ", "")

	// Security guardrail: limit window to prevent brute force attacks
	if opts.Window > 10 {
		return 0, false, otp.ErrWindowTooLarge
	}

	if len(passcode) != opts.Digits.Length() {
		return 0, false, otp.ErrValidateInputInvalidLength
	}

	// Helper function to check a specific counter
	checkCounter := func(c uint64) (bool, error) {
		otpstr, err := GenerateCodeCustom(secret, c, ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
			Encoder:   opts.Encoder,
		})
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(otpstr), []byte(passcode)) == 1, nil
	}

	// Check exact counter first
	valid, err := checkCounter(counter)
	if err != nil {
		return 0, false, err
	}
	if valid && (opts.AfterCounter == 0 || counter > opts.AfterCounter) {
		return 0, true, nil
	}

	// Check window counters (past and future)
	for i := uint64(1); i <= uint64(opts.Window); i++ {
		// Check counter - i (past)
		if counter >= i {
			c := counter - i
			if opts.AfterCounter == 0 || c > opts.AfterCounter {
				valid, err = checkCounter(c)
				if err != nil {
					return 0, false, err
				}
				if valid {
					return int(-i), true, nil
				}
			}
		}

		// Check counter + i (future)
		c := counter + i
		if c < counter {
			// uint64 overflow: counter + i wrapped around, skip
			continue
		}
		if opts.AfterCounter == 0 || c > opts.AfterCounter {
			valid, err = checkCounter(c)
			if err != nil {
				return 0, false, err
			}
			if valid {
				return int(i), true, nil
			}
		}
	}

	return 0, false, nil
}

// GenerateOpts provides options for .Generate()
type GenerateOpts struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Size in size of the generated Secret. Defaults to 20 bytes (160 bits).
	SecretSize uint
	// Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
	Secret []byte
	// Digits to request. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Reader to use for generating HOTP Key.
	Rand io.Reader
	// Initial counter value. Defaults to 0. For maximum compatibility with
	// authenticator apps (Google Authenticator, Microsoft Authenticator),
	// use counter=0. Some apps may reset non-zero counters on import.
	Counter uint64
	// ImageURL is an optional URL to an image (icon/logo) for this key.
	// Only supported by FreeOTP/FreeOTP+; other authenticator apps ignore it.
	ImageURL string
	// GoogleAuthenticatorCompat enables workarounds for Google Authenticator
	// compatibility issues. When true, appends a trailing '&' to the URI query
	// string to work around a GA parsing bug. Default is false.
	// See: https://github.com/pquerna/otp/issues/94
	GoogleAuthenticatorCompat bool
	// ExtraParams are additional query parameters to include in the otpauth:// URI.
	ExtraParams map[string]string
	// IssuerInLabelOmit controls whether to omit the issuer from the URI label path.
	IssuerInLabelOmit bool
}

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Generate creates a new HOTP Key.
func Generate(opts GenerateOpts) (*otp.Key, error) {
	// url encode the Issuer/AccountName
	if opts.Issuer == "" {
		return nil, otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, otp.ErrGenerateMissingAccountName
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

	// Validate parameters match GenerateCodeCustom guardrails
	if opts.SecretSize < 16 {
		return nil, otp.ErrSecretTooShort
	}
	if opts.SecretSize > 64 {
		return nil, otp.ErrSecretTooLong
	}
	digitsVal := int(opts.Digits)
	if digitsVal < 6 || digitsVal > 10 {
		return nil, otp.ErrDigitsOutOfRange
	}
	if !opts.Algorithm.IsValid() {
		return nil, otp.ErrInvalidAlgorithm
	}

	// Validate ImageURL if provided
	if opts.ImageURL != "" {
		imgURL, err := url.Parse(opts.ImageURL)
		if err != nil || imgURL.Scheme != "https" || imgURL.Host == "" || imgURL.Path == "" {
			return nil, ErrInvalidImageURL
		}
	}

	// otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

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
	if opts.Algorithm != otp.AlgorithmSHA1 {
		v.Set("algorithm", opts.Algorithm.String())
	}
	if opts.Digits != otp.DigitsSix {
		v.Set("digits", opts.Digits.String())
	}
	v.Set("counter", strconv.FormatUint(opts.Counter, 10))

	if opts.ImageURL != "" {
		v.Set("image", opts.ImageURL)
	}

	// Add extra custom parameters
	internal.SetExtraParams(v, opts.ExtraParams, 1024)

	// Build label path
	path, rawPath := internal.BuildLabelPath(opts.Issuer, opts.AccountName, opts.IssuerInLabelOmit)
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "hotp",
		Path:     path,
		RawPath:  rawPath,
		RawQuery: internal.EncodeQueryTrailing(v, opts.GoogleAuthenticatorCompat),
	}

	return otp.NewKeyFromURL(u.String())
}
