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

package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"image"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"golang.org/x/crypto/sha3"
)

// Error when attempting to convert the secret from base32 to raw bytes.
var ErrValidateSecretInvalidBase32 = errors.New("decoding of secret as base32 failed")

// The user provided passcode length was not expected.
var ErrValidateInputInvalidLength = errors.New("input length unexpected")

// When generating a Key, the Issuer must be set.
var ErrGenerateMissingIssuer = errors.New("issuer must be set")

// When generating a Key, the Account Name must be set.
var ErrGenerateMissingAccountName = errors.New("accountName must be set")

// URI format validation errors.
var ErrInvalidURIFormat = errors.New("invalid URI format")
var ErrInvalidURIScheme = errors.New("invalid URI scheme, must be otpauth://")
var ErrInvalidURIType = errors.New("invalid OTP type, must be 'hotp' or 'totp'")
var ErrMissingSecret = errors.New("missing required 'secret' parameter")
var ErrInvalidSecretFormat = errors.New("invalid 'secret' format, must be valid Base32")
var ErrInvalidAlgorithm = errors.New("invalid 'algorithm' parameter")
var ErrInvalidDigits = errors.New("invalid 'digits' parameter")
var ErrInvalidPeriod = errors.New("invalid 'period' parameter")
var ErrInvalidCounter = errors.New("invalid 'counter' parameter")
var ErrColonInIssuer = errors.New("invalid colon in issuer name")
var ErrColonInAccountName = errors.New("invalid colon in account name")

// Security validation errors.
var ErrDigestTooSmall = errors.New("HMAC digest size too small, must be at least 19 bytes for dynamic truncation safety")
var ErrAlgorithmDigestInsufficient = errors.New("algorithm produces insufficient digest size for OTP generation")
var ErrReplayAttack = errors.New("replay attack detected: time step already used")
var ErrURITooLong = errors.New("URI exceeds maximum allowed length")
var ErrSecretTooShort = errors.New("secret too short, must be at least 16 bytes")
var ErrSecretTooLong = errors.New("secret too long, must be at most 64 bytes")
var ErrWindowTooLarge = errors.New("window exceeds maximum allowed value")
var ErrDigitsOutOfRange = errors.New("digits out of range: default encoder requires 6-10, Steam encoder allows 5-10")
var ErrPeriodOutOfRange = errors.New("period out of range, must be between 1 and 300 seconds")
var ErrInvalidEncoder = errors.New("invalid encoder: must be EncoderDefault or EncoderSteam")
var ErrInvalidImageURL = errors.New("image URL must be a valid HTTPS URL")
var ErrValidateInputInvalidChars = errors.New("passcode contains invalid characters")
var ErrInvalidURIChars = errors.New("issuer or account name contains invalid characters (control chars)")

// ValidationResult provides a structured result for OTP validation operations.
// It includes details about whether validation succeeded and metadata about
// the match for replay protection and clock drift detection.
type ValidationResult struct {
	// Valid indicates whether the passcode was accepted.
	Valid bool
	// Delta is the offset from the expected counter/step (0 = exact match,
	// negative = past, positive = future). Useful for clock drift detection.
	Delta int
	// Step is the matched time step (TOTP) or counter value (HOTP) for replay prevention tracking.
	Step uint64
}

// Validation regex patterns
var (
	// Base32 alphabet: A-Z, 2-7 (RFC 4648)
	secretRegex = regexp.MustCompile(`^[2-7A-Z]+=*$`)
	// Supported algorithms (canonical names after normalization)
	algorithmRegex = regexp.MustCompile(`^SHA(?:1|224|256|384|512|3-224|3-256|3-384|3-512)$|^MD5$`)
	// Positive integer
	posIntRegex = regexp.MustCompile(`^\+?[1-9]\d*$`)
	// Integer (including zero and negative)
	intRegex = regexp.MustCompile(`^[+-]?\d+$`)
)

// normalizeAlgorithmName normalizes algorithm name variants to canonical form.
// Accepts aliases like "SHA-256", "SHA2-256", "SSL3-SHA1" and produces "SHA256", "SHA1".
func normalizeAlgorithmName(name string) string {
	s := strings.ToUpper(strings.TrimSpace(name))
	// SSL3-SHA1 -> SHA1 (remainder already has SHA prefix)
	if strings.HasPrefix(s, "SSL3-") {
		return s[5:]
	}
	// Strip known prefixes that authenticator apps may emit
	// SHA-256 -> SHA256, SHA2-256 -> SHA256
	for _, prefix := range []string{"SHA2-", "SHA2?", "SHA-"} {
		if strings.HasPrefix(s, prefix) {
			return "SHA" + s[len(prefix):]
		}
	}
	return s
}

// containsControlChars reports whether s contains ASCII control characters
// (U+0000-U+001F, U+007F) excluding common whitespace (space, tab).
func containsControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// Key represents a TOTP or HOTP key.
type Key struct {
	orig string
	url  *url.URL
}

// NewKeyFromURL creates a new Key from an TOTP or HOTP url.
//
// The URL format is documented here:
//
//	https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// This function performs strict validation per IETF draft-andesco-otpauth-uri:
// - Validates URI scheme is "otpauth://"
// - Validates OTP type is "hotp" or "totp"
// - Validates required "secret" parameter exists and is valid Base32
// - Validates optional parameters have correct formats
// - Rejects URIs with colons in parsed issuer or account name
func NewKeyFromURL(orig string) (*Key, error) {
	s := strings.TrimSpace(orig)

	// 0. Validate URI length to prevent memory exhaustion
	if len(s) > 2048 {
		return nil, ErrURITooLong
	}

	// 1. Validate URI scheme
	if !strings.HasPrefix(s, "otpauth://") {
		return nil, ErrInvalidURIScheme
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	// 2. Validate OTP type
	if u.Host != "hotp" && u.Host != "totp" {
		return nil, ErrInvalidURIType
	}

	// 3. Validate required secret parameter
	q := u.Query()
	secret := q.Get("secret")
	if secret == "" {
		return nil, ErrMissingSecret
	}

	// 4. Validate secret format (Base32)
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if !secretRegex.MatchString(secret) {
		return nil, ErrInvalidSecretFormat
	}

	// 5. Validate optional algorithm parameter (normalize aliases like SHA-256 -> SHA256)
	if alg := q.Get("algorithm"); alg != "" {
		if !algorithmRegex.MatchString(normalizeAlgorithmName(alg)) {
			return nil, ErrInvalidAlgorithm
		}
	}

	// 6. Validate optional digits parameter
	if digits := q.Get("digits"); digits != "" {
		if !posIntRegex.MatchString(digits) {
			return nil, ErrInvalidDigits
		}
	}

	// 7. Validate optional period parameter (TOTP)
	if u.Host == "totp" && q.Get("period") != "" {
		if !posIntRegex.MatchString(q.Get("period")) {
			return nil, ErrInvalidPeriod
		}
	}

	// 8. Validate optional counter parameter (HOTP)
	if u.Host == "hotp" && q.Get("counter") != "" {
		if !intRegex.MatchString(q.Get("counter")) {
			return nil, ErrInvalidCounter
		}
	}

	k := &Key{
		orig: s,
		url:  u,
	}

	// 9. Validate no colons or control characters in issuer or account name
	issuer := k.Issuer()
	account := k.AccountName()
	if strings.Contains(issuer, ":") {
		return nil, ErrColonInIssuer
	}
	if strings.Contains(account, ":") {
		return nil, ErrColonInAccountName
	}

	// 10. Reject control characters in issuer and account name (prevent CRLF injection)
	if containsControlChars(issuer) || containsControlChars(account) {
		return nil, ErrInvalidURIChars
	}

	return k, nil
}

func (k *Key) String() string {
	return k.orig
}

// Image returns a QR-Code image of the specified width and height,
// suitable for use by many clients like Google-Authenticator
// to enroll a user's TOTP/HOTP key.
func (k *Key) Image(width int, height int) (image.Image, error) {
	b, err := qr.Encode(k.orig, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}

	b, err = barcode.Scale(b, width, height)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// Type returns "hotp" or "totp".
func (k *Key) Type() string {
	if k.url == nil {
		return ""
	}
	return k.url.Host
}

// Issuer returns the name of the issuing organization.
func (k *Key) Issuer() string {
	if k.url == nil {
		return ""
	}
	q := k.url.Query()

	issuer := q.Get("issuer")

	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

// AccountName returns the name of the user's account.
func (k *Key) AccountName() string {
	if k.url == nil {
		return ""
	}
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return p[i+1:]
}

// Secret returns the opaque secret for this Key.
func (k *Key) Secret() string {
	if k.url == nil {
		return ""
	}
	q := k.url.Query()

	return q.Get("secret")
}

// Period returns the rotation time in seconds.
func (k *Key) Period() uint64 {
	if k.url == nil {
		return 30
	}
	q := k.url.Query()

	if u, err := strconv.ParseUint(q.Get("period"), 10, 64); err == nil {
		return u
	}

	// If no period is defined 30 seconds is the default per (rfc6238)
	return 30
}

// Digits returns the number of OTP digits.
func (k *Key) Digits() Digits {
	if k.url == nil {
		return DigitsSix
	}
	q := k.url.Query()

	if u, err := strconv.ParseUint(q.Get("digits"), 10, 64); err == nil {
		return Digits(u)
	}

	// Six is the most common value.
	return DigitsSix
}

// Algorithm returns the algorithm used or the default (SHA1).
func (k *Key) Algorithm() Algorithm {
	if k.url == nil {
		return AlgorithmSHA1
	}
	q := k.url.Query()

	a := strings.ToLower(normalizeAlgorithmName(q.Get("algorithm")))
	switch a {
	case "sha256":
		return AlgorithmSHA256
	case "sha512":
		return AlgorithmSHA512
	case "md5":
		return AlgorithmMD5
	case "sha224":
		return AlgorithmSHA224
	case "sha384":
		return AlgorithmSHA384
	case "sha3-224":
		return AlgorithmSHA3_224
	case "sha3-256":
		return AlgorithmSHA3_256
	case "sha3-384":
		return AlgorithmSHA3_384
	case "sha3-512":
		return AlgorithmSHA3_512
	default:
		return AlgorithmSHA1
	}
}

// Encoder returns the encoder used or the default ("")
func (k *Key) Encoder() Encoder {
	if k.url == nil {
		return EncoderDefault
	}
	q := k.url.Query()

	a := strings.ToLower(q.Get("encoder"))
	switch a {
	case "steam":
		return EncoderSteam
	default:
		return EncoderDefault
	}
}

// Counter returns the initial HOTP counter value, or 0 if not set or not an HOTP key.
func (k *Key) Counter() uint64 {
	if k.url == nil {
		return 0
	}
	q := k.url.Query()
	if u, err := strconv.ParseUint(q.Get("counter"), 10, 64); err == nil {
		return u
	}
	return 0
}

// URL returns the OTP URL as a string
func (k *Key) URL() string {
	if k.url == nil {
		return ""
	}
	return k.url.String()
}

// ImageURL returns the image parameter from the OTP URL, if set.
// Only FreeOTP and FreeOTP+ support this parameter; other authenticator
// apps ignore it.
func (k *Key) ImageURL() string {
	if k.url == nil {
		return ""
	}
	q := k.url.Query()
	return q.Get("image")
}

// GetExtraParam returns the value of a custom query parameter from the OTP URI.
// Returns empty string if the parameter does not exist.
// This is useful for reading custom parameters that were set via ExtraParams
// during key generation (e.g., "lock", "source", etc.).
func (k *Key) GetExtraParam(key string) string {
	if k.url == nil {
		return ""
	}
	return k.url.Query().Get(key)
}

// Algorithm represents the hashing function to use in the HMAC
// operation needed for OTPs.
type Algorithm int

const (
	// AlgorithmSHA1 should be used for compatibility with Google Authenticator.
	//
	// HMAC-SHA1 remains cryptographically secure for OTP despite SHA1 collision attacks.
	// See RFC 4226 Section 9: https://tools.ietf.org/html/rfc4226#section-9
	//
	// For new deployments where all clients support SHA256, consider AlgorithmSHA256.
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
	// Extended algorithms (appended to preserve numeric values of original constants)
	AlgorithmSHA224
	AlgorithmSHA384
	// SHA3 variants (Keccak) - extended algorithm support
	AlgorithmSHA3_224
	AlgorithmSHA3_256
	AlgorithmSHA3_384
	AlgorithmSHA3_512
)

// Semantic aliases for clarity and documentation.

// AlgorithmCompat is the compatibility default (SHA1).
// Use for maximum compatibility with all authenticator apps including
// Google Authenticator, Microsoft Authenticator, Authy, and others.
//
// This is the zero-value default for ValidateOpts.Algorithm.
const AlgorithmCompat = AlgorithmSHA1

// AlgorithmSecure is the security-recommended algorithm (SHA256).
// Use for new deployments where all clients support SHA256:
// - Google Authenticator 2.0+
// - Microsoft Authenticator
// - Authy
// - KeePassXC
// - WinAuth
// - Bitwarden
//
// Note: Some older authenticator apps may not support SHA256.
const AlgorithmSecure = AlgorithmSHA256

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	case AlgorithmSHA224:
		return "SHA224"
	case AlgorithmSHA384:
		return "SHA384"
	case AlgorithmSHA3_224:
		return "SHA3-224"
	case AlgorithmSHA3_256:
		return "SHA3-256"
	case AlgorithmSHA3_384:
		return "SHA3-384"
	case AlgorithmSHA3_512:
		return "SHA3-512"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(a))
	}
}

// ParseAlgorithm parses an algorithm name string (case-insensitive) into an Algorithm.
// Accepts common aliases: "SHA-256", "SHA256", "SHA2-256", "SHA-1", "SHA1", "SSL3-SHA1".
// Returns an error if the name is not recognized.
func ParseAlgorithm(name string) (Algorithm, error) {
	switch strings.ToLower(normalizeAlgorithmName(name)) {
	case "sha1":
		return AlgorithmSHA1, nil
	case "sha256":
		return AlgorithmSHA256, nil
	case "sha512":
		return AlgorithmSHA512, nil
	case "md5":
		return AlgorithmMD5, nil
	case "sha224":
		return AlgorithmSHA224, nil
	case "sha384":
		return AlgorithmSHA384, nil
	case "sha3-224":
		return AlgorithmSHA3_224, nil
	case "sha3-256":
		return AlgorithmSHA3_256, nil
	case "sha3-384":
		return AlgorithmSHA3_384, nil
	case "sha3-512":
		return AlgorithmSHA3_512, nil
	default:
		return AlgorithmSHA1, ErrInvalidAlgorithm
	}
}

// IsValid reports whether the Algorithm is a known, supported value.
func (a Algorithm) IsValid() bool {
	switch a {
	case AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512,
		AlgorithmMD5, AlgorithmSHA224, AlgorithmSHA384,
		AlgorithmSHA3_224, AlgorithmSHA3_256, AlgorithmSHA3_384, AlgorithmSHA3_512:
		return true
	}
	return false
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	case AlgorithmSHA224:
		return sha256.New224()
	case AlgorithmSHA384:
		return sha512.New384()
	case AlgorithmSHA3_224:
		return sha3.New224()
	case AlgorithmSHA3_256:
		return sha3.New256()
	case AlgorithmSHA3_384:
		return sha3.New384()
	case AlgorithmSHA3_512:
		return sha3.New512()
	default:
		// Unknown algorithm: fallback to SHA1 but callers should check IsValid() first.
		return sha1.New()
	}
}

// HashChecked returns the hash.Hash for the algorithm, returning an error if
// the algorithm is unknown or invalid. For safe usage, prefer this over Hash()
// which silently falls back to SHA1 for unknown algorithms.
func (a Algorithm) HashChecked() (hash.Hash, error) {
	if !a.IsValid() {
		return nil, ErrInvalidAlgorithm
	}
	return a.Hash(), nil
}

// Digits represents the number of digits present in the
// user's OTP passcode. Six and Eight are the most common values.
type Digits int

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

// Format converts an integer into the zero-filled size for this Digits.
func (d Digits) Format(in int32) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, in)
}

// Length returns the number of characters for this Digits.
func (d Digits) Length() int {
	return int(d)
}

func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}

// Encoder represents the output encoding format for OTP codes.
type Encoder string

const (
	EncoderDefault Encoder = ""
	// EncoderSteam produces 5-character alphanumeric codes using the Steam Guard
	// alphabet (23456789BCDFGHJKMNPQRTVWXY). Only compatible with KeePassXC, WinAuth,
	// Bitwarden, and the Steam Mobile App. Google Authenticator and Microsoft
	// Authenticator do not support this encoder.
	EncoderSteam Encoder = "steam"
)
