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
	"image"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyAllThere(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8`)
	require.NoError(t, err, "failed to parse url")
	require.Equal(t, "totp", k.Type(), "Extracting Type")
	require.Equal(t, "Example", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, "JBSWY3DPEHPK3PXP", k.Secret(), "Extracting Secret")
	require.Equal(t, AlgorithmSHA256, k.Algorithm())
	require.Equal(t, DigitsEight, k.Digits())
}

func TestKeyIssuerOnlyInPath(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "failed to parse url")
	require.Equal(t, "Example", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extracting Account Name")
}

func TestKeyNoIssuer(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "failed to parse url")
	require.Equal(t, "", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extracting Account Name")
}

func TestKeyWithNewLine(t *testing.T) {
	w, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP
`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "JBSWY3DPEHPK3PXP", sec)
}

func TestKeyImageURL(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&image=https://example.com/logo.png`)
	require.NoError(t, err)
	require.Equal(t, "https://example.com/logo.png", k.ImageURL())
}

func TestKeyImageURLAbsent(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`)
	require.NoError(t, err)
	require.Equal(t, "", k.ImageURL())
}

func TestKeyString(t *testing.T) {
	raw := `otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`
	k, err := NewKeyFromURL(raw)
	require.NoError(t, err)
	require.Equal(t, raw, k.String())
}

func TestKeyURL(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`)
	require.NoError(t, err)
	url := k.URL()
	require.Contains(t, url, "otpauth://totp/")
	require.Contains(t, url, "secret=JBSWY3DPEHPK3PXP")
}

func TestKeyImage(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`)
	require.NoError(t, err)
	img, err := k.Image(200, 200)
	require.NoError(t, err)
	require.NotNil(t, img)
	// Verify image dimensions
	bounds := img.Bounds()
	require.Equal(t, 200, bounds.Dx())
	require.Equal(t, 200, bounds.Dy())
}

func TestKeyImageInvalidSize(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`)
	require.NoError(t, err)
	_, err = k.Image(0, 0)
	require.Error(t, err)
}

func TestKeyPeriod(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&period=60`)
	require.NoError(t, err)
	require.Equal(t, uint64(60), k.Period())
}

func TestKeyPeriodDefault(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	require.Equal(t, uint64(30), k.Period())
}

func TestKeyEncoderSteam(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&encoder=steam`)
	require.NoError(t, err)
	require.Equal(t, EncoderSteam, k.Encoder())
}

func TestKeyEncoderDefault(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	require.Equal(t, EncoderDefault, k.Encoder())
}

func TestKeyDigitsDefault(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	require.Equal(t, DigitsSix, k.Digits())
}

func TestKeyAlgorithmDefault(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA1, k.Algorithm())
}

func TestKeyAlgorithmMD5(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&algorithm=md5`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmMD5, k.Algorithm())
}

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		alg Algorithm
		str string
	}{
		{AlgorithmSHA1, "SHA1"},
		{AlgorithmSHA256, "SHA256"},
		{AlgorithmSHA512, "SHA512"},
		{AlgorithmMD5, "MD5"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.str, tt.alg.String())
	}
}

func TestAlgorithmHash(t *testing.T) {
	hashes := []Algorithm{AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512, AlgorithmMD5}
	for _, alg := range hashes {
		h := alg.Hash()
		require.NotNil(t, h, "Hash() returned nil for %v", alg)
	}
}

func TestDigitsFormat(t *testing.T) {
	require.Equal(t, "000042", DigitsSix.Format(42))
	require.Equal(t, "00000042", DigitsEight.Format(42))
}

func TestDigitsLength(t *testing.T) {
	require.Equal(t, 6, DigitsSix.Length())
	require.Equal(t, 8, DigitsEight.Length())
}

func TestDigitsString(t *testing.T) {
	require.Equal(t, "6", DigitsSix.String())
	require.Equal(t, "8", DigitsEight.String())
}

func TestNewKeyFromURLError(t *testing.T) {
	_, err := NewKeyFromURL("://invalid")
	require.Error(t, err)
}

func TestKeyType(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0`)
	require.NoError(t, err)
	require.Equal(t, "hotp", k.Type())
}

func TestKeyImageAssertedImage(t *testing.T) {
	// Verify returned image implements image.Image
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	img, err := k.Image(100, 100)
	require.NoError(t, err)
	var _ image.Image = img
}

// ===== New URI Validation Tests =====

func TestNewKeyFromURLInvalidScheme(t *testing.T) {
	_, err := NewKeyFromURL("http://example.com/totp?secret=ABC")
	require.Error(t, err)
	require.Equal(t, ErrInvalidURIScheme, err)
}

func TestNewKeyFromURLInvalidType(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://invalid/Example:alice?secret=JBSWY3DPEHPK3PXP")
	require.Error(t, err)
	require.Equal(t, ErrInvalidURIType, err)
}

func TestNewKeyFromURLMissingSecret(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Example:alice?issuer=Example")
	require.Error(t, err)
	require.Equal(t, ErrMissingSecret, err)
}

func TestNewKeyFromURLInvalidSecretFormat(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Example:alice?secret=INVALID!123")
	require.Error(t, err)
	require.Equal(t, ErrInvalidSecretFormat, err)
}

func TestNewKeyFromURLInvalidAlgorithm(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=INVALID")
	require.Error(t, err)
	require.Equal(t, ErrInvalidAlgorithm, err)
}

func TestNewKeyFromURLInvalidDigits(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=abc")
	require.Error(t, err)
	require.Equal(t, ErrInvalidDigits, err)
}

func TestNewKeyFromURLInvalidPeriod(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&period=abc")
	require.Error(t, err)
	require.Equal(t, ErrInvalidPeriod, err)
}

func TestNewKeyFromURLInvalidCounter(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=abc")
	require.Error(t, err)
	require.Equal(t, ErrInvalidCounter, err)
}

func TestNewKeyFromURLColonInIssuer(t *testing.T) {
	// This URI has "Evil:Example:alice" in the path, which when split on colon
	// results in issuer="Evil" and account="Example:alice"
	// The account name "Example:alice" contains a colon
	_, err := NewKeyFromURL("otpauth://totp/Evil:Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example")
	require.Error(t, err)
	require.Equal(t, ErrColonInAccountName, err) // Account name has colon
}

func TestNewKeyFromURLColonInAccountName(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Example:alice:extra?secret=JBSWY3DPEHPK3PXP")
	require.Error(t, err)
	require.Equal(t, ErrColonInAccountName, err)
}

func TestNewKeyFromURLValidSecretWithSpaces(t *testing.T) {
	// Secret with internal spaces in URL encoding should be accepted and cleaned
	k, err := NewKeyFromURL("otpauth://totp/Example:alice?secret=JBSW%20Y3DP%20EHPK%203PXP")
	require.NoError(t, err)
	// URL decoding gives us "JBSW Y3DP EHPK 3PXP" with spaces, but validation cleans it
	require.Equal(t, "JBSW Y3DP EHPK 3PXP", k.Secret()) // Raw URL decoded value
}

// ===== SHA224/SHA384 Tests =====

func TestKeyAlgorithmSHA224(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha224`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA224, k.Algorithm())
}

func TestKeyAlgorithmSHA384(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha384`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA384, k.Algorithm())
}

func TestAlgorithmSHA224String(t *testing.T) {
	require.Equal(t, "SHA224", AlgorithmSHA224.String())
}

func TestAlgorithmSHA384String(t *testing.T) {
	require.Equal(t, "SHA384", AlgorithmSHA384.String())
}

func TestAlgorithmSHA224Hash(t *testing.T) {
	h := AlgorithmSHA224.Hash()
	require.NotNil(t, h)
	require.Equal(t, 28, h.Size()) // SHA224 produces 28 bytes
}

func TestAlgorithmSHA384Hash(t *testing.T) {
	h := AlgorithmSHA384.Hash()
	require.NotNil(t, h)
	require.Equal(t, 48, h.Size()) // SHA384 produces 48 bytes
}

// ===== SHA3 Algorithm Tests =====

func TestKeyAlgorithmSHA3_224(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha3-224`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA3_224, k.Algorithm())
}

func TestKeyAlgorithmSHA3_256(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha3-256`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA3_256, k.Algorithm())
}

func TestKeyAlgorithmSHA3_384(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha3-384`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA3_384, k.Algorithm())
}

func TestKeyAlgorithmSHA3_512(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha3-512`)
	require.NoError(t, err)
	require.Equal(t, AlgorithmSHA3_512, k.Algorithm())
}

func TestAlgorithmSHA3_224String(t *testing.T) {
	require.Equal(t, "SHA3-224", AlgorithmSHA3_224.String())
}

func TestAlgorithmSHA3_256String(t *testing.T) {
	require.Equal(t, "SHA3-256", AlgorithmSHA3_256.String())
}

func TestAlgorithmSHA3_384String(t *testing.T) {
	require.Equal(t, "SHA3-384", AlgorithmSHA3_384.String())
}

func TestAlgorithmSHA3_512String(t *testing.T) {
	require.Equal(t, "SHA3-512", AlgorithmSHA3_512.String())
}

func TestAlgorithmSHA3_224Hash(t *testing.T) {
	h := AlgorithmSHA3_224.Hash()
	require.NotNil(t, h)
	require.Equal(t, 28, h.Size()) // SHA3-224 produces 28 bytes
}

func TestAlgorithmSHA3_256Hash(t *testing.T) {
	h := AlgorithmSHA3_256.Hash()
	require.NotNil(t, h)
	require.Equal(t, 32, h.Size()) // SHA3-256 produces 32 bytes
}

func TestAlgorithmSHA3_384Hash(t *testing.T) {
	h := AlgorithmSHA3_384.Hash()
	require.NotNil(t, h)
	require.Equal(t, 48, h.Size()) // SHA3-384 produces 48 bytes
}

func TestAlgorithmSHA3_512Hash(t *testing.T) {
	h := AlgorithmSHA3_512.Hash()
	require.NotNil(t, h)
	require.Equal(t, 64, h.Size()) // SHA3-512 produces 64 bytes
}

func TestAlgorithmStringAll(t *testing.T) {
	tests := []struct {
		alg Algorithm
		str string
	}{
		{AlgorithmSHA1, "SHA1"},
		{AlgorithmSHA224, "SHA224"},
		{AlgorithmSHA256, "SHA256"},
		{AlgorithmSHA384, "SHA384"},
		{AlgorithmSHA512, "SHA512"},
		{AlgorithmSHA3_224, "SHA3-224"},
		{AlgorithmSHA3_256, "SHA3-256"},
		{AlgorithmSHA3_384, "SHA3-384"},
		{AlgorithmSHA3_512, "SHA3-512"},
		{AlgorithmMD5, "MD5"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.str, tt.alg.String())
	}
}

func TestAlgorithmHashAll(t *testing.T) {
	algorithms := []Algorithm{
		AlgorithmSHA1, AlgorithmSHA224, AlgorithmSHA256, AlgorithmSHA384, AlgorithmSHA512,
		AlgorithmSHA3_224, AlgorithmSHA3_256, AlgorithmSHA3_384, AlgorithmSHA3_512,
		AlgorithmMD5,
	}
	for _, alg := range algorithms {
		h := alg.Hash()
		require.NotNil(t, h, "Hash() returned nil for %v", alg)
	}
}

// ===== ParseAlgorithm tests =====

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		input string
		want  Algorithm
	}{
		{"SHA1", AlgorithmSHA1},
		{"SHA-1", AlgorithmSHA1},
		{"sha1", AlgorithmSHA1},
		{"SHA256", AlgorithmSHA256},
		{"SHA-256", AlgorithmSHA256},
		{"SHA2-256", AlgorithmSHA256},
		{"sha256", AlgorithmSHA256},
		{"SHA512", AlgorithmSHA512},
		{"SHA-512", AlgorithmSHA512},
		{"MD5", AlgorithmMD5},
		{"md5", AlgorithmMD5},
		{"SHA224", AlgorithmSHA224},
		{"SHA384", AlgorithmSHA384},
		{"SHA3-224", AlgorithmSHA3_224},
		{"SHA3-256", AlgorithmSHA3_256},
		{"SHA3-384", AlgorithmSHA3_384},
		{"SHA3-512", AlgorithmSHA3_512},
		{"SSL3-SHA1", AlgorithmSHA1},
	}
	for _, tt := range tests {
		got, err := ParseAlgorithm(tt.input)
		require.NoError(t, err, "ParseAlgorithm(%q) error", tt.input)
		require.Equal(t, tt.want, got, "ParseAlgorithm(%q)", tt.input)
	}
}

func TestParseAlgorithmInvalid(t *testing.T) {
	_, err := ParseAlgorithm("INVALID")
	require.Error(t, err)
	require.Equal(t, ErrInvalidAlgorithm, err)
}

// ===== IsValid tests =====

func TestAlgorithmIsValid(t *testing.T) {
	valid := []Algorithm{
		AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512, AlgorithmMD5,
		AlgorithmSHA224, AlgorithmSHA384,
		AlgorithmSHA3_224, AlgorithmSHA3_256, AlgorithmSHA3_384, AlgorithmSHA3_512,
	}
	for _, alg := range valid {
		require.True(t, alg.IsValid(), "IsValid() should be true for %s", alg)
	}

	require.False(t, Algorithm(999).IsValid(), "unknown algorithm should not be valid")
}

// ===== HashChecked tests =====

func TestAlgorithmHashChecked(t *testing.T) {
	h, err := AlgorithmSHA256.HashChecked()
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Equal(t, 32, h.Size())
}

func TestAlgorithmHashCheckedInvalid(t *testing.T) {
	h, err := Algorithm(999).HashChecked()
	require.Error(t, err)
	require.Equal(t, ErrInvalidAlgorithm, err)
	require.Nil(t, h)
}

// ===== Key.Counter tests =====

func TestKeyCounter(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=42`)
	require.NoError(t, err)
	require.Equal(t, uint64(42), k.Counter())
}

func TestKeyCounterDefault(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	require.Equal(t, uint64(0), k.Counter())
}

// ===== Key.GetExtraParam tests =====

func TestKeyGetExtraParam(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&source=web&lock=true`)
	require.NoError(t, err)
	require.Equal(t, "web", k.GetExtraParam("source"))
	require.Equal(t, "true", k.GetExtraParam("lock"))
	require.Equal(t, "", k.GetExtraParam("nonexistent"))
}

// ===== Nil Key receiver tests =====

func TestKeyNilReceivers(t *testing.T) {
	k := &Key{} // url is nil
	require.Equal(t, "", k.Type())
	require.Equal(t, "", k.Issuer())
	require.Equal(t, "", k.AccountName())
	require.Equal(t, "", k.Secret())
	require.Equal(t, uint64(30), k.Period())
	require.Equal(t, DigitsSix, k.Digits())
	require.Equal(t, AlgorithmSHA1, k.Algorithm())
	require.Equal(t, EncoderDefault, k.Encoder())
	require.Equal(t, uint64(0), k.Counter())
	require.Equal(t, "", k.URL())
	require.Equal(t, "", k.ImageURL())
	require.Equal(t, "", k.GetExtraParam("any"))
}

// ===== CRLF injection rejection =====

func TestNewKeyFromURLCRLFInIssuer(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Test%0AEvil:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=Test%0AEvil")
	require.Error(t, err)
	require.Equal(t, ErrInvalidURIChars, err)
}

func TestNewKeyFromURLNullInAccount(t *testing.T) {
	_, err := NewKeyFromURL("otpauth://totp/Test:user%00@test.com?secret=JBSWY3DPEHPK3PXP")
	require.Error(t, err)
	require.Equal(t, ErrInvalidURIChars, err)
}

func TestNewKeyFromURLTooLong(t *testing.T) {
	longURI := "otpauth://totp/Test:user@test.com?secret=JBSWY3DPEHPK3PXP&padding=" + string(make([]byte, 2500))
	_, err := NewKeyFromURL(longURI)
	require.Error(t, err)
	require.Equal(t, ErrURITooLong, err)
}

func TestNewKeyFromURLValidShortPath(t *testing.T) {
	// Normal URI should still work
	_, err := NewKeyFromURL("otpauth://totp/Test:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=Test")
	require.NoError(t, err)
}

// ===== AlgorithmStringUnknown test =====

func TestAlgorithmStringUnknown(t *testing.T) {
	require.Equal(t, "UNKNOWN(999)", Algorithm(999).String())
}

// ===== Hash fallback for unknown algorithm =====

func TestAlgorithmHashUnknown(t *testing.T) {
	h := Algorithm(999).Hash()
	require.NotNil(t, h) // falls back to SHA1
	require.Equal(t, 20, h.Size())
}

// ===== Image error path (invalid QR data) =====

func TestKeyImageQRError(t *testing.T) {
	// Create a key with an extremely long string that will fail QR encoding
	k := &Key{orig: string(make([]byte, 10000))}
	_, err := k.Image(200, 200)
	require.Error(t, err)
}
