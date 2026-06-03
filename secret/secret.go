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

package secret

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// Security validation errors
var ErrSecretTooShort = errors.New("secret too short, must be at least 16 bytes per RFC 4226")
var ErrSecretTooLong = errors.New("secret too long, must be at most 64 bytes")

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Secret represents an OTP secret key with multiple encoding representations.
type Secret struct {
	bytes []byte
}

// New creates a new random secret of given size in bytes.
// Recommended minimum size is 20 bytes (160 bits) per RFC 4226.
// Minimum accepted size is 16 bytes (128 bits), maximum is 64 bytes.
func New(size int) (*Secret, error) {
	if size < 16 {
		return nil, ErrSecretTooShort
	}
	if size > 64 {
		return nil, ErrSecretTooLong
	}
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return &Secret{bytes: bytes}, nil
}

// FromBytes creates a secret from raw bytes.
// Validates that the secret length is between 16 and 64 bytes per RFC 4226.
func FromBytes(bytes []byte) (*Secret, error) {
	if len(bytes) < 16 {
		return nil, ErrSecretTooShort
	}
	if len(bytes) > 64 {
		return nil, ErrSecretTooLong
	}
	// Copy the bytes to prevent external modification
	copyBytes := make([]byte, len(bytes))
	copy(copyBytes, bytes)
	return &Secret{bytes: copyBytes}, nil
}

// FromBase32 creates a secret from a Base32 encoded string.
// Handles missing padding and removes internal spaces for usability.
// Validates that the decoded secret length is between 16 and 64 bytes per RFC 4226.
func FromBase32(str string) (*Secret, error) {
	// Remove all spaces for usability (handles "JBSW Y3DP EHPK 3PXP")
	str = strings.ReplaceAll(str, " ", "")
	str = strings.TrimSpace(str)
	str = strings.ToUpper(str)

	// Add padding if missing
	if n := len(str) % 8; n != 0 {
		str = str + strings.Repeat("=", 8-n)
	}

	bytes, err := base32.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	if len(bytes) < 16 {
		return nil, ErrSecretTooShort
	}
	if len(bytes) > 64 {
		return nil, ErrSecretTooLong
	}
	return &Secret{bytes: bytes}, nil
}

// FromHex creates a secret from a hexadecimal string.
// Removes spaces for usability (handles "AB CD EF 12").
// Validates that the decoded secret length is between 16 and 64 bytes per RFC 4226.
func FromHex(str string) (*Secret, error) {
	str = strings.ReplaceAll(str, " ", "")
	str = strings.TrimSpace(str)
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	if len(bytes) < 16 {
		return nil, ErrSecretTooShort
	}
	if len(bytes) > 64 {
		return nil, ErrSecretTooLong
	}
	return &Secret{bytes: bytes}, nil
}

// Bytes returns a copy of the raw bytes of the secret.
// Returns a copy to prevent accidental modification of the internal secret.
func (s *Secret) Bytes() []byte {
	if s.bytes == nil {
		return nil
	}
	out := make([]byte, len(s.bytes))
	copy(out, s.bytes)
	return out
}

// Clear zeros out the secret bytes to minimize memory exposure.
// After calling Clear, the secret should no longer be used.
func (s *Secret) Clear() {
	if s.bytes != nil {
		for i := range s.bytes {
			s.bytes[i] = 0
		}
		s.bytes = nil
	}
}

// Base32 returns the Base32 encoded string without padding.
// This is the format used in otpauth:// URIs.
func (s *Secret) Base32() string {
	return b32NoPadding.EncodeToString(s.bytes)
}

// Base32WithPadding returns the Base32 encoded string with standard padding.
func (s *Secret) Base32WithPadding() string {
	return base32.StdEncoding.EncodeToString(s.bytes)
}

// Hex returns the hexadecimal encoded string.
func (s *Secret) Hex() string {
	return hex.EncodeToString(s.bytes)
}

// Len returns the length of the secret in bytes.
func (s *Secret) Len() int {
	return len(s.bytes)
}
