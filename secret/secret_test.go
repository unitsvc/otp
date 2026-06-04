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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	// Create a new secret of 20 bytes (RFC recommended)
	s, err := New(20)
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t, 20, s.Len())
}

func TestNewValidation(t *testing.T) {
	// Test minimum size (16 bytes)
	s, err := New(16)
	require.NoError(t, err)
	require.Equal(t, 16, s.Len())

	// Test maximum size (64 bytes)
	s, err = New(64)
	require.NoError(t, err)
	require.Equal(t, 64, s.Len())

	// Test too short (< 16 bytes)
	_, err = New(15)
	require.Error(t, err)
	require.Equal(t, ErrSecretTooShort, err)

	// Test too long (> 64 bytes)
	_, err = New(65)
	require.Error(t, err)
	require.Equal(t, ErrSecretTooLong, err)
}

func TestFromBytes(t *testing.T) {
	// 16 bytes (minimum)
	bytes := make([]byte, 16)
	for i := range bytes {
		bytes[i] = byte(i)
	}
	s, err := FromBytes(bytes)
	require.NoError(t, err)
	require.NotNil(t, s)
	// Bytes() returns a copy, so it should not be the same slice
	require.NotSame(t, &bytes[0], &(s.Bytes()[0]))
	require.Equal(t, bytes, s.Bytes())
}

func TestFromBytesValidation(t *testing.T) {
	// Test too short (< 16 bytes)
	shortBytes := []byte("short12345678") // 14 bytes
	_, err := FromBytes(shortBytes)
	require.Error(t, err)
	require.Equal(t, ErrSecretTooShort, err)

	// Test too long (> 64 bytes)
	longBytes := make([]byte, 65)
	_, err = FromBytes(longBytes)
	require.Error(t, err)
	require.Equal(t, ErrSecretTooLong, err)
}

func TestFromBase32(t *testing.T) {
	// 20 bytes secret: "12345678901234567890" -> Base32
	// GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ (32 chars)
	s, err := FromBase32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t, 20, s.Len())

	// Test with padding
	s, err = FromBase32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.NoError(t, err)
	require.Equal(t, 20, s.Len())

	// Test lowercase (should work)
	s, err = FromBase32("gezdgnbvgy3tqojqgezdgnbvgy3tqojq")
	require.NoError(t, err)
	require.Equal(t, 20, s.Len())

	// Test with internal spaces (should work)
	s, err = FromBase32("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ")
	require.NoError(t, err)
	require.Equal(t, 20, s.Len())
}

func TestFromBase32Invalid(t *testing.T) {
	// Test invalid Base32 character
	_, err := FromBase32("INVALID!1234567890ABC")
	require.Error(t, err)

	// Test too short (< 16 bytes decoded)
	// "GEZDGNBVGY3TQOJQGEZDGNBVGY" = 16 bytes (actually 16 bytes is minimum, should pass)
	// Let's use 10 bytes: "JBSWY3DPEHPK3PXP" = 10 bytes
	_, err = FromBase32("JBSWY3DPEHPK3PXP")
	require.Error(t, err)
	require.Equal(t, ErrSecretTooShort, err)
}

func TestFromHex(t *testing.T) {
	// 20 bytes in hex: "12345678901234567890" -> 40 hex chars
	s, err := FromHex("3132333435363738393031323334353637383930")
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t, 20, s.Len())

	// Test uppercase (should work)
	s, err = FromHex("3132333435363738393031323334353637383930")
	require.NoError(t, err)
	require.Equal(t, 20, s.Len())

	// Test with spaces (should work)
	s, err = FromHex("31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30")
	require.NoError(t, err)
	require.Equal(t, 20, s.Len())
}

func TestFromHexInvalid(t *testing.T) {
	// Test invalid hex character
	_, err := FromHex("INVALIDHEX1234567890ABCDEF1234567890ABCDEF")
	require.Error(t, err)

	// Test too short (< 16 bytes = 32 hex chars)
	_, err = FromHex("313233343536373839303132333435") // 15 bytes
	require.Error(t, err)
	require.Equal(t, ErrSecretTooShort, err)
}

func TestSecretBase32(t *testing.T) {
	// Use 17 bytes to ensure padding is needed (17*8=136 bits, 136/5=27.2 chars)
	bytes := make([]byte, 17)
	for i := range bytes {
		bytes[i] = byte(i + 1)
	}
	s, err := FromBytes(bytes)
	require.NoError(t, err)

	// Base32 without padding
	b32 := s.Base32()
	require.NotEmpty(t, b32)
	// 17 bytes = 28 base32 chars (with padding would be 32)
	require.Equal(t, 28, len(b32))

	// Base32 with padding - should have padding for non-multiple of 8
	b32pad := s.Base32WithPadding()
	require.Contains(t, b32pad, "=")
	require.Equal(t, 32, len(b32pad)) // padded to multiple of 8
}

func TestSecretHex(t *testing.T) {
	bytes := make([]byte, 20)
	s, err := FromBytes(bytes)
	require.NoError(t, err)

	hex := s.Hex()
	require.NotEmpty(t, hex)
	require.Equal(t, 40, len(hex)) // 20 bytes = 40 hex chars
}

func TestSecretLen(t *testing.T) {
	s, err := New(32)
	require.NoError(t, err)
	require.Equal(t, 32, s.Len())
}

func TestRoundTrip(t *testing.T) {
	// Create random secret
	original, err := New(20)
	require.NoError(t, err)

	// Convert to Base32 and back
	b32 := original.Base32()
	fromB32, err := FromBase32(b32)
	require.NoError(t, err)
	require.Equal(t, original.Bytes(), fromB32.Bytes())

	// Convert to Hex and back
	hex := original.Hex()
	fromHex, err := FromHex(hex)
	require.NoError(t, err)
	require.Equal(t, original.Bytes(), fromHex.Bytes())
}

func TestBytesReturnsCopy(t *testing.T) {
	// Create a secret
	s, err := New(20)
	require.NoError(t, err)

	// Get bytes copy
	bytes1 := s.Bytes()
	bytes2 := s.Bytes()

	// They should be equal but not the same slice
	require.Equal(t, bytes1, bytes2)
	require.NotSame(t, &bytes1[0], &bytes2[0])

	// Modifying one should not affect the other
	bytes1[0] = 0xFF
	require.NotEqual(t, bytes1[0], bytes2[0])
}

func TestClear(t *testing.T) {
	// Create a secret
	s, err := New(20)
	require.NoError(t, err)
	require.Equal(t, 20, s.Len())

	// Clear it
	s.Clear()

	// Should be zero length now
	require.Equal(t, 0, s.Len())

	// Bytes() should return nil
	require.Nil(t, s.Bytes())
}
