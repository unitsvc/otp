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

package internal

import (
	"golang.org/x/text/unicode/norm"
)

// NormalizeNFKC applies Unicode NFKC (Normalization Form Compatibility Composition)
// to the input string. This is useful for handling fullwidth characters and other
// Unicode compatibility variants that users might input.
//
// For example, Japanese fullwidth characters like "ｊｓ１２３４５" are normalized
// to their ASCII equivalents "js12345", making validation work correctly for
// international users.
//
// NFKC normalization:
// - Converts compatibility characters to their canonical equivalents
// - Composes characters where possible
// - Preserves semantic meaning while standardizing representation
//
// This function is optional and should be used when:
// - Users might input OTP codes via methods that produce fullwidth characters
// - Supporting international users who use different input methods
// - Ensuring consistent comparison regardless of input method
func NormalizeNFKC(s string) string {
	return norm.NFKC.String(s)
}
