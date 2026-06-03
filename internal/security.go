package internal

// ZeroBytes clears a byte slice by filling it with zeros.
// This is used to minimize the window during which sensitive key material
// remains in memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
