# otp

[![Go Reference](https://pkg.go.dev/badge/github.com/unitsvc/otp.svg)](https://pkg.go.dev/github.com/unitsvc/otp) [![Go Report Card](https://goreportcard.com/badge/github.com/unitsvc/otp)](https://goreportcard.com/report/github.com/unitsvc/otp) [![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://go.dev/) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A Go library for generating and validating **One-Time Passwords** (OTPs), implementing [HOTP (RFC 4226)](https://tools.ietf.org/html/rfc4226) and [TOTP (RFC 6238)](https://tools.ietf.org/html/rfc6238).

## Features

- **HOTP** — Counter-based OTP (RFC 4226)
- **TOTP** — Time-based OTP (RFC 6238)
- **10 hash algorithms** — SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, MD5
- **Steam Guard** encoder support
- **Secret management** — Generate, import (Base32/Hex/Bytes), and securely clear secrets
- **QR code generation** — For authenticator app enrollment
- **Replay protection** — Prevent re-use of previously accepted OTPs
- **Unicode NFKC normalization** — Fullwidth digit support for international users
- **RFC-compliant defaults** — SHA1/6-digit/30s for Google Authenticator compatibility
- **Security guardrails** — HTTPS-only image URLs, parameter injection prevention, window/digit/period limits

## Install

```bash
go get github.com/unitsvc/otp
```

## Quick Start

### TOTP — Generate and Validate

```go
package main

import (
    "fmt"
    "time"

    "github.com/unitsvc/otp/totp"
)

func main() {
    // Generate a new TOTP key
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "Example",
        AccountName: "user@example.com",
    })
    if err != nil {
        panic(err)
    }

    // Display the secret and QR code
    fmt.Println("Secret:", key.Secret())

    // Validate a passcode
    passcode := "123456" // user-provided
    valid := totp.Validate(passcode, key.Secret())
    fmt.Println("Valid:", valid)
}
```

### HOTP — Counter-based

```go
key, _ := hotp.Generate(hotp.GenerateOpts{
    Issuer:      "Example",
    AccountName: "user@example.com",
})

code, _ := hotp.GenerateCode(key.Secret(), 0)
valid := hotp.Validate(code, 0, key.Secret())
```

### Secret Management

```go
// Generate a random 20-byte secret
sec, _ := secret.New(20)
fmt.Println(sec.Base32())  // JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP

// Import from Base32
sec, _ = secret.FromBase32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")

// Securely clear when done
sec.Clear()
```

## API Reference

### Core Types (`otp` package)

| Type              | Description                                                                                                                                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Algorithm`       | Hash algorithm: `AlgorithmSHA1`, `AlgorithmSHA256`, `AlgorithmSHA512`, `AlgorithmSHA224`, `AlgorithmSHA384`, `AlgorithmSHA3_224`, `AlgorithmSHA3_256`, `AlgorithmSHA3_384`, `AlgorithmSHA3_512`, `AlgorithmMD5` |
| `AlgorithmCompat` | Alias for `AlgorithmSHA1` (Google Authenticator compatible)                                                                                                                                                     |
| `AlgorithmSecure` | Alias for `AlgorithmSHA256` (recommended)                                                                                                                                                                       |
| `Digits`          | Digit count: `DigitsSix` (default), `DigitsEight`                                                                                                                                                               |
| `Encoder`         | Output format: `EncoderDefault`, `EncoderSteam`                                                                                                                                                                 |
| `Key`             | Represents an OTP key with methods: `Secret()`, `Issuer()`, `AccountName()`, `Algorithm()`, `Digits()`, `Period()`, `Counter()`, `URL()`, `Image()`, `ImageURL()`                                               |

```go
algo, _ := otp.ParseAlgorithm("SHA256")     // parse from string
key, _ := otp.NewKeyFromURL("otpauth://...")  // parse otpauth URI
```

### TOTP (`totp` package)

| Function                                                                                | Description                                  |
| --------------------------------------------------------------------------------------- | -------------------------------------------- |
| `Validate(passcode, secret string) bool`                                                | Validate with defaults (SHA1, 30s, 6 digits) |
| `ValidateSecure(passcode, secret string) bool`                                          | Validate with SHA256                         |
| `GenerateCode(secret string, t time.Time) (string, error)`                              | Generate code with defaults                  |
| `GenerateCodeCustom(secret string, t time.Time, opts ValidateOpts) (string, error)`     | Generate with custom opts                    |
| `ValidateCustom(passcode, secret string, t time.Time, opts ValidateOpts) (bool, error)` | Validate with custom opts                    |
| `ValidateCustomStep(...)`                                                               | Validate and return the matched time step    |
| `ValidateCustomSkewPolicy(...)`                                                         | Validate with asymmetric past/future skew    |
| `ValidateRFCCompliant(...)`                                                             | RFC 6238-compliant validation                |
| `Generate(opts GenerateOpts) (*otp.Key, error)`                                         | Create a new TOTP key                        |
| `Counter(period uint, t time.Time) uint64`                                              | Calculate time-step counter                  |
| `Remaining(period uint, t time.Time) uint64`                                            | Milliseconds until next rotation             |

```go
// Custom algorithm and digits
code, _ := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
    Period:    60,
    Digits:    otp.DigitsEight,
    Algorithm: otp.AlgorithmSHA512,
})

// Replay protection — reject codes from steps already used
valid, step, _ := totp.ValidateCustomStep(code, secret, time.Now(), totp.ValidateOpts{
    Period:    30,
    AfterStep: lastUsedStep, // zero-value = disabled
})
```

### HOTP (`hotp` package)

| Function                                                                                                               | Description                              |
| ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `Validate(passcode string, counter uint64, secret string) bool`                                                        | Validate with defaults                   |
| `GenerateCode(secret string, counter uint64) (string, error)`                                                          | Generate code                            |
| `GenerateCodeCustom(secret string, counter uint64, opts ValidateOpts) (string, error)`                                 | Generate with custom opts                |
| `ValidateCustomWindow(passcode string, counter uint64, secret string, opts ValidateOptsWithWindow) (int, bool, error)` | Window validation with replay protection |
| `Generate(opts GenerateOpts) (*otp.Key, error)`                                                                        | Create a new HOTP key                    |

```go
// Window validation with replay protection
delta, found, _ := hotp.ValidateCustomWindow(code, expectedCounter, secret,
    hotp.ValidateOptsWithWindow{
        Window:       2,
        AfterCounter: lastUsedCounter, // reject counters <= this value
    })
```

### Secret (`secret` package)

| Function                                | Description                 |
| --------------------------------------- | --------------------------- |
| `New(size int) (*Secret, error)`        | Random secret (16–64 bytes) |
| `FromBytes(b []byte) (*Secret, error)`  | From raw bytes (copied)     |
| `FromBase32(s string) (*Secret, error)` | From Base32 string          |
| `FromHex(s string) (*Secret, error)`    | From hex string             |

`Secret` methods: `Bytes()`, `Base32()`, `Base32WithPadding()`, `Hex()`, `Len()`, `Clear()`

## Advanced Usage

### QR Code Enrollment

```go
key, _ := totp.Generate(totp.GenerateOpts{
    Issuer:      "MyApp",
    AccountName: "alice@example.com",
    ImageURL:    "https://myapp.com/logo.png", // HTTPS required
})

// Generate 200x200 QR code image
img, _ := key.Image(200, 200)
```

### Steam Guard

```go
code, _ := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
    Digits: 5,
    Encoder: otp.EncoderSteam,
})
```

### Unicode NFKC Normalization

```go
// Accepts fullwidth digits: ＡＢＣ１２３ → ABC123
valid, _ := hotp.ValidateCustomNormalized(passcode, counter, secret, opts)
```

### URI Generation with Custom Parameters

```go
key, _ := totp.Generate(totp.GenerateOpts{
    Issuer:      "MyApp",
    AccountName: "user@example.com",
    Algorithm:   otp.AlgorithmSHA256,
    Digits:      otp.DigitsEight,
    Period:      60,
    SecretSize:  32,
})
// URI omits default params (SHA1, 6 digits, 30s) for compact QR codes
fmt.Println(key.URL())
// otpauth://totp/MyApp:user@example.com?algorithm=SHA256&digits=8&period=60&...
```

## Algorithm Support

| Algorithm           | Digest Size | Notes                                              |
| ------------------- | ----------- | -------------------------------------------------- |
| `AlgorithmSHA1`     | 20 bytes    | Default; Google Authenticator compatible           |
| `AlgorithmSHA256`   | 32 bytes    | Recommended for new deployments                    |
| `AlgorithmSHA512`   | 64 bytes    |                                                    |
| `AlgorithmSHA224`   | 28 bytes    |                                                    |
| `AlgorithmSHA384`   | 48 bytes    |                                                    |
| `AlgorithmSHA3-224` | 28 bytes    |                                                    |
| `AlgorithmSHA3-256` | 32 bytes    |                                                    |
| `AlgorithmSHA3-384` | 48 bytes    |                                                    |
| `AlgorithmSHA3-512` | 64 bytes    |                                                    |
| `AlgorithmMD5`      | 16 bytes    | Rejected — digest too small for dynamic truncation |

Aliases: `ParseAlgorithm` accepts `"SHA-256"`, `"SHA2-256"`, `"SSL3-SHA1"` etc.

## Examples

See the [`example/`](./example) directory for complete working programs:

- [`example/main.go`](./example/main.go) — Basic TOTP enrollment with QR code
- [`example/totp/`](./example/totp/) — TOTP features (algorithms, skew, Steam, validation)
- [`example/hotp/`](./example/hotp/) — HOTP features (counter, window, replay protection)
- [`example/otp/`](./example/otp/) — Core types (algorithms, digits, encoders, URI parsing)
- [`example/secret/`](./example/secret/) — Secret management (generate, import, clear)

## Security Considerations

- **Secrets are validated** to be 16–64 bytes per RFC 4226 Section 4
- **Image URLs must be HTTPS** — HTTP, javascript:, and file:// are rejected
- **Parameter injection is prevented** — `&` and `=` in values are percent-encoded
- **Window/digit/period limits** — Prevent misconfiguration (e.g., window > 10)
- **Replay protection** — `AfterCounter`/`AfterStep` prevent OTP re-use
- **`Secret.Clear()`** — Zeros the internal buffer when no longer needed
- **`Secret.Bytes()`** — Returns a copy; mutating does not affect the original
- **MD5 is rejected** — 16-byte digest is too small for the dynamic truncation algorithm

## Compatibility

Compatible with all major authenticator apps:

- Google Authenticator
- Microsoft Authenticator
- Authy
- FreeOTP
- andOTP / Aegis
- 1Password

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
