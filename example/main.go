// Package main demonstrates a basic TOTP setup flow.
//
// This is the original example from the library. For comprehensive examples
// covering all features, see the sub-directories:
//
//	go run ./example/secret/main.go   — Secret management
//	go run ./example/hotp/main.go     — HOTP (counter-based) OTP
//	go run ./example/totp/main.go     — TOTP (time-based) OTP
//	go run ./example/otp/main.go      — Core package (Key, URI, algorithms)
//
// Run this example: go run ./example/main.go
//
// Feature highlights across examples:
//
//	TOTP:  ValidateCustomResult, SkewPolicy, AfterStep (replay), ExtraParams,
//	       IssuerInLabelOmit, GoogleAuthenticatorCompat, CounterWithT0/RemainingWithT0
//	HOTP:  Window validation, AfterCounter (replay), ExtraParams, IssuerInLabelOmit,
//	       GoogleAuthenticatorCompat, NFKC normalization
//	OTP:   Algorithm aliases (SHA-256, SHA2-256, SSL3-SHA1), HashChecked, GetExtraParam,
//	       ValidationResult, Steam Guard encoder
//	Secret: New/FromBase32/FromHex/FromBytes, Clear(), Bytes() (independent copy)
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"image/png"
	"os"

	"github.com/unitsvc/otp"
	"github.com/unitsvc/otp/totp"
)

func display(key *otp.Key, data []byte) {
	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	fmt.Println("Writing PNG to qr-code.png....")
	os.WriteFile("qr-code.png", data, 0644)
	fmt.Println("")
	fmt.Println("Please add your TOTP to your OTP Application now!")
	fmt.Println("")
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return text
}

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
	})
	if err != nil {
		panic(err)
	}

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	// Display the QR code to the user
	display(key, buf.Bytes())

	// Now Validate that the user's successfully added the passcode
	fmt.Println("Validating TOTP...")
	passcode := promptForPasscode()
	if totp.Validate(passcode, key.Secret()) {
		println("Valid passcode!")
		os.Exit(0)
	} else {
		println("Invalid passcode!")
		os.Exit(1)
	}
}
