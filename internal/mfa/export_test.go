package mfa

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// generateForTest computes the code for an arbitrary step so window tests
// can name the previous and next codes without hard-coding more vectors.
func generateForTest(secret []byte, step int64) (string, error) {
	return hotp.GenerateCodeCustom(Base32Secret(secret), uint64(step),
		hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}
