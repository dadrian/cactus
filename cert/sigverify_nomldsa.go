//go:build !mldsa

package cert

var mldsaVerificationAvailable = false

func verifyMLDSA(SignatureAlgorithm, []byte, []byte, []byte) error {
	return ErrUnsupportedAlgorithm
}
