//go:build mldsa

package cert

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var mldsaVerificationAvailable = true

func verifyMLDSA(alg SignatureAlgorithm, publicKey, msg, sig []byte) error {
	switch alg {
	case AlgMLDSA44:
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return fmt.Errorf("cert: parse ML-DSA-44 public key: %w", err)
		}
		if !mldsa44.Verify(&pk, msg, nil, sig) {
			return errors.New("cert: ML-DSA-44 signature did not verify")
		}
		return nil
	case AlgMLDSA65:
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return fmt.Errorf("cert: parse ML-DSA-65 public key: %w", err)
		}
		if !mldsa65.Verify(&pk, msg, nil, sig) {
			return errors.New("cert: ML-DSA-65 signature did not verify")
		}
		return nil
	default:
		return ErrUnsupportedAlgorithm
	}
}
