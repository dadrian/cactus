//go:build mldsa

package cert

import (
	"bytes"
	"testing"

	"github.com/letsencrypt/cactus/signer"
)

func TestVerifyMTCSignatureMLDSA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signer   signer.Algorithm
		verifier SignatureAlgorithm
	}{
		{name: "mldsa-44", signer: signer.AlgMLDSA44, verifier: AlgMLDSA44},
		{name: "mldsa-65", signer: signer.AlgMLDSA65, verifier: AlgMLDSA65},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := bytes.Repeat([]byte{0x42}, signer.SeedSize)
			sgn, err := signer.FromSeed(tc.signer, seed)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("test message")
			sigBytes, err := sgn.Sign(nil, msg)
			if err != nil {
				t.Fatal(err)
			}
			key := CosignerKey{
				ID:        TrustAnchorID("test.cosigner"),
				Algorithm: tc.verifier,
				PublicKey: sgn.PublicKey(),
			}
			sig := MTCSignature{
				CosignerID: TrustAnchorID("test.cosigner"),
				Signature:  sigBytes,
			}
			if err := VerifyMTCSignature(key, sig, msg); err != nil {
				t.Errorf("verify: %v", err)
			}
			bad := append([]byte(nil), msg...)
			bad[0] ^= 1
			if err := VerifyMTCSignature(key, sig, bad); err == nil {
				t.Error("expected verify to fail with tampered message")
			}
		})
	}
}
