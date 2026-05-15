//go:build mldsa

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
)

func verifyCSRSignature(csr *x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err == nil {
		return nil
	}
	return verifyMLDSACSRSignature(csr)
}

func verifyMLDSACSRSignature(csr *x509.CertificateRequest) error {
	var req struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(csr.Raw, &req); err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(csr.RawSubjectPublicKeyInfo, &spki); err != nil {
		return fmt.Errorf("parse CSR SPKI: %w", err)
	}
	if !req.Algorithm.Algorithm.Equal(spki.Algorithm.Algorithm) {
		return fmt.Errorf("CSR signature algorithm %s does not match SPKI algorithm %s",
			req.Algorithm.Algorithm.String(), spki.Algorithm.Algorithm.String())
	}

	msg := csr.RawTBSCertificateRequest
	if len(msg) == 0 {
		msg = req.TBS.FullBytes
	}
	sig, err := bitStringBytes(req.Signature, "CSR signature")
	if err != nil {
		return err
	}
	pub, err := bitStringBytes(spki.PublicKey, "CSR public key")
	if err != nil {
		return err
	}

	switch {
	case req.Algorithm.Algorithm.Equal(oidMLDSA44):
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("parse ML-DSA-44 CSR public key: %w", err)
		}
		if !mldsa44.Verify(&pk, msg, nil, sig) {
			return errors.New("ML-DSA-44 CSR signature did not verify")
		}
		return nil
	case req.Algorithm.Algorithm.Equal(oidMLDSA65):
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("parse ML-DSA-65 CSR public key: %w", err)
		}
		if !mldsa65.Verify(&pk, msg, nil, sig) {
			return errors.New("ML-DSA-65 CSR signature did not verify")
		}
		return nil
	default:
		return fmt.Errorf("x509: cannot verify signature: algorithm unimplemented")
	}
}

func bitStringBytes(b asn1.BitString, name string) ([]byte, error) {
	if b.BitLength != len(b.Bytes)*8 {
		return nil, fmt.Errorf("%s BIT STRING has unused bits", name)
	}
	return b.Bytes, nil
}
