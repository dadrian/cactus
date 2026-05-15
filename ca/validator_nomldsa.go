//go:build !mldsa

package ca

import "crypto/x509"

func verifyCSRSignature(csr *x509.CertificateRequest) error {
	return csr.CheckSignature()
}
