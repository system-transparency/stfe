package x509util

import (
	"fmt"

	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// LoadCertificates loads a PEM-encoded list of certificates from file
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading certificate chain: %v", err)
	}
	return NewCertificateList(pem)
}

// LoadTrustAnchors loads a list of PEM-encoded certificates from file
func LoadTrustAnchors(path string) ([]*x509.Certificate, *x509.CertPool, error) {
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading trust anchors: %v", err)
	}
	anchorList, err := NewCertificateList(pem)
	if err != nil || len(anchorList) == 0 {
		return nil, nil, fmt.Errorf("failed parsing trust anchors: %v", err)
	}
	return anchorList, NewCertPool(anchorList), nil
}

// LoadEd25519SigningKey loads an Ed25519 private key from a given path
func LoadEd25519SigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading private key: %v", err)
	}
	return NewEd25519PrivateKey(data)
}

// NewCertificateList parses a block of PEM-encoded certificates
func NewCertificateList(rest []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected pem block type: %v", block.Type)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing x509 certificate: %v", err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// NewCertPool returns a new cert pool from a list of certificates
func NewCertPool(certificates []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

// NewEd25519PrivateKey creates a new ed25519 private-key from a PEM block
func NewEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem block: is empty")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("bad pem block type: %v", block.Type)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("pem block: trailing data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Errorf("x509 parser failed: %v", err)
	}
	switch t := key.(type) {
	case ed25519.PrivateKey:
		return key.(ed25519.PrivateKey), nil
	default:
		return nil, fmt.Errorf("unexpected signing key type: %v", t)
	}
}

// ParseDerChain parses a list of DER-encoded X.509 certificates, such that the
// first (zero-index) string is interpretted as an end-entity certificate and
// the remaining ones as the an intermediate CertPool.
func ParseDerChain(chain [][]byte) (*x509.Certificate, *x509.CertPool, error) {
	certificates, err := ParseDerList(chain)
	if err != nil || len(certificates) == 0 {
		return nil, nil, err
	}
	intermediatePool := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediatePool.AddCert(certificate)
	}
	return certificates[0], intermediatePool, nil
}

// ParseDerList parses a list of DER-encoded certificates
func ParseDerList(certificates [][]byte) ([]*x509.Certificate, error) {
	ret := make([]*x509.Certificate, 0, len(certificates))
	for _, der := range certificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate decoding failed: %v", err)
		}
		ret = append(ret, c)
	}
	return ret, nil
}

// VerifyChain checks whether the listed certificates are chained such
// that the first is signed by the second, the second by the third, etc.
func VerifyChain(chain []*x509.Certificate) error {
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return err
		}
	}
	return nil
}
