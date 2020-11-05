package x509util

import (
	"fmt"

	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// LoadTrustAnchors loads a list of PEM-encoded certificates from file
func LoadTrustAnchors(path string) ([]*x509.Certificate, *x509.CertPool, error) {
	rest, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading trust anchors: %v", err)
	}

	pool := x509.NewCertPool()
	var anchors []*x509.Certificate
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid trust anchor before rest(%s): %v", rest, err)
		}

		anchors = append(anchors, certificate)
		pool.AddCert(certificate)
	}

	if len(anchors) == 0 {
		return nil, nil, fmt.Errorf("found no valid trust anchor in: %s", path)
	}
	return anchors, pool, nil
}

// LoadEd25519SigningKey loads an Ed25519 private key from a given path
func LoadEd25519SigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading private key: %v", err)
	}
	return ParseEd25519PrivateKey(data)
}

// ParseEd25519PrivateKey parses a PEM-encoded private key block
func ParseEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
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

// LoadChain loads a PEM-encoded certificate chain from a given path
func LoadChain(path string) ([]*x509.Certificate, error) {
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading certificate chain: %v", err)
	}
	return ParseChain(blob)
}

// ParseChain parses a PEM-encoded certificate chain
func ParseChain(rest []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
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
		chain = append(chain, certificate)
	}
	return chain, nil
}

// ParseDerChain parses a list of DER-encoded X.509 certificates, such that the
// first (zero-index) string is interpretted as an end-entity certificate and
// the remaining ones as the an intermediate CertPool.
func ParseDerChain(chain [][]byte) (*x509.Certificate, *x509.CertPool, error) {
	certificates, err := ParseDerChainToList(chain)
	if err != nil || len(certificates) == 0 {
		return nil, nil, err
	}
	intermediatePool := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediatePool.AddCert(certificate)
	}
	return certificates[0], intermediatePool, nil
}

// ParseDerChainToList parses a list of DER-encoded certificates
func ParseDerChainToList(chain [][]byte) ([]*x509.Certificate, error) {
	ret := make([]*x509.Certificate, 0, len(chain))
	for _, der := range chain {
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
