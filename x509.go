package stfe

import (
	"fmt"

	"crypto/ecdsa"
	"crypto/rsa"
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

func VerifyChain(ld *LogParameters, certificate *x509.Certificate) ([]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots:     ld.AnchorPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // TODO: move to ld
	} // TODO: add intermediates

	chains, err := certificate.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("chain verification failed: %v", err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("chain verification failed: no chain")
	}
	return chains[0], nil // if we found multiple paths just pick the first one
}

func VerifySignature(leaf, signature []byte, certificate *x509.Certificate) error {
	var algo x509.SignatureAlgorithm
	switch t := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		algo = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		algo = x509.ECDSAWithSHA256
	default:
		return fmt.Errorf("unsupported public key algorithm: %v", t)
	}

	if err := certificate.CheckSignature(algo, leaf, signature); err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}
