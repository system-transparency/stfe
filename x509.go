package stfe

import (
	"fmt"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/google/certificate-transparency-go/tls"
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

func LoadEd25519SigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading private key: %v", err)
	}

	var block *pem.Block
	block, data = pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key not loaded")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("trailing data found after key: %v", data)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing signing key: %v", err)
	}

	switch t := key.(type) {
	case ed25519.PrivateKey:
		return key.(ed25519.PrivateKey), nil
	default:
		return nil, fmt.Errorf("unexpected signing key type: %v", t)
	}
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

func GenV1SDI(ld *LogParameters, leaf []byte) (StItem, error) {
	// Note that ed25519 does not use the passed io.Reader
	sig, err := ld.Signer.Sign(rand.Reader, leaf, crypto.Hash(0))
	if err != nil {
		return StItem{}, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	return NewSignedDebugInfoV1(ld.LogId, []byte("reserved"), sig), nil
}

func GenV1STH(ld *LogParameters, th TreeHeadV1) (StItem, error) {
	serialized, err := tls.Marshal(th)
	if err != nil {
		return StItem{}, fmt.Errorf("failed tls marshaling tree head: %v", err)
	}

	// Note that ed25519 does not use the passed io.Reader
	sig, err := ld.Signer.Sign(rand.Reader, serialized, crypto.Hash(0))
	if err != nil {
		return StItem{}, fmt.Errorf("ed25519 signature failed: %v", err)
	}
	return NewSignedTreeHeadV1(th, ld.LogId, sig), nil
}
