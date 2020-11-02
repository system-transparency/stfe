package stfe

import (
	"fmt"

	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
)

func (sdi *SignedDebugInfoV1) Verify(scheme tls.SignatureScheme, publicKey, message []byte) error {
	if scheme != tls.Ed25519 {
		return fmt.Errorf("unsupported signature scheme: %v", scheme)
	}

	// TODO: fix so that publicKey is already passed as crypto.PublicKey
	k, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed parsing public key: %v", err)
	}

	switch t := k.(type) {
	case ed25519.PublicKey:
		vk := k.(ed25519.PublicKey)
		if !ed25519.Verify(vk, message, sdi.Signature) {
			return fmt.Errorf("invalid signature: PublicKey(%v) Message(%v) Signature(%v)", vk, message, sdi.Signature)
		}
		return nil
	default:
		return fmt.Errorf("Unsupported public key: %s", t)
	}
}
