package client

import (
	"fmt"

	"crypto"
	"crypto/ed25519"
	"crypto/tls"

	"github.com/system-transparency/stfe"
)

// TODO: fix so that publicKey is already passed as crypto.PublicKey
//k, err := x509.ParsePKIXPublicKey(publicKey)
//if err != nil {
//	return fmt.Errorf("failed parsing public key: %v", err)
//}

func VerifySignedDebugInfoV1(sdi *stfe.StItem, scheme tls.SignatureScheme, key crypto.PublicKey, message []byte) error {
	if err := supportedScheme(scheme, key); err != nil {
		return err
	}
	if !ed25519.Verify(key.(ed25519.PublicKey), message, sdi.SignedDebugInfoV1.Signature) {
		return fmt.Errorf("bad signature")
	}
	return nil
}

// VerifySignedTreeHeadV1 verifies an STH signature
func VerifySignedTreeHeadV1(sth *stfe.StItem, scheme tls.SignatureScheme, key crypto.PublicKey) error {
	serialized, err := sth.SignedTreeHeadV1.TreeHead.Marshal()
	if err != nil {
		return fmt.Errorf("failed marshaling tree head: %v", err)
	}
	if err := supportedScheme(scheme, key); err != nil {
		return err
	}

	if !ed25519.Verify(key.(ed25519.PublicKey), serialized, sth.SignedTreeHeadV1.Signature) {
		return fmt.Errorf("bad signature")
	}
	return nil
}

// supportedScheme checks whether the client library supports the log's
// signature scheme and public key type
func supportedScheme(scheme tls.SignatureScheme, key crypto.PublicKey) error {
	if _, ok := key.(ed25519.PublicKey); ok && scheme == tls.Ed25519 {
		return nil
	}
	switch t := key.(type) {
	default:
		return fmt.Errorf("unsupported scheme(%v) and key(%v)", scheme, t)
	}
}
