package client

import (
	"fmt"

	"crypto"
	"crypto/ed25519"
	"crypto/tls"

	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe"
)

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

// VerifyConsistencyProofV1 verifies that a consistency proof is valid without
// checking any sth signature
func VerifyConsistencyProofV1(proof, first, second *stfe.StItem) error {
	path := make([][]byte, 0, len(proof.ConsistencyProofV1.ConsistencyPath))
	for _, nh := range proof.ConsistencyProofV1.ConsistencyPath {
		path = append(path, nh.Data)
	}
	return merkle.NewLogVerifier(rfc6962.DefaultHasher).VerifyConsistencyProof(
		int64(proof.ConsistencyProofV1.TreeSize1),
		int64(proof.ConsistencyProofV1.TreeSize2),
		first.SignedTreeHeadV1.TreeHead.RootHash.Data,
		second.SignedTreeHeadV1.TreeHead.RootHash.Data,
		path,
	)
}

// VerifyInclusionProofV1 verifies that an inclusion proof is valid without checking
// any sth signature
func VerifyInclusionProofV1(proof *stfe.StItem, rootHash, leafHash []byte) error {
	path := make([][]byte, 0, len(proof.InclusionProofV1.InclusionPath))
	for _, nh := range proof.InclusionProofV1.InclusionPath {
		path = append(path, nh.Data)
	}
	return merkle.NewLogVerifier(rfc6962.DefaultHasher).VerifyInclusionProof(
		int64(proof.InclusionProofV1.LeafIndex),
		int64(proof.InclusionProofV1.TreeSize),
		path,
		rootHash,
		leafHash,
	)
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
