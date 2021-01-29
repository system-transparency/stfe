package client

import (
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe"
)

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
