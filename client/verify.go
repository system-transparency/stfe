package client

import (
	"fmt"
	"reflect"

	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/system-transparency/stfe/types"
)

func VerifySignedTreeHeadV1(namespace *types.Namespace, sth *types.StItem) error {
	if got, want := &sth.SignedTreeHeadV1.Signature.Namespace, namespace; !reflect.DeepEqual(got, want) {
		return fmt.Errorf("unexpected log id: %v", want)
	}
	th, err := types.Marshal(sth.SignedTreeHeadV1.TreeHead)
	if err != nil {
		return fmt.Errorf("Marshal: %v", err)
	}
	if err := namespace.Verify(th, sth.SignedTreeHeadV1.Signature.Signature); err != nil {
		return fmt.Errorf("Verify: %v", err)
	}
	return nil
}

func VerifyConsistencyProofV1(proof, first, second *types.StItem) error {
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

func VerifyInclusionProofV1(proof, sth *types.StItem, leafHash []byte) error {
	path := make([][]byte, 0, len(proof.InclusionProofV1.InclusionPath))
	for _, nh := range proof.InclusionProofV1.InclusionPath {
		path = append(path, nh.Data)
	}
	return merkle.NewLogVerifier(rfc6962.DefaultHasher).VerifyInclusionProof(
		int64(proof.InclusionProofV1.LeafIndex),
		int64(proof.InclusionProofV1.TreeSize),
		path,
		sth.SignedTreeHeadV1.TreeHead.RootHash.Data,
		leafHash,
	)
}
