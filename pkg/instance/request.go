package stfe

import (
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/system-transparency/stfe/pkg/types"
)

func (i *Instance) leafRequestFromHTTP(r *http.Request) (*types.LeafRequest, error) {
	var req types.LeafRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	vk := ed25519.PublicKey(req.VerificationKey[:])
	msg := req.Message.Marshal()
	sig := req.Signature[:]
	if !ed25519.Verify(vk, msg, sig) {
		return nil, fmt.Errorf("invalid signature")
	}
	// TODO: check shard hint
	// TODO: check domain hint
	return &req, nil
}

func (i *Instance) cosignatureRequestFromHTTP(r *http.Request) (*types.CosignatureRequest, error) {
	var req types.CosignatureRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if _, ok := i.Witnesses[*req.KeyHash]; !ok {
		return nil, fmt.Errorf("Unknown witness: %x", req.KeyHash)
	}
	return &req, nil
}

func (i *Instance) consistencyProofRequestFromHTTP(r *http.Request) (*types.ConsistencyProofRequest, error) {
	var req types.ConsistencyProofRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if req.OldSize < 1 {
		return nil, fmt.Errorf("OldSize(%d) must be larger than zero", req.OldSize)
	}
	if req.NewSize <= req.OldSize {
		return nil, fmt.Errorf("NewSize(%d) must be larger than OldSize(%d)", req.NewSize, req.OldSize)
	}
	return &req, nil
}

func (i *Instance) inclusionProofRequestFromHTTP(r *http.Request) (*types.InclusionProofRequest, error) {
	var req types.InclusionProofRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if req.TreeSize < 1 {
		return nil, fmt.Errorf("TreeSize(%d) must be larger than zero", req.TreeSize)
	}
	return &req, nil
}

func (i *Instance) leavesRequestFromHTTP(r *http.Request) (*types.LeavesRequest, error) {
	var req types.LeavesRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	if req.StartSize > req.EndSize {
		return nil, fmt.Errorf("StartSize(%d) must be less than or equal to EndSize(%d)", req.StartSize, req.EndSize)
	}
	if req.EndSize-req.StartSize+1 > uint64(i.MaxRange) {
		req.EndSize = req.StartSize + uint64(i.MaxRange) - 1
	}
	return &req, nil
}
