package stfe

import (
	"fmt"

	"crypto/ed25519"
	"net/http"

	"github.com/system-transparency/stfe/types"
)

func (lp *LogParameters) parseAddEntryV1Request(r *http.Request) (*types.Leaf, error) {
	var req types.LeafRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	if pub, msg, sig := ed25519.PublicKey(req.VerificationKey[:]), req.Message.Marshal(), req.Signature[:]; !ed25519.Verify(pub, msg, sig) {
		return nil, fmt.Errorf("Invalid signature")
	}
	// TODO: check shard hint
	// TODO: check domain hint
	return &types.Leaf{
		Message: req.Message,
		SigIdent: types.SigIdent{
			Signature: req.Signature,
			KeyHash:   types.Hash(req.VerificationKey[:]),
		},
	}, nil
}

func (lp *LogParameters) parseAddCosignatureRequest(r *http.Request) (*types.CosignatureRequest, error) {
	var req types.CosignatureRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("unpackOctetPost: %v", err)
	}
	if _, ok := lp.Witnesses[*req.KeyHash]; !ok {
		return nil, fmt.Errorf("Unknown witness: %x", req.KeyHash)
	}
	return &req, nil
}

func (lp *LogParameters) parseGetConsistencyProofRequest(r *http.Request) (*types.ConsistencyProofRequest, error) {
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

func (lp *LogParameters) parseGetProofByHashRequest(r *http.Request) (*types.InclusionProofRequest, error) {
	var req types.InclusionProofRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if req.TreeSize < 1 {
		return nil, fmt.Errorf("TreeSize(%d) must be larger than zero", req.TreeSize)
	}
	return &req, nil
}

func (lp *LogParameters) parseGetEntriesRequest(r *http.Request) (*types.LeavesRequest, error) {
	var req types.LeavesRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	if req.StartSize > req.EndSize {
		return nil, fmt.Errorf("StartSize(%d) must be less than or equal to EndSize(%d)", req.StartSize, req.EndSize)
	}
	if req.EndSize-req.StartSize+1 > uint64(lp.MaxRange) {
		req.EndSize = req.StartSize + uint64(lp.MaxRange) - 1
	}
	return &req, nil
}
