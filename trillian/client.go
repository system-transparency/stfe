package trillian

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
	"google.golang.org/grpc/codes"
)

// Client is a wrapper around the Trillian gRPC client
type Client struct {
	// TreeID is a Merkle tree identifier that Trillian uses
	TreeID int64

	// GRPC is a Trillian gRPC client
	GRPC trillian.TrillianLogClient
}

func (c *Client) AddLeaf(ctx context.Context, req *types.LeafRequest) error {
	leaf := types.Leaf{
		Message: req.Message,
		SigIdent: types.SigIdent{
			Signature: req.Signature,
			KeyHash:   types.Hash(req.VerificationKey[:]),
		},
	}
	serialized := leaf.Marshal()

	glog.V(3).Infof("queueing leaf request: %x", types.HashLeaf(serialized))
	rsp, err := c.GRPC.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: c.TreeID,
		Leaf: &trillian.LogLeaf{
			LeafValue: serialized,
		},
	})
	if err != nil {
		return fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return fmt.Errorf("no response")
	}
	if rsp.QueuedLeaf == nil {
		return fmt.Errorf("no queued leaf")
	}
	if codes.Code(rsp.QueuedLeaf.GetStatus().GetCode()) == codes.AlreadyExists {
		return fmt.Errorf("leaf is already queued or included")
	}
	return nil
}

func (c *Client) GetTreeHead(ctx context.Context) (*types.TreeHead, error) {
	rsp, err := c.GRPC.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: c.TreeID,
	})
	if err != nil {
		return nil, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("no response")
	}
	if rsp.SignedLogRoot == nil {
		return nil, fmt.Errorf("no signed log root")
	}
	if rsp.SignedLogRoot.LogRoot == nil {
		return nil, fmt.Errorf("no log root")
	}
	var r ttypes.LogRootV1
	if err := r.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("no log root: unmarshal failed: %v", err)
	}
	if len(r.RootHash) != types.HashSize {
		return nil, fmt.Errorf("unexpected hash length: %d", len(r.RootHash))
	}

	var hash [types.HashSize]byte
	th := types.TreeHead{
		Timestamp: uint64(r.TimestampNanos / 1000 / 1000 / 1000),
		TreeSize:  uint64(r.TreeSize),
		RootHash:  &hash,
	}
	copy(th.RootHash[:], r.RootHash)
	return &th, nil
}

func (c *Client) GetConsistencyProof(ctx context.Context, req *types.ConsistencyProofRequest) (*types.ConsistencyProof, error) {
	return nil, fmt.Errorf("TODO")
}

func (c *Client) GetInclusionProof(ctx context.Context, req *types.InclusionProofRequest) (*types.InclusionProof, error) {
	return nil, fmt.Errorf("TODO")
}

func (c *Client) GetLeaves(ctx context.Context, req *types.LeavesRequest) (*types.LeafList, error) {
	return nil, fmt.Errorf("TODO")
}
