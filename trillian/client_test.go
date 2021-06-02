package trillian

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/certificate-transparency-go/trillian/mockclient"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAddLeaf(t *testing.T) {
	req := &types.LeafRequest{
		Message: types.Message{
			ShardHint: 0,
			Checksum:  &[types.HashSize]byte{},
		},
		Signature:       &[types.SignatureSize]byte{},
		VerificationKey: &[types.VerificationKeySize]byte{},
		DomainHint:      "example.com",
	}
	for _, table := range []struct {
		description string
		req         *types.LeafRequest
		rsp         *trillian.QueueLeafResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: backend failure",
			req:         req,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			req:         req,
			wantErr:     true,
		},
		{
			description: "invalid: no queued leaf",
			req:         req,
			rsp:         &trillian.QueueLeafResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: leaf is already queued or included",
			req:         req,
			rsp: &trillian.QueueLeafResponse{
				QueuedLeaf: &trillian.QueuedLogLeaf{
					Leaf: &trillian.LogLeaf{
						LeafValue: req.Message.Marshal(),
					},
					Status: status.New(codes.AlreadyExists, "duplicate").Proto(),
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			req:         req,
			rsp: &trillian.QueueLeafResponse{
				QueuedLeaf: &trillian.QueuedLogLeaf{
					Leaf: &trillian.LogLeaf{
						LeafValue: req.Message.Marshal(),
					},
					Status: status.New(codes.OK, "ok").Proto(),
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mockclient.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := Client{GRPC: grpc}

			err := client.AddLeaf(context.Background(), table.req)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
		}()
	}
}

func TestGetTreeHead(t *testing.T) {
	// valid root
	root := &ttypes.LogRootV1{
		TreeSize:       0,
		RootHash:       make([]byte, types.HashSize),
		TimestampNanos: 1622585623133599429,
	}
	buf, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("must marshal log root: %v", err)
	}
	// invalid root
	root.RootHash = make([]byte, types.HashSize+1)
	bufBadHash, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("must marshal log root: %v", err)
	}

	for _, table := range []struct {
		description string
		rsp         *trillian.GetLatestSignedLogRootResponse
		err         error
		wantErr     bool
		wantTh      *types.TreeHead
	}{
		{
			description: "invalid: backend failure",
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			wantErr:     true,
		},
		{
			description: "invalid: no signed log root",
			rsp:         &trillian.GetLatestSignedLogRootResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: no log root",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{},
			},
			wantErr: true,
		},
		{
			description: "invalid: no log root: unmarshal failed",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: buf[1:],
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: unexpected hash length",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: bufBadHash,
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: buf,
				},
			},
			wantTh: &types.TreeHead{
				Timestamp: 1622585623,
				TreeSize:  0,
				RootHash:  &[types.HashSize]byte{},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mockclient.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := Client{GRPC: grpc}

			th, err := client.GetTreeHead(context.Background())
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := th, table.wantTh; !reflect.DeepEqual(got, want) {
				t.Errorf("got tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	req := &types.ConsistencyProofRequest{
		OldSize: 1,
		NewSize: 3,
	}
	for _, table := range []struct {
		description string
		req         *types.ConsistencyProofRequest
		rsp         *trillian.GetConsistencyProofResponse
		err         error
		wantErr     bool
		wantProof   *types.ConsistencyProof
	}{
		{
			description: "invalid: backend failure",
			req:         req,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			req:         req,
			wantErr:     true,
		},
		{
			description: "invalid: no consistency proof",
			req:         req,
			rsp:         &trillian.GetConsistencyProofResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: not a consistency proof (1/2)",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{},
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: not a consistency proof (2/2)",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{
						make([]byte, types.HashSize),
						make([]byte, types.HashSize+1),
					},
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{
						make([]byte, types.HashSize),
						make([]byte, types.HashSize),
					},
				},
			},
			wantProof: &types.ConsistencyProof{
				OldSize: 1,
				NewSize: 3,
				Path: []*[types.HashSize]byte{
					&[types.HashSize]byte{},
					&[types.HashSize]byte{},
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mockclient.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := Client{GRPC: grpc}

			proof, err := client.GetConsistencyProof(context.Background(), table.req)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := proof, table.wantProof; !reflect.DeepEqual(got, want) {
				t.Errorf("got proof\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetInclusionProof(t *testing.T) {}
func TestGetLeaves(t *testing.T)         {}
