package stfe

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/system-transparency/stfe/trillian"
	"github.com/system-transparency/stfe/types"
)

// StateManager coordinates access to the log's tree heads and (co)signatures
type StateManager interface {
	Latest(context.Context) (*types.SignedTreeHead, error)
	ToSign(context.Context) (*types.SignedTreeHead, error)
	Cosigned(context.Context) (*types.SignedTreeHead, error)
	AddCosignature(context.Context, ed25519.PublicKey, *[types.SignatureSize]byte) error
	Run(context.Context)
}

// StateManagerSingle implements the StateManager interface.  It is assumed that
// the log server is running on a single-instance machine.  So, no coordination.
type StateManagerSingle struct {
	client   *trillian.Client
	signer   crypto.Signer
	interval time.Duration
	deadline time.Duration
	sync.RWMutex

	// cosigned is the current cosigned tree head that is being served
	cosigned types.SignedTreeHead

	// tosign is the current tree head that is being cosigned by witnesses
	tosign types.SignedTreeHead

	// cosignature keeps track of all cosignatures for the tosign tree head
	cosignature map[[types.HashSize]byte]*types.SigIdent
}

func NewStateManagerSingle(client *trillian.Client, signer crypto.Signer, interval, deadline time.Duration) (*StateManagerSingle, error) {
	sm := &StateManagerSingle{
		client:   client,
		signer:   signer,
		interval: interval,
		deadline: deadline,
	}

	ctx, _ := context.WithTimeout(context.Background(), sm.deadline)
	sth, err := sm.Latest(ctx)
	if err != nil {
		return nil, fmt.Errorf("Latest: %v", err)
	}

	sm.cosigned = *sth
	sm.tosign = *sth
	sm.cosignature = make(map[[types.HashSize]byte]*types.SigIdent)
	return sm, nil
}

func (sm *StateManagerSingle) Run(ctx context.Context) {
	schedule.Every(ctx, sm.interval, func(ctx context.Context) {
		ictx, _ := context.WithTimeout(ctx, sm.deadline)
		nextTreeHead, err := sm.Latest(ictx)
		if err != nil {
			glog.Warningf("rotate failed: Latest: %v", err)
			return
		}

		sm.Lock()
		defer sm.Unlock()
		sm.rotate(nextTreeHead)
	})
}

func (sm *StateManagerSingle) Latest(ctx context.Context) (*types.SignedTreeHead, error) {
	th, err := sm.client.GetTreeHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("LatestTreeHead: %v", err)
	}
	sth, err := sign(sm.signer, th)
	if err != nil {
		return nil, fmt.Errorf("sign: %v", err)
	}
	return sth, nil
}

func (sm *StateManagerSingle) ToSign(_ context.Context) (*types.SignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	return &sm.tosign, nil
}

func (sm *StateManagerSingle) Cosigned(_ context.Context) (*types.SignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	return &sm.cosigned, nil
}

func (sm *StateManagerSingle) AddCosignature(_ context.Context, vk ed25519.PublicKey, sig *[types.SignatureSize]byte) error {
	sm.Lock()
	defer sm.Unlock()

	if msg := sm.tosign.TreeHead.Marshal(); !ed25519.Verify(vk, msg, sig[:]) {
		return fmt.Errorf("invalid signature for tree head with timestamp: %d", sm.tosign.Timestamp)
	}
	witness := types.Hash(vk[:])
	if _, ok := sm.cosignature[*witness]; ok {
		return fmt.Errorf("signature-signer pair is a duplicate")
	}
	sm.cosignature[*witness] = &types.SigIdent{
		Signature: sig,
		KeyHash:   witness,
	}

	glog.V(3).Infof("accepted new cosignature from witness: %x", *witness)
	return nil
}

// rotate rotates the log's cosigned and stable STH.  The caller must aquire the
// source's read-write lock if there are concurrent reads and/or writes.
func (sm *StateManagerSingle) rotate(next *types.SignedTreeHead) {
	if reflect.DeepEqual(sm.cosigned.TreeHead, sm.tosign.TreeHead) {
		for _, sigident := range sm.cosigned.SigIdent[1:] { // skip log sigident
			if _, ok := sm.cosignature[*sigident.KeyHash]; !ok {
				sm.cosignature[*sigident.KeyHash] = sigident
			}
		}
	}
	// cosignatures will contain all cosignatures (even if repeated tree head)
	var cosignatures []*types.SigIdent
	for _, sigident := range sm.cosignature {
		cosignatures = append(cosignatures, sigident)
	}

	// Update cosigned tree head
	sm.cosigned.TreeHead = sm.tosign.TreeHead
	sm.cosigned.SigIdent = append(sm.tosign.SigIdent, cosignatures...)

	// Update to-sign tree head
	sm.tosign = *next
	sm.cosignature = make(map[[types.HashSize]byte]*types.SigIdent)
	glog.V(3).Infof("rotated sth")
}

func sign(signer crypto.Signer, th *types.TreeHead) (*types.SignedTreeHead, error) {
	sig, err := signer.Sign(nil, th.Marshal(), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("Sign: %v", err)
	}

	sigident := types.SigIdent{
		KeyHash:   types.Hash(signer.Public().(ed25519.PublicKey)[:]),
		Signature: &[types.SignatureSize]byte{},
	}
	copy(sigident.Signature[:], sig)
	return &types.SignedTreeHead{
		TreeHead: *th,
		SigIdent: []*types.SigIdent{
			&sigident,
		},
	}, nil
}
