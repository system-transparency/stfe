package stfe

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"reflect"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
)

// SthSource provides access to the log's (co)signed tree heads
type SthSource interface {
	Latest(context.Context) (*types.SignedTreeHead, error)
	Stable(context.Context) (*types.SignedTreeHead, error)
	Cosigned(context.Context) (*types.SignedTreeHead, error)
	AddCosignature(context.Context, ed25519.PublicKey, *[types.SignatureSize]byte) error
	Run(context.Context)
}

// ActiveSthSource implements the SthSource interface for an STFE instance that
// accepts new logging requests, i.e., the log is running in read+write mode.
type ActiveSthSource struct {
	client        trillian.TrillianLogClient
	logParameters *LogParameters
	sync.RWMutex

	// cosigned is the current cosigned tree head that is served
	cosigned types.SignedTreeHead

	// tosign is the current tree head that is being cosigned
	tosign types.SignedTreeHead

	// cosignature keeps track of all collected cosignatures for tosign
	cosignature map[[types.HashSize]byte]*types.SigIdent
}

func NewActiveSthSource(cli trillian.TrillianLogClient, lp *LogParameters) (*ActiveSthSource, error) {
	s := ActiveSthSource{
		client:        cli,
		logParameters: lp,
	}

	ctx, _ := context.WithTimeout(context.Background(), lp.Deadline)
	sth, err := s.Latest(ctx)
	if err != nil {
		return nil, fmt.Errorf("Latest: %v", err)
	}

	s.cosigned = *sth
	s.tosign = *sth
	s.cosignature = make(map[[types.HashSize]byte]*types.SigIdent)
	return &s, nil
}

func (s *ActiveSthSource) Run(ctx context.Context) {
	schedule.Every(ctx, s.logParameters.Interval, func(ctx context.Context) {
		// get the next stable sth
		ictx, _ := context.WithTimeout(ctx, s.logParameters.Deadline)
		sth, err := s.Latest(ictx)
		if err != nil {
			glog.Warningf("cannot rotate without new sth: Latest: %v", err)
			return
		}
		// rotate
		s.Lock()
		defer s.Unlock()
		s.rotate(sth)
	})
}

func (s *ActiveSthSource) Latest(ctx context.Context) (*types.SignedTreeHead, error) {
	trsp, err := s.client.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: s.logParameters.TreeId,
	})
	var lr ttypes.LogRootV1
	if errInner := checkGetLatestSignedLogRoot(s.logParameters, trsp, err, &lr); errInner != nil {
		return nil, fmt.Errorf("invalid signed log root response: %v", errInner)
	}
	return s.logParameters.Sign(NewTreeHeadFromLogRoot(&lr))
}

func (s *ActiveSthSource) Stable(_ context.Context) (*types.SignedTreeHead, error) {
	s.RLock()
	defer s.RUnlock()
	return &s.tosign, nil
}

func (s *ActiveSthSource) Cosigned(_ context.Context) (*types.SignedTreeHead, error) {
	s.RLock()
	defer s.RUnlock()
	return &s.cosigned, nil
}

func (s *ActiveSthSource) AddCosignature(_ context.Context, vk ed25519.PublicKey, sig *[types.SignatureSize]byte) error {
	s.Lock()
	defer s.Unlock()

	if msg := s.tosign.TreeHead.Marshal(); !ed25519.Verify(vk, msg, sig[:]) {
		return fmt.Errorf("Invalid signature for tree head with timestamp: %d", s.tosign.TreeHead.Timestamp)
	}
	witness := types.Hash(vk[:])
	if _, ok := s.cosignature[*witness]; ok {
		glog.V(3).Infof("received cosignature again (duplicate)")
		return nil // duplicate
	}
	s.cosignature[*witness] = &types.SigIdent{
		Signature: sig,
		KeyHash:   witness,
	}
	glog.V(3).Infof("accepted new cosignature")
	return nil
}

// rotate rotates the log's cosigned and stable STH.  The caller must aquire the
// source's read-write lock if there are concurrent reads and/or writes.
func (s *ActiveSthSource) rotate(next *types.SignedTreeHead) {
	if reflect.DeepEqual(s.cosigned.TreeHead, s.tosign.TreeHead) {
		for _, sigident := range s.cosigned.SigIdent[1:] { // skip log sigident
			if _, ok := s.cosignature[*sigident.KeyHash]; !ok {
				s.cosignature[*sigident.KeyHash] = sigident
			}
		}
	}
	var cosignatures []*types.SigIdent
	for _, sigident := range s.cosignature {
		cosignatures = append(cosignatures, sigident)
	} // cosignatures contains all cosignatures, even if repeated tree head

	// Update cosigned tree head
	s.cosigned.TreeHead = s.tosign.TreeHead
	s.cosigned.SigIdent = append(s.tosign.SigIdent, cosignatures...)

	// Update to-sign tree head
	s.tosign = *next
	s.cosignature = make(map[[types.HashSize]byte]*types.SigIdent)
	glog.V(3).Infof("rotated sth")
}
