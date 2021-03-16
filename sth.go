package stfe

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"github.com/system-transparency/stfe/types"
)

// SthSource provides access to the log's STHs.
type SthSource interface {
	// Latest returns the most reccent signed_tree_head_v*.
	Latest(context.Context) (*types.StItem, error)
	// Stable returns the most recent signed_tree_head_v* that is stable for
	// some period of time, e.g., 10 minutes.
	Stable(context.Context) (*types.StItem, error)
	// Cosigned returns the most recent cosigned_tree_head_v*.
	Cosigned(context.Context) (*types.StItem, error)
	// AddCosignature attempts to add a cosignature to the stable STH.  The
	// passed cosigned_tree_head_v* must have a single verified cosignature.
	AddCosignature(context.Context, *types.StItem) error
	// Run keeps the STH source updated until cancelled
	Run(context.Context)
}

// ActiveSthSource implements the SthSource interface for an STFE instance that
// accepts new logging requests, i.e., the log is running in read+write mode.
type ActiveSthSource struct {
	client          trillian.TrillianLogClient
	logParameters   *LogParameters
	currCosth       *types.StItem                                 // current cosigned_tree_head_v1 (already finalized)
	nextCosth       *types.StItem                                 // next cosigned_tree_head_v1 (under preparation)
	cosignatureFrom map[[types.NamespaceFingerprintSize]byte]bool // track who we got cosignatures from in nextCosth
	mutex           sync.RWMutex
}

// NewActiveSthSource returns an initialized ActiveSthSource
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

	// TODO: load persisted cosigned STH?
	s.currCosth = types.NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, nil)
	s.nextCosth = types.NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, nil)
	s.cosignatureFrom = make(map[[types.NamespaceFingerprintSize]byte]bool)
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
		s.mutex.Lock()
		defer s.mutex.Unlock()
		if err := s.rotate(sth); err != nil {
			glog.Warningf("rotate failed: %v", err)
		}
		// TODO: persist cosigned STH?
	})
}

func (s *ActiveSthSource) Latest(ctx context.Context) (*types.StItem, error) {
	trsp, err := s.client.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: s.logParameters.TreeId,
	})
	var lr ttypes.LogRootV1
	if errInner := checkGetLatestSignedLogRoot(s.logParameters, trsp, err, &lr); errInner != nil {
		return nil, fmt.Errorf("invalid signed log root response: %v", errInner)
	}
	return s.logParameters.SignTreeHeadV1(NewTreeHeadV1FromLogRoot(&lr))
}

func (s *ActiveSthSource) Stable(_ context.Context) (*types.StItem, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.nextCosth == nil {
		return nil, fmt.Errorf("no stable sth available")
	}
	return types.NewSignedTreeHeadV1(&s.nextCosth.CosignedTreeHeadV1.SignedTreeHead.TreeHead, &s.nextCosth.CosignedTreeHeadV1.SignedTreeHead.Signature), nil
}

func (s *ActiveSthSource) Cosigned(_ context.Context) (*types.StItem, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.currCosth == nil {
		return nil, fmt.Errorf("no cosigned sth available")
	}
	return s.currCosth, nil
}

func (s *ActiveSthSource) AddCosignature(_ context.Context, costh *types.StItem) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !reflect.DeepEqual(s.nextCosth.CosignedTreeHeadV1.SignedTreeHead, costh.CosignedTreeHeadV1.SignedTreeHead) {
		return fmt.Errorf("cosignature covers a different tree head")
	}
	witness, err := costh.CosignedTreeHeadV1.Cosignatures[0].Namespace.Fingerprint()
	if err != nil {
		return fmt.Errorf("namespace without fingerprint: %v", err)
	}
	if _, ok := s.cosignatureFrom[*witness]; ok {
		return nil // duplicate
	}
	s.cosignatureFrom[*witness] = true
	s.nextCosth.CosignedTreeHeadV1.Cosignatures = append(s.nextCosth.CosignedTreeHeadV1.Cosignatures, costh.CosignedTreeHeadV1.Cosignatures[0])
	return nil
}

// rotate rotates the log's cosigned and stable STH.  The caller must aquire the
// source's read-write lock if there are concurrent reads and/or writes.
func (s *ActiveSthSource) rotate(fixedSth *types.StItem) error {
	// rotate stable -> cosigned
	if reflect.DeepEqual(&s.currCosth.CosignedTreeHeadV1.SignedTreeHead, &s.nextCosth.CosignedTreeHeadV1.SignedTreeHead) {
		for _, sigv1 := range s.currCosth.CosignedTreeHeadV1.Cosignatures {
			witness, err := sigv1.Namespace.Fingerprint()
			if err != nil {
				return fmt.Errorf("namespace without fingerprint: %v", err)
			}
			if _, ok := s.cosignatureFrom[*witness]; !ok {
				s.cosignatureFrom[*witness] = true
				s.nextCosth.CosignedTreeHeadV1.Cosignatures = append(s.nextCosth.CosignedTreeHeadV1.Cosignatures, sigv1)
			}
		}
	}
	s.currCosth.CosignedTreeHeadV1.SignedTreeHead = s.nextCosth.CosignedTreeHeadV1.SignedTreeHead
	s.currCosth.CosignedTreeHeadV1.Cosignatures = make([]types.SignatureV1, len(s.nextCosth.CosignedTreeHeadV1.Cosignatures))
	copy(s.currCosth.CosignedTreeHeadV1.Cosignatures, s.nextCosth.CosignedTreeHeadV1.Cosignatures)

	// rotate new stable -> stable
	if !reflect.DeepEqual(&s.nextCosth.CosignedTreeHeadV1.SignedTreeHead, fixedSth.SignedTreeHeadV1) {
		s.nextCosth = types.NewCosignedTreeHeadV1(fixedSth.SignedTreeHeadV1, nil)
		s.cosignatureFrom = make(map[[types.NamespaceFingerprintSize]byte]bool)
	}
	return nil
}
