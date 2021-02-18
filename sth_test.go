package stfe

import (
	"context"
	"crypto"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	cttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe/namespace"
	"github.com/system-transparency/stfe/namespace/testdata"
)

func TestNewActiveSthSource(t *testing.T) {
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		trsp        *trillian.GetLatestSignedLogRootResponse
		terr        error
		wantErr     bool
		wantCosi    *StItem // current cosigned sth
		wantStable  *StItem // next stable sth that signatures are collected for
	}{
		{
			description: "invalid trillian response",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testSignature),
			terr:        fmt.Errorf("internal server error"),
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testSignature),
			trsp:        makeLatestSignedLogRootResponse(t, testTimestamp, testTreeSize, testNodeHash),
			wantCosi:    NewCosignedTreeHeadV1(NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature).SignedTreeHeadV1, nil),
			wantStable:  NewCosignedTreeHeadV1(NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature).SignedTreeHeadV1, nil),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, table.signer, nil)
			defer th.mockCtrl.Finish()
			th.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.trsp, table.terr)
			source, err := NewActiveSthSource(th.client, th.instance.LogParameters)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			if got, want := source.currSth, table.wantCosi; !reflect.DeepEqual(got, want) {
				t.Errorf("got cosigned sth %v but wanted %v in test %q", got, want, table.description)
			}
			if got, want := source.nextSth, table.wantStable; !reflect.DeepEqual(got, want) {
				t.Errorf("got stable sth %v but wanted %v in test %q", got, want, table.description)
			}
			cosignatureFrom := make(map[string]bool)
			for _, wit := range table.wantStable.CosignedTreeHeadV1.SignatureV1 {
				cosignatureFrom[wit.Namespace.String()] = true
			}
			if got, want := source.cosignatureFrom, cosignatureFrom; !reflect.DeepEqual(got, want) {
				if got == nil {
					t.Errorf("got uninitialized witness map %v but wanted %v in test %q", nil, want, table.description)
				} else {
					t.Errorf("got witness map %v but wanted %v in test %q", got, want, table.description)
				}
			}
		}()
	}
}

func TestLatest(t *testing.T) {
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		trsp        *trillian.GetLatestSignedLogRootResponse
		terr        error
		wantErr     bool
		wantRsp     *StItem
	}{
		{
			description: "invalid trillian response",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testSignature),
			terr:        fmt.Errorf("internal server error"),
			wantErr:     true,
		},
		{
			description: "signature failure",
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signing failed")),
			terr:        fmt.Errorf("internal server error"),
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testSignature),
			trsp:        makeLatestSignedLogRootResponse(t, testTimestamp, testTreeSize, testNodeHash),
			wantRsp:     NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			th := newTestHandler(t, table.signer, nil)
			defer th.mockCtrl.Finish()
			th.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.trsp, table.terr)
			sth, err := th.instance.SthSource.Latest(context.Background())
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := sth, table.wantRsp; !reflect.DeepEqual(got, want) {
				t.Errorf("got %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestStable(t *testing.T) {
	sth := NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature)
	for _, table := range []struct {
		description string
		source      SthSource
		wantRsp     *StItem
		wantErr     bool
	}{
		{
			description: "no stable sth",
			source:      &ActiveSthSource{},
			wantErr:     true,
		},
		{
			description: "valid",
			source: &ActiveSthSource{
				nextSth: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, nil)},
			wantRsp: sth,
		},
	} {
		sth, err := table.source.Stable(context.Background())
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := sth, table.wantRsp; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestCosigned(t *testing.T) {
	sth := NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature)
	sigs := []SignatureV1{
		SignatureV1{
			Namespace: *mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
			Signature: testSignature,
		},
	}
	for _, table := range []struct {
		description string
		source      SthSource
		wantRsp     *StItem
		wantErr     bool
	}{
		{
			description: "no cosigned sth: nil",
			source:      &ActiveSthSource{},
			wantErr:     true,
		},
		{
			description: "no cosigned sth: nil signatures",
			source: &ActiveSthSource{
				currSth: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, nil),
			},
			wantErr: true,
		},
		{
			description: "valid",
			source: &ActiveSthSource{
				currSth: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, sigs),
			},
			wantRsp: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, sigs),
		},
	} {
		cosi, err := table.source.Cosigned(context.Background())
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := cosi, table.wantRsp; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestAddCosignature(t *testing.T) {
	sth := NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature)
	wit1 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)
	wit2 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk2)
	for _, table := range []struct {
		description string
		source      *ActiveSthSource
		req         *StItem
		wantWit     []*namespace.Namespace
		wantErr     bool
	}{
		{
			description: "invalid: cosignature must target the stable sth",
			source: &ActiveSthSource{
				nextSth:         NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, nil),
				cosignatureFrom: make(map[string]bool),
			},
			req: NewCosignedTreeHeadV1(NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp+1000000, testTreeSize, testNodeHash)), testLogId, testSignature).SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantErr: true,
		},
		{
			description: "valid: adding duplicate into a pool of cosignatures",
			source: &ActiveSthSource{
				nextSth: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit1,
						Signature: testSignature,
					},
				}),
				cosignatureFrom: map[string]bool{
					wit1.String(): true,
				},
			},
			req: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantWit: []*namespace.Namespace{wit1},
		},
		{
			description: "valid: adding into an empty pool of cosignatures",
			source: &ActiveSthSource{
				nextSth:         NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, nil),
				cosignatureFrom: make(map[string]bool),
			},
			req: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantWit: []*namespace.Namespace{wit1},
		},
		{
			description: "valid: adding into a pool of cosignatures",
			source: &ActiveSthSource{
				nextSth: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit1,
						Signature: testSignature,
					},
				}),
				cosignatureFrom: map[string]bool{
					wit1.String(): true,
				},
			},
			req: NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit2,
					Signature: testSignature,
				},
			}),
			wantWit: []*namespace.Namespace{wit1, wit2},
		},
	} {
		err := table.source.AddCosignature(context.Background(), table.req)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		// Check that the next cosigned sth is updated
		var sigs []SignatureV1
		for _, wit := range table.wantWit {
			sigs = append(sigs, SignatureV1{
				Namespace: *wit,
				Signature: testSignature,
			})
		}
		if got, want := table.source.nextSth, NewCosignedTreeHeadV1(sth.SignedTreeHeadV1, sigs); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v but wanted %v in test %q", got, want, table.description)
		}
		// Check that the map tracking witness signatures is updated
		if got, want := len(table.source.cosignatureFrom), len(table.wantWit); got != want {
			t.Errorf("witness map got %d cosignatures but wanted %d in test %q", got, want, table.description)
		} else {
			for _, wit := range table.wantWit {
				if _, ok := table.source.cosignatureFrom[wit.String()]; !ok {
					t.Errorf("missing signature from witness %X in test %q", wit.String(), table.description)
				}
			}
		}
	}
}

func TestRotate(t *testing.T) {
	sth1 := NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp, testTreeSize, testNodeHash)), testLogId, testSignature)
	sth2 := NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp+1000000, testTreeSize+1, testNodeHash)), testLogId, testSignature)
	sth3 := NewSignedTreeHeadV1(NewTreeHeadV1(makeTrillianLogRoot(t, testTimestamp+2000000, testTreeSize+2, testNodeHash)), testLogId, testSignature)
	wit1 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)
	wit2 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk2)
	wit3 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk3)
	for _, table := range []struct {
		description string
		source      *ActiveSthSource
		fixedSth    *StItem
		wantCurrSth *StItem
		wantNextSth *StItem
		wantWit     []*namespace.Namespace
	}{
		{
			description: "not repeated cosigned and not repeated stable",
			source: &ActiveSthSource{
				currSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, nil),
				nextSth: NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit1,
						Signature: testSignature,
					},
				}),
				cosignatureFrom: map[string]bool{
					wit1.String(): true,
				},
			},
			fixedSth: sth3,
			wantCurrSth: NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantNextSth: NewCosignedTreeHeadV1(sth3.SignedTreeHeadV1, nil),
			wantWit:     nil, // no cosignatures for the next stable sth yet
		},
		{
			description: "not repeated cosigned and repeated stable",
			source: &ActiveSthSource{
				currSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, nil),
				nextSth: NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit1,
						Signature: testSignature,
					},
				}),
				cosignatureFrom: map[string]bool{
					wit1.String(): true,
				},
			},
			fixedSth: sth2,
			wantCurrSth: NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantNextSth: NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantWit: []*namespace.Namespace{wit1},
		},
		{
			description: "repeated cosigned and not repeated stable",
			source: &ActiveSthSource{
				currSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit1,
						Signature: testSignature,
					},
					SignatureV1{
						Namespace: *wit2,
						Signature: testSignature,
					},
				}),
				nextSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit2,
						Signature: testSignature,
					},
					SignatureV1{
						Namespace: *wit3,
						Signature: testSignature,
					},
				}),
				cosignatureFrom: map[string]bool{
					wit2.String(): true,
					wit3.String(): true,
				},
			},
			fixedSth: sth3,
			wantCurrSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit2,
					Signature: testSignature,
				},
				SignatureV1{
					Namespace: *wit3,
					Signature: testSignature,
				},
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantNextSth: NewCosignedTreeHeadV1(sth3.SignedTreeHeadV1, nil),
			wantWit:     nil, // no cosignatures for the next stable sth yet
		},
		{
			description: "repeated cosigned and repeated stable",
			source: &ActiveSthSource{
				currSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit1,
						Signature: testSignature,
					},
					SignatureV1{
						Namespace: *wit2,
						Signature: testSignature,
					},
				}),
				nextSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
					SignatureV1{
						Namespace: *wit2,
						Signature: testSignature,
					},
					SignatureV1{
						Namespace: *wit3,
						Signature: testSignature,
					},
				}),
				cosignatureFrom: map[string]bool{
					wit2.String(): true,
					wit3.String(): true,
				},
			},
			fixedSth: sth1,
			wantCurrSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit2,
					Signature: testSignature,
				},
				SignatureV1{
					Namespace: *wit3,
					Signature: testSignature,
				},
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantNextSth: NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []SignatureV1{
				SignatureV1{
					Namespace: *wit2,
					Signature: testSignature,
				},
				SignatureV1{
					Namespace: *wit3,
					Signature: testSignature,
				},
				SignatureV1{
					Namespace: *wit1,
					Signature: testSignature,
				},
			}),
			wantWit: []*namespace.Namespace{wit1, wit2, wit3},
		},
	} {
		table.source.rotate(table.fixedSth)
		if got, want := table.source.currSth, table.wantCurrSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got currSth %X but wanted %X in test %q", got, want, table.description)
		}
		if got, want := table.source.nextSth, table.wantNextSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got nextSth %X but wanted %X in test %q", got, want, table.description)
		}
		if got, want := len(table.source.cosignatureFrom), len(table.wantWit); got != want {
			t.Errorf("witness map got %d cosignatures but wanted %d in test %q", got, want, table.description)
		} else {
			for _, wit := range table.wantWit {
				if _, ok := table.source.cosignatureFrom[wit.String()]; !ok {
					t.Errorf("missing signature from witness %X in test %q", wit.String(), table.description)
				}
			}
		}
		// check that adding cosignatures to stable will not effect cosigned sth
		wantLen := len(table.source.currSth.CosignedTreeHeadV1.SignatureV1)
		table.source.nextSth.CosignedTreeHeadV1.SignatureV1 = append(table.source.nextSth.CosignedTreeHeadV1.SignatureV1, SignatureV1{Namespace: *wit1, Signature: testSignature})
		if gotLen := len(table.source.currSth.CosignedTreeHeadV1.SignatureV1); gotLen != wantLen {
			t.Errorf("adding cosignatures to the stable sth modifies the fixated cosigned sth in test %q", table.description)
		}
	}
}
