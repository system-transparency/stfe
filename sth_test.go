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
	"github.com/system-transparency/stfe/testdata"
	"github.com/system-transparency/stfe/types"
)

func TestNewActiveSthSource(t *testing.T) {
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		trsp        *trillian.GetLatestSignedLogRootResponse
		terr        error
		wantErr     bool
		wantCosi    *types.StItem // current cosigned sth
		wantStable  *types.StItem // next stable sth that signatures are collected for
	}{
		{
			description: "invalid: no Trillian response",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testdata.Signature),
			terr:        fmt.Errorf("internal server error"),
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testdata.Signature),
			trsp:        testdata.DefaultTSlr(t),
			wantCosi:    testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
			wantStable:  testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, table.signer)
			defer ti.ctrl.Finish()
			ti.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.trsp, table.terr)
			source, err := NewActiveSthSource(ti.client, ti.instance.LogParameters)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			if got, want := source.currCosth, table.wantCosi; !reflect.DeepEqual(got, want) {
				t.Errorf("got cosigned sth\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
			if got, want := source.nextCosth, table.wantStable; !reflect.DeepEqual(got, want) {
				t.Errorf("got stable sth\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
			}
			cosignatureFrom := make(map[[types.NamespaceFingerprintSize]byte]bool)
			for _, cosig := range table.wantStable.CosignedTreeHeadV1.Cosignatures {
				cosignatureFrom[testdata.Fingerprint(t, &cosig.Namespace)] = true
			}
			if got, want := source.cosignatureFrom, cosignatureFrom; !reflect.DeepEqual(got, want) {
				if got == nil {
					t.Errorf("got uninitialized witness map\n%v\n\tbut wanted\n%v\n\tin test %q", nil, want, table.description)
				} else {
					t.Errorf("got witness map\n%v\n\t but wanted\n%v\n\tin test %q", got, want, table.description)
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
		wantRsp     *types.StItem
	}{
		{
			description: "invalid: no Trillian response",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testdata.Signature),
			terr:        fmt.Errorf("internal server error"),
			wantErr:     true,
		},
		{
			description: "invalid: no signature",
			signer:      cttestdata.NewSignerWithErr(nil, fmt.Errorf("signing failed")),
			terr:        fmt.Errorf("internal server error"),
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      cttestdata.NewSignerWithFixedSig(nil, testdata.Signature),
			trsp:        testdata.DefaultTSlr(t),
			wantRsp:     testdata.DefaultSth(t, testdata.Ed25519VkLog),
		},
	} {
		func() { // run deferred functions at the end of each iteration
			ti := newTestInstance(t, table.signer)
			defer ti.ctrl.Finish()
			ti.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.trsp, table.terr)
			sth, err := ti.instance.SthSource.Latest(context.Background())
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := sth, table.wantRsp; !reflect.DeepEqual(got, want) {
				t.Errorf("got\n%v\n\tbut wanted\n%v\n\t in test %q", got, want, table.description)
			}
		}()
	}
}

func TestStable(t *testing.T) {
	for _, table := range []struct {
		description string
		source      SthSource
		wantRsp     *types.StItem
		wantErr     bool
	}{
		{
			description: "invalid: no stable sth",
			source:      &ActiveSthSource{},
			wantErr:     true,
		},
		{
			description: "valid",
			source: &ActiveSthSource{
				nextCosth: testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
			},
			wantRsp: testdata.DefaultSth(t, testdata.Ed25519VkLog),
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
			t.Errorf("got\n%v\n\t but wanted\n%v\n\t in test %q", got, want, table.description)
		}
	}
}

func TestCosigned(t *testing.T) {
	for _, table := range []struct {
		description string
		source      SthSource
		wantRsp     *types.StItem
		wantErr     bool
	}{
		{
			description: "invalid: no cosigned sth: nil",
			source:      &ActiveSthSource{},
			wantErr:     true,
		},
		{
			description: "invalid: no cosigned sth: nil signatures",
			source: &ActiveSthSource{
				currCosth: testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
			},
			wantErr: true,
		},
		{
			description: "valid",
			source: &ActiveSthSource{
				currCosth: testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
			},
			wantRsp: testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
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
			t.Errorf("got\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
		}
	}
}

func TestAddCosignature(t *testing.T) {
	for _, table := range []struct {
		description string
		source      *ActiveSthSource
		req         *types.StItem
		wantWit     []*types.Namespace
		wantErr     bool
	}{
		{
			description: "invalid: cosignature must target the stable sth",
			source: &ActiveSthSource{
				nextCosth:       testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
				cosignatureFrom: make(map[[types.NamespaceFingerprintSize]byte]bool),
			},
			req:     testdata.DefaultCosth(t, testdata.Ed25519VkLog2, [][32]byte{testdata.Ed25519VkWitness}),
			wantErr: true,
		},
		{
			description: "valid: adding duplicate into a pool of cosignatures",
			source: &ActiveSthSource{
				nextCosth: testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
				cosignatureFrom: map[[types.NamespaceFingerprintSize]byte]bool{
					testdata.Fingerprint(t, testdata.NewNamespace(t, testdata.Ed25519VkWitness)): true,
				},
			},
			req:     testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
			wantWit: []*types.Namespace{testdata.NewNamespace(t, testdata.Ed25519VkWitness)},
		},
		{
			description: "valid: adding into an empty pool of cosignatures",
			source: &ActiveSthSource{
				nextCosth:       testdata.DefaultCosth(t, testdata.Ed25519VkLog, nil),
				cosignatureFrom: make(map[[types.NamespaceFingerprintSize]byte]bool),
			},
			req:     testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
			wantWit: []*types.Namespace{testdata.NewNamespace(t, testdata.Ed25519VkWitness)},
		},
		{
			description: "valid: adding into a pool of cosignatures",
			source: &ActiveSthSource{
				nextCosth: testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness}),
				cosignatureFrom: map[[types.NamespaceFingerprintSize]byte]bool{
					testdata.Fingerprint(t, testdata.NewNamespace(t, testdata.Ed25519VkWitness)): true,
				},
			},
			req:     testdata.DefaultCosth(t, testdata.Ed25519VkLog, [][32]byte{testdata.Ed25519VkWitness2}),
			wantWit: []*types.Namespace{testdata.NewNamespace(t, testdata.Ed25519VkWitness), testdata.NewNamespace(t, testdata.Ed25519VkWitness2)},
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
		var sigs []types.SignatureV1
		for _, wit := range table.wantWit {
			sigs = append(sigs, types.SignatureV1{
				Namespace: *wit,
				Signature: testdata.Signature,
			})
		}
		if got, want := table.source.nextCosth, types.NewCosignedTreeHeadV1(testdata.DefaultSth(t, testdata.Ed25519VkLog).SignedTreeHeadV1, sigs); !reflect.DeepEqual(got, want) {
			t.Errorf("got\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
		}
		// Check that the map tracking witness signatures is updated
		if got, want := len(table.source.cosignatureFrom), len(table.wantWit); got != want {
			t.Errorf("witness map got %d cosignatures but wanted %d in test %q", got, want, table.description)
		} else {
			for _, wit := range table.wantWit {
				if _, ok := table.source.cosignatureFrom[testdata.Fingerprint(t, wit)]; !ok {
					t.Errorf("missing signature from witness %X in test %q", testdata.Fingerprint(t, wit), table.description)
				}
			}
		}
	}
}

func TestRotate(t *testing.T) {
	// distinct sths
	sth1 := testdata.DefaultSth(t, testdata.Ed25519VkLog)
	sth2 := testdata.DefaultSth(t, testdata.Ed25519VkLog2)
	sth3 := testdata.DefaultSth(t, testdata.Ed25519VkLog3)
	// distinct witnesses
	wit1 := testdata.NewNamespace(t, testdata.Ed25519VkWitness)
	wit2 := testdata.NewNamespace(t, testdata.Ed25519VkWitness2)
	wit3 := testdata.NewNamespace(t, testdata.Ed25519VkWitness3)
	for _, table := range []struct {
		description string
		source      *ActiveSthSource
		fixedSth    *types.StItem
		wantCurrSth *types.StItem
		wantNextSth *types.StItem
		wantWit     []*types.Namespace
	}{
		{
			description: "not repeated cosigned and not repeated stable",
			source: &ActiveSthSource{
				currCosth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, nil),
				nextCosth: types.NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []types.SignatureV1{
					types.SignatureV1{
						Namespace: *wit1,
						Signature: testdata.Signature,
					},
				}),
				cosignatureFrom: map[[types.NamespaceFingerprintSize]byte]bool{
					testdata.Fingerprint(t, wit1): true,
				},
			},
			fixedSth: sth3,
			wantCurrSth: types.NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []types.SignatureV1{
				types.SignatureV1{
					Namespace: *wit1,
					Signature: testdata.Signature,
				},
			}),
			wantNextSth: types.NewCosignedTreeHeadV1(sth3.SignedTreeHeadV1, nil),
			wantWit:     nil, // no cosignatures for the next stable sth yet
		},
		{
			description: "not repeated cosigned and repeated stable",
			source: &ActiveSthSource{
				currCosth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, nil),
				nextCosth: types.NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []types.SignatureV1{
					types.SignatureV1{
						Namespace: *wit1,
						Signature: testdata.Signature,
					},
				}),
				cosignatureFrom: map[[types.NamespaceFingerprintSize]byte]bool{
					testdata.Fingerprint(t, wit1): true,
				},
			},
			fixedSth: sth2,
			wantCurrSth: types.NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []types.SignatureV1{
				types.SignatureV1{
					Namespace: *wit1,
					Signature: testdata.Signature,
				},
			}),
			wantNextSth: types.NewCosignedTreeHeadV1(sth2.SignedTreeHeadV1, []types.SignatureV1{
				types.SignatureV1{
					Namespace: *wit1,
					Signature: testdata.Signature,
				},
			}),
			wantWit: []*types.Namespace{wit1},
		},
		{
			description: "repeated cosigned and not repeated stable",
			source: &ActiveSthSource{
				currCosth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
					types.SignatureV1{
						Namespace: *wit1,
						Signature: testdata.Signature,
					},
					types.SignatureV1{
						Namespace: *wit2,
						Signature: testdata.Signature,
					},
				}),
				nextCosth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
					types.SignatureV1{
						Namespace: *wit2,
						Signature: testdata.Signature,
					},
					types.SignatureV1{
						Namespace: *wit3,
						Signature: testdata.Signature,
					},
				}),
				cosignatureFrom: map[[types.NamespaceFingerprintSize]byte]bool{
					testdata.Fingerprint(t, wit2): true,
					testdata.Fingerprint(t, wit3): true,
				},
			},
			fixedSth: sth3,
			wantCurrSth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
				types.SignatureV1{
					Namespace: *wit2,
					Signature: testdata.Signature,
				},
				types.SignatureV1{
					Namespace: *wit3,
					Signature: testdata.Signature,
				},
				types.SignatureV1{
					Namespace: *wit1,
					Signature: testdata.Signature,
				},
			}),
			wantNextSth: types.NewCosignedTreeHeadV1(sth3.SignedTreeHeadV1, nil),
			wantWit:     nil, // no cosignatures for the next stable sth yet
		},
		{
			description: "repeated cosigned and repeated stable",
			source: &ActiveSthSource{
				currCosth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
					types.SignatureV1{
						Namespace: *wit1,
						Signature: testdata.Signature,
					},
					types.SignatureV1{
						Namespace: *wit2,
						Signature: testdata.Signature,
					},
				}),
				nextCosth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
					types.SignatureV1{
						Namespace: *wit2,
						Signature: testdata.Signature,
					},
					types.SignatureV1{
						Namespace: *wit3,
						Signature: testdata.Signature,
					},
				}),
				cosignatureFrom: map[[types.NamespaceFingerprintSize]byte]bool{
					testdata.Fingerprint(t, wit2): true,
					testdata.Fingerprint(t, wit3): true,
				},
			},
			fixedSth: sth1,
			wantCurrSth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
				types.SignatureV1{
					Namespace: *wit2,
					Signature: testdata.Signature,
				},
				types.SignatureV1{
					Namespace: *wit3,
					Signature: testdata.Signature,
				},
				types.SignatureV1{
					Namespace: *wit1,
					Signature: testdata.Signature,
				},
			}),
			wantNextSth: types.NewCosignedTreeHeadV1(sth1.SignedTreeHeadV1, []types.SignatureV1{
				types.SignatureV1{
					Namespace: *wit2,
					Signature: testdata.Signature,
				},
				types.SignatureV1{
					Namespace: *wit3,
					Signature: testdata.Signature,
				},
				types.SignatureV1{
					Namespace: *wit1,
					Signature: testdata.Signature,
				},
			}),
			wantWit: []*types.Namespace{wit1, wit2, wit3},
		},
	} {
		table.source.rotate(table.fixedSth)
		if got, want := table.source.currCosth, table.wantCurrSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got currCosth\n%v\n\tbut wanted \n%v\n\tin test %q", got, want, table.description)
		}
		if got, want := table.source.nextCosth, table.wantNextSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got nextCosth\n%v\n\tbut wanted\n%v\n\tin test %q", got, want, table.description)
		}
		if got, want := len(table.source.cosignatureFrom), len(table.wantWit); got != want {
			t.Errorf("witness map got %d cosignatures but wanted %d in test %q", got, want, table.description)
		} else {
			for _, wit := range table.wantWit {
				if _, ok := table.source.cosignatureFrom[testdata.Fingerprint(t, wit)]; !ok {
					t.Errorf("missing signature from witness %X in test %q", testdata.Fingerprint(t, wit), table.description)
				}
			}
		}
		// check that adding cosignatures to stable will not effect cosigned sth
		wantLen := len(table.source.currCosth.CosignedTreeHeadV1.Cosignatures)
		table.source.nextCosth.CosignedTreeHeadV1.Cosignatures = append(table.source.nextCosth.CosignedTreeHeadV1.Cosignatures, types.SignatureV1{Namespace: *wit1, Signature: testdata.Signature})
		if gotLen := len(table.source.currCosth.CosignedTreeHeadV1.Cosignatures); gotLen != wantLen {
			t.Errorf("adding cosignatures to the stable sth modifies the fixated cosigned sth in test %q", table.description)
		}
	}
}
