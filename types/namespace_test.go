package types

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"crypto/ed25519"
)

var (
	// Namespace
	testNamespaceReserved = Namespace{
		Format: NamespaceFormatReserved,
	}

	testNamespace          = testNamespaceEd25519V1
	testNamespaceBytes     = testNamespaceEd25519V1Bytes
	testNamespaceEd25519V1 = Namespace{
		Format:    NamespaceFormatEd25519V1,
		Ed25519V1: &testEd25519V1,
	}
	testNamespaceEd25519V1Bytes = bytes.Join([][]byte{
		[]byte{0x00, 0x01}, // format ed25519_v1
		testEd25519V1Bytes, // Ed25519V1
	}, nil)

	// Subtypes used by Namespace
	testEd25519V1 = Ed25519V1{
		Namespace: [32]byte{},
	}
	testEd25519V1Bytes = bytes.Join([][]byte{
		make([]byte, 32), // namespace, no length specifier because fixed size
	}, nil)
)

func TestNewNamespaceEd25519V1(t *testing.T) {
	size := 32 // verification key size
	for _, table := range []struct {
		description string
		vk          []byte
		wantErr     bool
	}{
		{
			description: "invalid",
			vk:          make([]byte, size+1),
			wantErr:     true,
		},
		{
			description: "valid",
			vk:          make([]byte, size),
		},
	} {
		n, err := NewNamespaceEd25519V1(table.vk)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := n.Format, NamespaceFormatEd25519V1; got != want {
			t.Errorf("got namespace format %v but wanted %v in test %q", got, want, table.description)
			continue
		}
		if got, want := n.Ed25519V1.Namespace[:], table.vk; !bytes.Equal(got, want) {
			t.Errorf("got namespace %X but wanted %X in test %q", got, want, table.description)
		}
	}
}

func TestNamespaceString(t *testing.T) {
	wantPrefix := map[NamespaceFormat]string{
		NamespaceFormatReserved:    "Format(reserved)",
		NamespaceFormatEd25519V1:   "Format(ed25519_v1): &{Namespace",
		NamespaceFormat(1<<16 - 1): "unknown Namespace: unknown NamespaceFormat: 65535",
	}
	tests := append(test_cases_namespace(t), testCaseType{
		description: "valid: unknown Namespace",
		item: Namespace{
			Format: NamespaceFormat(1<<16 - 1),
		},
	})
	for _, table := range tests {
		namespace, ok := table.item.(Namespace)
		if !ok {
			t.Fatalf("must cast to Namespace in test %q", table.description)
		}

		prefix, ok := wantPrefix[namespace.Format]
		if !ok {
			t.Fatalf("must have prefix for StFormat %v in test %q", namespace.Format, table.description)
		}
		if got, want := namespace.String(), prefix; !strings.HasPrefix(got, want) {
			t.Errorf("got %q but wanted prefix %q in test %q", got, want, table.description)
		}
	}
}

func TestFingerprint(t *testing.T) {
	for _, table := range []struct {
		description string
		namespace   *Namespace
		wantErr     bool
		wantFpr     [NamespaceFingerprintSize]byte
	}{
		{
			description: "invalid: no fingerprint for type",
			namespace: &Namespace{
				Format: NamespaceFormatReserved,
			},
			wantErr: true,
		},
		{
			description: "valid: ed25519_v1",
			namespace:   mustInitNamespaceEd25519V1(t, 0xaf),
			wantFpr: func() (ret [NamespaceFingerprintSize]byte) {
				for i, _ := range ret {
					ret[i] = 0xaf
				}
				return
			}(),
		},
	} {
		fpr, err := table.namespace.Fingerprint()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := *fpr, table.wantFpr; !bytes.Equal(got[:], want[:]) {
			t.Errorf("got fpr %v but wanted %v in test %q", got, want, table.description)
		}
	}
}

func TestVerify(t *testing.T) {
	var tests []testCaseNamespace
	tests = append(tests, test_cases_verify(t)...)
	tests = append(tests, test_cases_verify_ed25519v1(t)...)
	for _, table := range tests {
		err := table.namespace.Verify(table.msg, table.sig)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestNewNamespacePool(t *testing.T) {
	ns1 := mustInitNamespaceEd25519V1(t, 0x00)
	ns2 := mustInitNamespaceEd25519V1(t, 0xff)
	nsr := &Namespace{Format: NamespaceFormatReserved}
	for _, table := range []struct {
		description string
		namespaces  []*Namespace
		wantErr     bool
	}{
		{
			description: "invalid: duplicate namespace",
			namespaces:  []*Namespace{ns1, ns1, ns2},
			wantErr:     true,
		},
		{
			description: "invalid: namespace without key",
			namespaces:  []*Namespace{ns1, nsr, ns2},
			wantErr:     true,
		},
		{
			description: "valid: empty",
			namespaces:  []*Namespace{},
		},
		{
			description: "valid: one namespace",
			namespaces:  []*Namespace{ns1},
		},
		{
			description: "valid: two namespaces",
			namespaces:  []*Namespace{ns1, ns2},
		},
	} {
		_, err := NewNamespacePool(table.namespaces)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestFind(t *testing.T) {
	ns1 := mustInitNamespaceEd25519V1(t, 0x00)
	ns2 := mustInitNamespaceEd25519V1(t, 0xff)

	// Empty pool
	pool, err := NewNamespacePool(nil)
	if err != nil {
		t.Fatalf("must create new namespace pool: %v", err)
	}
	if _, ok := pool.Find(ns1); ok {
		t.Errorf("found namespace in empty pool")
	}

	// Pool with one namespace
	pool, err = NewNamespacePool([]*Namespace{ns1})
	if err != nil {
		t.Fatalf("must create new namespace pool: %v", err)
	}
	if ns, ok := pool.Find(ns1); !ok {
		t.Errorf("could not find namespace that is a member of the pool")
	} else if !reflect.DeepEqual(ns, ns1) {
		t.Errorf("found namespace but it is wrong")
	}
	if _, ok := pool.Find(ns2); ok {
		t.Errorf("found namespace although it is not a member of the pool")
	}
}

func TestList(t *testing.T) {
	ns1 := mustInitNamespaceEd25519V1(t, 0x00)
	ns2 := mustInitNamespaceEd25519V1(t, 0xff)
	namespaces := []*Namespace{ns1, ns2}
	pool, err := NewNamespacePool(namespaces)
	if err != nil {
		t.Fatalf("must create new namespace pool: %v", err)
	}
	if got, want := len(pool.List()), len(namespaces); got != want {
		t.Errorf("got len %v but wanted %v", got, want)
	}
	pool.List()[0] = ns2
	if got, want := pool.List()[0].Ed25519V1.Namespace[:], ns1.Ed25519V1.Namespace[:]; !bytes.Equal(got, want) {
		t.Errorf("returned list is not a copy")
	}
}

// test_cases_namespace returns test cases for the different Namespace types.
// It is used by TestMarshalUnmarshal(), see test_item.go.
func test_cases_namespace(t *testing.T) []testCaseType {
	return []testCaseType{
		{
			description: "invalid: Namespace: reserved",
			item:        testNamespaceReserved,
			wantErr:     true,
		},
		{
			description: "valid: Namespace: ed25519_v1",
			item:        testNamespaceEd25519V1,
			wantBytes:   testNamespaceEd25519V1Bytes,
		},
	}
}

// test_cases_ed25519v1 returns test cases for the Ed25519V1 structure
// It is used by TestMarshalUnmarshal(), see test_item.go.
func test_cases_ed25519v1(t *testing.T) []testCaseType {
	return []testCaseType{
		{
			description: "valid: testNamespaceEd25519V1",
			item:        testEd25519V1,
			wantBytes:   testEd25519V1Bytes,
		},
	}
}

// testCaseNamespace is a common test case used for Namespace.Verify() tests
type testCaseNamespace struct {
	description string
	namespace   *Namespace
	msg, sig    []byte
	wantErr     bool
}

// test_cases_verify returns basic namespace.Verify() tests
func test_cases_verify(t *testing.T) []testCaseNamespace {
	return []testCaseNamespace{
		{
			description: "test_cases_verify: invalid: unsupported namespace",
			namespace:   &Namespace{Format: NamespaceFormatReserved},
			msg:         []byte("msg"),
			sig:         []byte("sig"),
			wantErr:     true,
		},
	}
}

// test_cases_verify_ed25519v1 returns ed25519_v1 Namespace.Verify() tests
func test_cases_verify_ed25519v1(t *testing.T) []testCaseNamespace {
	testEd25519Sk := [64]byte{230, 122, 195, 152, 194, 195, 147, 153, 80, 120, 153, 79, 102, 27, 52, 187, 136, 218, 150, 234, 107, 9, 167, 4, 92, 21, 11, 113, 42, 29, 129, 69, 75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78, 37, 45, 210}
	testEd25519Vk := [32]byte{75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78,
		37, 45, 210}
	return []testCaseNamespace{
		{
			description: "test_cases_verify_ed25519v1: invalid: sk signed message, but vk is not for sk",
			namespace: &Namespace{
				Format: NamespaceFormatEd25519V1,
				Ed25519V1: &Ed25519V1{
					Namespace: [32]byte{},
				},
			},
			msg:     []byte("message"),
			sig:     ed25519.Sign(ed25519.PrivateKey(testEd25519Sk[:]), []byte("message")),
			wantErr: true,
		},
		{
			description: "test_cases_verify_ed25519v1: invalid: vk is for sk, but sk did not sign message",
			namespace: &Namespace{
				Format: NamespaceFormatEd25519V1,
				Ed25519V1: &Ed25519V1{
					Namespace: testEd25519Vk,
				},
			},
			msg:     []byte("some message"),
			sig:     ed25519.Sign(ed25519.PrivateKey(testEd25519Sk[:]), []byte("another message")),
			wantErr: true,
		},
		{
			description: "test_cases_verify_ed25519v1: valid",
			namespace: &Namespace{
				Format: NamespaceFormatEd25519V1,
				Ed25519V1: &Ed25519V1{
					Namespace: testEd25519Vk,
				},
			},
			msg: []byte("message"),
			sig: ed25519.Sign(ed25519.PrivateKey(testEd25519Sk[:]), []byte("message")),
		},
	}
}

func mustInitNamespaceEd25519V1(t *testing.T, initByte byte) *Namespace {
	t.Helper()
	buf := make([]byte, 32)
	for i := 0; i < len(buf); i++ {
		buf[i] = initByte
	}
	ns, err := NewNamespaceEd25519V1(buf)
	if err != nil {
		t.Fatalf("must make Ed25519v1 namespace: %v", err)
	}
	return ns
}
