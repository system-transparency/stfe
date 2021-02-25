package types

import (
	"bytes"
	"strings"
	"testing"

	"crypto/ed25519"
)

// TestNamespaceString checks that the String() function prints the right
// format, and that the body is printed without a nil-pointer panic.
func TestNamespaceString(t *testing.T) {
	wantPrefix := map[NamespaceFormat]string{
		NamespaceFormatReserved:    "Format(reserved)",
		NamespaceFormatEd25519V1:   "Format(ed25519_v1): &{Namespace",
		NamespaceFormat(1<<16 - 1): "unknown Namespace: unknown NamespaceFormat: 65535",
	}
	tests := append(test_cases_namespace(t), testCaseSerialize{
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
	testEd25519Vk := [32]byte{75, 60, 249, 150, 229, 93, 75, 32, 103, 126, 244, 37, 53, 182, 68, 82, 249, 109, 49, 94, 10, 19, 146, 244, 58, 191, 169, 107, 78, 37, 45, 210}
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
