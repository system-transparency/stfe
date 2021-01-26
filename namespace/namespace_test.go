package namespace

import (
	"bytes"
	"testing"

	"crypto/ed25519"

	"github.com/system-transparency/stfe/namespace/testdata"
)

func TestNewNamespaceEd25519V1(t *testing.T) {
	for _, table := range []struct {
		description string
		vk          []byte
		wantErr     bool
	}{
		{
			description: "invalid",
			vk:          append(testdata.Ed25519Vk, 0x00),
			wantErr:     true,
		},
		{
			description: "valid",
			vk:          testdata.Ed25519Vk,
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
		if got, want := n.NamespaceEd25519V1.Namespace, table.vk; !bytes.Equal(got, want) {
			t.Errorf("got namespace %X but wanted %X in test %q", got, want, table.description)
		}
	}
}

func TestVerify(t *testing.T) {
	testMsg := []byte("msg")
	for _, table := range []struct {
		description string
		namespace   *Namespace
		msg, sig    []byte
		wantErr     bool
	}{
		{
			description: "invalid: unsupported namespace",
			namespace:   &Namespace{Format: NamespaceFormatReserved},
			msg:         testMsg,
			sig:         []byte("sig"),
			wantErr:     true,
		},
		{
			description: "invalid: bad ed25519 verification key",
			namespace:   mustNewNamespaceEd25519V1(t, testdata.Ed25519Sk[:32]),
			msg:         testMsg,
			sig:         ed25519.Sign(ed25519.PrivateKey(testdata.Ed25519Sk), testMsg),
			wantErr:     true,
		},
		{
			description: "invalid: ed25519 signature is not over message",
			namespace:   mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
			msg:         append(testMsg, 0x00),
			sig:         ed25519.Sign(ed25519.PrivateKey(testdata.Ed25519Sk), testMsg),
			wantErr:     true,
		},
		{
			description: "valid: ed25519",
			namespace:   mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
			msg:         testMsg,
			sig:         ed25519.Sign(ed25519.PrivateKey(testdata.Ed25519Sk), testMsg),
		},
	} {
		err := table.namespace.Verify(table.msg, table.sig)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error=%v but wanted %v in test %q: %v", got, want, table.description, err)
		}
	}
}

func TestMarshal(t *testing.T) {
	for _, table := range []struct {
		description string
		namespace   *Namespace
		wantErr     bool
		wantBytes   []byte
	}{
		{
			description: "invalid ed25519: namespace size too small",
			namespace: &Namespace{
				Format: NamespaceFormatEd25519V1,
				NamespaceEd25519V1: &NamespaceEd25519V1{
					Namespace: testdata.Ed25519Vk[:len(testdata.Ed25519Vk)-1],
				},
			},
			wantErr: true,
		},
		{
			description: "invalid ed25519: namespace size too large",
			namespace: &Namespace{
				Format: NamespaceFormatEd25519V1,
				NamespaceEd25519V1: &NamespaceEd25519V1{
					Namespace: append(testdata.Ed25519Vk, 0x00),
				},
			},
			wantErr: true,
		},
		{
			description: "valid: ed25519",
			namespace:   mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk),
			// TODO: wantBytes
		},
	} {
		_, err := table.namespace.Marshal()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		// TODO: add check that we got the bytes we wanted also
	}
}

func TestUnmarshal(t *testing.T) {
	// TODO
}

func TestNewNamespacePool(t *testing.T) {
	ns1, _ := NewNamespaceEd25519V1(testdata.Ed25519Vk)
	ns2, _ := NewNamespaceEd25519V1(make([]byte, 32))
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
	ns1 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)
	ns2 := mustNewNamespaceEd25519V1(t, make([]byte, 32))
	pool, _ := NewNamespacePool(nil)
	_, got := pool.Find(ns1)
	if want := false; got != want {
		t.Errorf("got %v but wanted %v in test %q", got, want, "empty pool")
	}

	pool, _ = NewNamespacePool([]*Namespace{ns1})
	_, got = pool.Find(ns1)
	if want := true; got != want {
		t.Errorf("got %v but wanted %v in test %q", got, want, "non-empty pool: looking for member")
	}
	_, got = pool.Find(ns2)
	if want := false; got != want {
		t.Errorf("got %v but wanted %v in test %q", got, want, "non-empty pool: looking for non-member")
	}
}

func TestList(t *testing.T) {
	ns1 := mustNewNamespaceEd25519V1(t, testdata.Ed25519Vk)
	ns2 := mustNewNamespaceEd25519V1(t, make([]byte, 32))
	namespaces := []*Namespace{ns1, ns2}
	pool, _ := NewNamespacePool(namespaces)
	l1 := pool.List()
	if got, want := len(l1), len(namespaces); got != want {
		t.Errorf("got len %v but wanted %v", got, want)
	}

	l1[0] = ns2
	l2 := pool.List()
	if bytes.Equal(l1[0].NamespaceEd25519V1.Namespace, l2[0].NamespaceEd25519V1.Namespace) {
		t.Errorf("returned list is not a copy")
	}
}

func mustNewNamespaceEd25519V1(t *testing.T, vk []byte) *Namespace {
	namespace, err := NewNamespaceEd25519V1(vk)
	if err != nil {
		t.Fatalf("must make ed25519 namespace: %v", err)
	}
	return namespace
}
