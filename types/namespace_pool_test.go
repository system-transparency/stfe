package types

import (
	"bytes"
	"reflect"
	"testing"
)

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
