// Package namespace provides namespace functionality.  A namespace refers to a
// particular verification key and signing algorithm that can be serialized with
// TLS 1.2 notation, see RFC 5246 (§4).  Only Ed25519 is supported at this time.
//
// For example, this is how a serialized Ed25519 namespace looks like:
//
// 0   2                      34 (byte index)
// +---+----------------------+
// | 1 +   Verification key   +
// +---+----------------------+
package namespace

import (
	"fmt"

	"crypto/ed25519"

	"github.com/google/certificate-transparency-go/tls"
)

// NamespaceFormat defines a particular namespace type that is versioend
type NamespaceFormat tls.Enum

const (
	NamespaceFormatReserved  NamespaceFormat = 0
	NamespaceFormatEd25519V1 NamespaceFormat = 1
)

// Namespace references a versioned namespace based on a given format specifier
type Namespace struct {
	Format             NamespaceFormat     `tls:"maxval:65535"`
	NamespaceEd25519V1 *NamespaceEd25519V1 `tls:"selector:Format,val:1"`
}

// NamespaceEd25519V1 uses an Ed25519 verification key as namespace.  Encoding,
// signing, and verification operations are defined by RFC 8032.
type NamespaceEd25519V1 struct {
	Namespace []byte `tls:"minlen:32,maxlen:32"`
}

// String returns a human-readable representation of a namespace.
func (n Namespace) String() string {
	switch n.Format {
	case NamespaceFormatEd25519V1:
		return fmt.Sprintf("%x", n.NamespaceEd25519V1.Namespace)
	default:
		return "reserved"
	}
}

// NewNamespaceEd25519V1 returns an new Ed25519V1 namespace based on a
// verification key.
func NewNamespaceEd25519V1(vk []byte) (*Namespace, error) {
	if len(vk) != 32 {
		return nil, fmt.Errorf("invalid verification key: must be 32 bytes")
	}
	return &Namespace{
		Format: NamespaceFormatEd25519V1,
		NamespaceEd25519V1: &NamespaceEd25519V1{
			Namespace: vk,
		},
	}, nil
}

// Verify checks that signature is valid over message for this namespace
func (ns *Namespace) Verify(message, signature []byte) error {
	switch ns.Format {
	case NamespaceFormatEd25519V1:
		if !ed25519.Verify(ed25519.PublicKey(ns.NamespaceEd25519V1.Namespace), message, signature) {
			return fmt.Errorf("ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("namespace not supported: %v", ns.Format)
	}
	return nil
}

func (ns *Namespace) Marshal() ([]byte, error) {
	serialized, err := tls.Marshal(*ns)
	if err != nil {
		return nil, fmt.Errorf("marshaled failed for namespace(%v): %v", ns.Format, err)
	}
	return serialized, err
}

func (ns *Namespace) Unmarshal(serialized []byte) error {
	extra, err := tls.Unmarshal(serialized, ns)
	if err != nil {
		return fmt.Errorf("unmarshal failed for namespace: %v", err)
	} else if len(extra) > 0 {
		return fmt.Errorf("unmarshal found extra data for namespace(%v): %v", ns.Format, err)
	}
	return nil
}

// NamespacePool is a pool of namespaces that contain complete verification keys
type NamespacePool struct {
	pool map[string]*Namespace
	list []*Namespace
	// If we need to update this structure without a restart => add mutex.
}

// NewNameSpacePool creates a new namespace pool from a list of namespaces.  An
// error is returned if there are duplicate namespaces or namespaces without a
// complete verification key.  The latter is determined by namespaceWithKey().
func NewNamespacePool(namespaces []*Namespace) (*NamespacePool, error) {
	np := &NamespacePool{
		pool: make(map[string]*Namespace),
		list: make([]*Namespace, 0),
	}
	for _, namespace := range namespaces {
		if !namespaceWithKey(namespace.Format) {
			return nil, fmt.Errorf("need verification key in namespace pool: %v", namespace.Format)
		}
		if _, ok := np.pool[namespace.String()]; ok {
			return nil, fmt.Errorf("duplicate namespace: %v", namespace.String())
		}
		np.pool[namespace.String()] = namespace
		np.list = append(np.list, namespace)
	}
	return np, nil
}

// Find checks if namespace is a member of the namespace pool.
func (np *NamespacePool) Find(namespace *Namespace) (*Namespace, bool) {
	if _, ok := np.pool[namespace.String()]; !ok {
		return nil, false
	}
	// If the passed namespace is a key fingerprint the actual key needs to be
	// attached before returning.  Not applicable for Ed25519.  Docdoc later.
	return namespace, true
}

// List returns a copied list of namespaces that is used by this pool.
func (np *NamespacePool) List() []*Namespace {
	namespaces := make([]*Namespace, len(np.list))
	copy(namespaces, np.list)
	return namespaces
}

// namespaceWithKey returns true if a namespace format contains a complete
// verification key.  I.e., some formats might have a key fingerprint instead.
func namespaceWithKey(format NamespaceFormat) bool {
	switch format {
	case NamespaceFormatEd25519V1:
		return true
	default:
		return false
	}
}
