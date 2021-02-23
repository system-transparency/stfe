package types

import (
	"fmt"
)

// NamespacePool is a pool of namespaces that contain complete verification keys
type NamespacePool struct {
	pool map[[NamespaceFingerprintSize]byte]*Namespace
	list []*Namespace
	// If we need to update this structure without a restart => add mutex.
}

// NewNameSpacePool creates a new namespace pool from a list of namespaces.  An
// error is returned if there are duplicate namespaces or namespaces without a
// complete verification key.  The latter is determined by namespaceWithKey().
func NewNamespacePool(namespaces []*Namespace) (*NamespacePool, error) {
	np := &NamespacePool{
		pool: make(map[[NamespaceFingerprintSize]byte]*Namespace),
		list: make([]*Namespace, 0),
	}
	for _, namespace := range namespaces {
		if !namespaceWithKey(namespace.Format) {
			return nil, fmt.Errorf("need verification key in namespace pool: %v", namespace.Format)
		}
		fpr, err := namespace.Fingerprint()
		if err != nil {
			return nil, fmt.Errorf("need fingerprint in namespace pool: %v", err)
		}
		if _, ok := np.pool[*fpr]; ok {
			return nil, fmt.Errorf("duplicate namespace: %v", namespace.String())
		}
		np.pool[*fpr] = namespace
		np.list = append(np.list, namespace)
	}
	return np, nil
}

// Find checks if namespace is a member of the namespace pool.
func (np *NamespacePool) Find(namespace *Namespace) (*Namespace, bool) {
	fpr, err := namespace.Fingerprint()
	if err != nil {
		return nil, false
	}
	if _, ok := np.pool[*fpr]; !ok {
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
