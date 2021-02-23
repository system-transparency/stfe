package types

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

	NamespaceFingerprintSize = 32
)

// Namespace references a versioned namespace based on a given format specifier
type Namespace struct {
	Format    NamespaceFormat `tls:"maxval:65535"`
	Ed25519V1 *Ed25519V1      `tls:"selector:Format,val:1"`
}

// Ed25519V1 uses an Ed25519 verification key as namespace.  Encoding,
// signing, and verification operations are defined by RFC 8032.
type Ed25519V1 struct {
	Namespace [32]byte
}

func (f NamespaceFormat) String() string {
	switch f {
	case NamespaceFormatReserved:
		return "reserved"
	case NamespaceFormatEd25519V1:
		return "ed25519_v1"
	default:
		return fmt.Sprintf("unknown NamespaceFormat: %d", f)
	}
}

func (n Namespace) String() string {
	switch n.Format {
	case NamespaceFormatReserved:
		return fmt.Sprintf("Format(%s)", n.Format)
	case NamespaceFormatEd25519V1:
		return fmt.Sprintf("Format(%s): %+v", n.Format, n.Ed25519V1)
	default:
		return fmt.Sprintf("unknown Namespace: %v", n.Format)
	}
}

// Fingerprint returns a fixed-size namespace fingerprint that is unique.
func (n *Namespace) Fingerprint() (*[NamespaceFingerprintSize]byte, error) {
	switch n.Format {
	case NamespaceFormatEd25519V1:
		return &n.Ed25519V1.Namespace, nil
	default:
		return nil, fmt.Errorf("unsupported NamespaceFormat: %v", n.Format)
	}
}

// Verify checks that signature is valid over message for this namespace
func (ns *Namespace) Verify(message, signature []byte) error {
	switch ns.Format {
	case NamespaceFormatEd25519V1:
		if !ed25519.Verify(ed25519.PublicKey(ns.Ed25519V1.Namespace[:]), message, signature) {
			return fmt.Errorf("ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("namespace not supported: %v", ns.Format)
	}
	return nil
}

// NewNamespaceEd25519V1 returns an new Ed25519V1 namespace based on a
// verification key.
func NewNamespaceEd25519V1(vk []byte) (*Namespace, error) {
	if len(vk) != 32 {
		return nil, fmt.Errorf("invalid verification key: must be 32 bytes")
	}

	var ed25519v1 Ed25519V1
	copy(ed25519v1.Namespace[:], vk)
	return &Namespace{
		Format:    NamespaceFormatEd25519V1,
		Ed25519V1: &ed25519v1,
	}, nil
}
