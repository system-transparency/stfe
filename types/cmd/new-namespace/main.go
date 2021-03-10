// Package main outputs the private and public parts of a new namespace
package main

import (
	"flag"
	"fmt"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe/types"
)

var (
	format = flag.String("format", string(types.NamespaceFormatEd25519V1), "namespace format")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	switch *format {
	case string(types.NamespaceFormatEd25519V1):
		glog.Infof("generating new ed25519_v1 namespace")
		sk, vk, namespace, err := genEd25519V1Namespace()
		if err != nil {
			glog.Errorf("genEd25519V1Namespace: %v", err)
			break
		}
		fmt.Printf("sk: %s\n", base64.StdEncoding.EncodeToString(sk))
		fmt.Printf("vk: %s\n", base64.StdEncoding.EncodeToString(vk))
		fmt.Printf("ed25519_v1: %s\n", base64.StdEncoding.EncodeToString(namespace))
	default:
		glog.Errorf("unsupported namespace format: %s", format)
	}
}

// genEd25519V1Namespace generates an Ed25519 secret key, verification key, and
// serialized ed25519_v1 namespace.
func genEd25519V1Namespace() ([]byte, []byte, []byte, error) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ed25519.GenerateKey: %v", err)
	}
	namespace, err := types.NewNamespaceEd25519V1(vk[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("types.NewNamespaceEd25519V1: %v", err)
	}
	serialized, err := types.Marshal(*namespace)
	if err != nil {
		fmt.Errorf("types.Marshal: %v", err)
	}
	return sk, vk, serialized, nil
}
