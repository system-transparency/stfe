package client

import (
	"flag"
	"fmt"

	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/system-transparency/stfe/types"
)

var (
	logId      = flag.String("log_id", "AAG+ZW+UesWdMFytUGkp28csBcziomSB3U2vvkAW55MVZQ==", "base64-encoded log identifier")
	logUrl     = flag.String("log_url", "http://tlog-poc.system-transparency.org:4780/st/v1", "log url")
	ed25519_sk = flag.String("ed25519_sk", "d8i6nud7PS1vdO0sIk9H+W0nyxbM63Y3/mSeUPRafWaFh8iH8QXvL7NaAYn2RZPrnEey+FdpmTYXE47OFO70eg==", "base64-encoded ed25519 signing key")
)

func NewClientFromFlags() (*Client, error) {
	var err error
	c := Client{
		HttpClient: &http.Client{},
	}
	if len(*ed25519_sk) != 0 {
		sk, err := base64.StdEncoding.DecodeString(*ed25519_sk)
		if err != nil {
			return nil, fmt.Errorf("ed25519_sk: DecodeString: %v", err)
		}
		c.Signer = ed25519.PrivateKey(sk)
		c.Namespace, err = types.NewNamespaceEd25519V1([]byte(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)))
		if err != nil {
			return nil, fmt.Errorf("ed25519_vk: NewNamespaceEd25519V1: %v", err)
		}
	}
	if c.Log, err = NewDescriptorFromFlags(); err != nil {
		return nil, fmt.Errorf("NewDescriptorFromFlags: %v", err)
	}
	return &c, nil
}

func NewDescriptorFromFlags() (*Descriptor, error) {
	b, err := base64.StdEncoding.DecodeString(*logId)
	if err != nil {
		return nil, fmt.Errorf("LogId: DecodeString: %v", err)
	}
	var namespace types.Namespace
	if err := types.Unmarshal(b, &namespace); err != nil {
		return nil, fmt.Errorf("LogId: Unmarshal: %v", err)
	}
	return &Descriptor{
		Namespace: &namespace,
		Url:       *logUrl,
	}, nil
}
