package main

import (
	"context"
	"flag"
	"fmt"

	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe/client"
	"github.com/system-transparency/stfe/server/descriptor"
)

var (
	operators = flag.String("operators", "../../server/descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=", "base64-encoded log identifier")
	chain     = flag.String("chain", "../../server/testdata/chain/ee.pem", "path to pem-encoded certificate chain that the log accepts")
	key       = flag.String("key", "../../server/testdata/chain/ee.key", "path to ed25519 private key that corresponds to the chain's end-entity certificate")
	name      = flag.String("name", "foobar-1.2.3", "package name")
	checksum  = flag.String("checksum", "50e7967bce266a506f8f614bb5096beba580d205046b918f47d23b2ec626d75e", "base64-encoded package checksum")
)

func main() {
	flag.Parse()

	client, err := setup()
	if err != nil {
		glog.Fatal(err)
	}

	pname, psum, err := params()
	if err != nil {
		glog.Fatal(err)
	}

	sdi, err := client.AddEntry(context.Background(), pname, psum)
	if err != nil {
		glog.Fatalf("add-entry failed: %v", err)
	}
	glog.Infof("got valid StItem: %v", sdi)
	glog.Flush()
}

func params() ([]byte, []byte, error) {
	b, err := base64.StdEncoding.DecodeString(*checksum)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding checksum: %v", err)
	}
	return []byte(*name), b, nil
}

func setup() (*client.Client, error) {
	blob, err := ioutil.ReadFile(*chain)
	if err != nil {
		return nil, fmt.Errorf("failed reading certificate chain: %v", err)
	}
	c, err := parseChain(blob)
	if err != nil {
		return nil, fmt.Errorf("failed loading certificate chain: %v", err)
	}

	blob, err = ioutil.ReadFile(*key)
	if err != nil {
		return nil, fmt.Errorf("failed reading ed25519 private key: %v", err)
	}
	k, err := parseEd25519PrivateKey(blob)
	if err != nil {
		return nil, fmt.Errorf("failed decoding ed25519 private key: %v", err)
	}

	blob, err = ioutil.ReadFile(*operators)
	if err != nil {
		return nil, fmt.Errorf("failed reading log operators: %v", err)
	}
	var ops []descriptor.Operator
	if err := json.Unmarshal(blob, &ops); err != nil {
		return nil, fmt.Errorf("failed decoding log operators: %v", err)
	}

	id, err := base64.StdEncoding.DecodeString(*logId)
	if err != nil {
		return nil, fmt.Errorf("failed decoding log identifier: %v", err)
	}

	// TODO: define FindLog() for []Operator
	var log *descriptor.Log
	for _, op := range ops {
		l, err := op.FindLog(id)
		if err == nil {
			log = l
			break
		}
	}
	if log == nil {
		return nil, fmt.Errorf("unknown log identifier: %v", err)
	}
	return client.NewClient(log, &http.Client{}, c, &k), nil
}

func parseEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem block: is empty")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("bad pem block type: %v", block.Type)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("pem block: trailing data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Errorf("x509 parser failed: %v", err)
	}
	switch t := key.(type) {
	case ed25519.PrivateKey:
		return key.(ed25519.PrivateKey), nil
	default:
		return nil, fmt.Errorf("unexpected signing key type: %v", t)
	}
}

func parseChain(rest []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected pem block type: %v", block.Type)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing x509 certificate: %v", err)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}
