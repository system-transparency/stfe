package main

import (
	"context"
	"flag"
	"fmt"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe"
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

	str, err := sdi.MarshalB64()
	if err != nil {
		glog.Fatalf("failed encoding valid signed debug info: %v", err)
	}
	glog.Infof("add-request succeeded: %s", str)
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
	c, err := stfe.LoadChain(*chain)
	if err != nil {
		return nil, fmt.Errorf("failed loading certificate chain: %v", err)
	}

	k, err := stfe.LoadEd25519SigningKey(*key)
	if err != nil {
		return nil, fmt.Errorf("failed loading key: %v", err)
	}

	blob, err := ioutil.ReadFile(*operators)
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

	log, err := descriptor.FindLog(ops, id)
	if err != nil {
		return nil, err
	}
	return client.NewClient(log, &http.Client{}, c, &k), nil
}
