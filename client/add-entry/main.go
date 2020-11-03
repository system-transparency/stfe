package main

import (
	"context"
	"flag"
	"fmt"

	"encoding/base64"
	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe/client"
)

var (
	operators = flag.String("operators", "../../server/descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=", "base64-encoded log identifier")
	chain     = flag.String("chain", "../../server/testdata/x509/chain.pem", "path to pem-encoded certificate chain that the log accepts")
	key       = flag.String("key", "../../server/testdata/x509/end-entity.key", "path to ed25519 private key that corresponds to the chain's end-entity certificate")
	name      = flag.String("name", "foobar-1.2.3", "package name")
	checksum  = flag.String("checksum", "50e7967bce266a506f8f614bb5096beba580d205046b918f47d23b2ec626d75e", "base64-encoded package checksum")
)

func main() {
	flag.Parse()

	pname := []byte(*name)
	psum, err := base64.StdEncoding.DecodeString(*checksum)
	if err != nil {
		glog.Fatalf("failed decoding checksum: %v", err)
	}

	client, err := client.NewClientFromPath(*logId, *chain, *key, *operators, &http.Client{}, true)
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
	fmt.Println(str)

	glog.Flush()
}
