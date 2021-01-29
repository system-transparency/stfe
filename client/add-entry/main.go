package main

import (
	"context"
	"flag"
	"fmt"

	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe/client"
	"github.com/system-transparency/stfe/descriptor"
)

var (
	operators = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc=", "base64-encoded log identifier")
	key       = flag.String("key", "Zaajc50Xt1tNpTj6WYkljzcVjLXL2CcQcHFT/xZqYEcc5AVSQo1amNgCE0pPJYLNqGUjtEO1/nXbeQcPYsAKPQ==", "base64-encoded ed25519 signing key")
	name      = flag.String("name", "foobar-1.2.3", "package name")
	checksum  = flag.String("checksum", "50e7967bce266a506f8f614bb5096beba580d205046b918f47d23b2ec626d75e", "base64-encoded package checksum")
)

func main() {
	flag.Parse()

	log, sk, sum := mustLoad(*operators, *logId, *key, *checksum)
	client, err := client.NewClient(log, &http.Client{}, true, sk)
	if err != nil {
		glog.Fatal(err)
	}

	sdi, err := client.AddEntry(context.Background(), []byte(*name), sum)
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

func mustLoad(operators, logId, key, checksum string) (*descriptor.Log, *ed25519.PrivateKey, []byte) {
	ops, err := descriptor.LoadOperators(operators)
	if err != nil {
		glog.Fatalf("failed loading log operators: %v")
	}
	id, err := base64.StdEncoding.DecodeString(logId)
	if err != nil {
		glog.Fatalf("invalid base64 log id: %v", err)
	}
	log, err := descriptor.FindLog(ops, id)
	if err != nil {
		glog.Fatalf("unknown log id: %v", err)
	}
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		glog.Fatalf("invalid base64 key: %v", err)
	}
	sk := ed25519.PrivateKey(b)
	b, err = base64.StdEncoding.DecodeString(checksum)
	if err != nil {
		glog.Fatalf("failed decoding checksum: %v", err)
	}
	return log, &sk, b
}
