package main

import (
	"context"
	"flag"
	"fmt"

	"encoding/base64"
	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/client"
)

var (
	operators      = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId          = flag.String("log_id", "B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=", "base64-encoded log identifier")
	chain          = flag.String("chain", "../../server/testdata/x509/end-entity.pem", "path to pem-encoded certificate chain that the log accepts")
	signedTreeHead = flag.String("sth", "AAEgB9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPMAAAF1jnn7fwAAAAAAAAAxICCqLJn4QWYd0aRIRjDWGf4GWalDIb/iH60jSSX89WgvAAAAQF9XPFRdM56KaelHFFg1RqjTw1yFL085zHhdNkLeZh9BCXxVTByqrHEMngAkY69EX45aJMWh9NymmPau0qoigA8=", "base64-encoded StItem of type StFormatSignedTreeHeadV1")
	entry          = flag.String("entry", "AAUBOCAsYkIyzdIhdxKU37sxCsoACg32rItmtpbZDvBv3vtkow==", "base64-encoded StItem of type StFormatChecksumV1")
)

func main() {
	flag.Parse()

	cli, err := client.NewClientFromPath(*logId, *chain, "", *operators, &http.Client{}, true)
	if err != nil {
		glog.Fatal(err)
	}

	var sth stfe.StItem
	if err := sth.UnmarshalB64(*signedTreeHead); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	if k, err := cli.Log.Key(); err != nil {
		glog.Fatalf("bad public key: %v", err)
	} else if err := client.VerifySignedTreeHeadV1(&sth, cli.Log.Scheme, k); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	glog.V(3).Info("verified sth")

	leaf, err := base64.StdEncoding.DecodeString(*entry)
	if err != nil {
		glog.Fatalf("failed decoding entry: %v", err)
	}
	proof, err := cli.GetProofByHash(context.Background(), sth.SignedTreeHeadV1.TreeHead.TreeSize, sth.SignedTreeHeadV1.TreeHead.RootHash.Data, leaf)
	if err != nil {
		glog.Fatalf("get-proof-by-hash failed: %v", err)
	}
	glog.V(3).Info("verified inclusion proof")

	str, err := proof.MarshalB64()
	if err != nil {
		glog.Fatalf("failed encoding valid inclusion proof: %v", err)
	}
	fmt.Println(str)

	glog.Flush()
}
