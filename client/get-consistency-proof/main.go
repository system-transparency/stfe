package main

import (
	"context"
	"flag"
	"fmt"

	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/client"
)

var (
	operators = flag.String("operators", "../../server/descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=", "base64-encoded log identifier")
	chain     = flag.String("chain", "../../server/testdata/x509/end-entity.pem", "path to pem-encoded certificate chain that the log accepts")
	first     = flag.String("first", "AAEgB9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPMAAAF1jnn7fwAAAAAAAAAxICCqLJn4QWYd0aRIRjDWGf4GWalDIb/iH60jSSX89WgvAAAAQF9XPFRdM56KaelHFFg1RqjTw1yFL085zHhdNkLeZh9BCXxVTByqrHEMngAkY69EX45aJMWh9NymmPau0qoigA8=", "first base64-encoded StItem of type StFormatSignedTreeHeadV1")
	second    = flag.String("second", "AAEgB9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPMAAAF1jsZrygAAAAAAAABFIL7Zz0WEolql7o7G496Izl7Qy/l2Qd/Pwc87W8jFPoL6AAAAQHc7ttIDUKuMJR7uqCLb3qqAxiwEN5KLt/7IblT7f+QaKq4BqqI3cO6vT3eMSZMHZDd4EkgvkAwo1o7IsA4N8Qc=", "second base64-encoded StItem of type StFormatSignedTreeHeadV1")
)

func main() {
	flag.Parse()

	cli, err := client.NewClientFromPath(*logId, *chain, "", *operators, &http.Client{}, true)
	if err != nil {
		glog.Fatal(err)
	}

	var sth1 stfe.StItem
	if err := sth1.UnmarshalB64(*first); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	if err := client.VerifySignedTreeHeadV1(&sth1, cli.Log.Scheme, cli.Log.Key()); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	glog.V(3).Info("verified first sth")

	var sth2 stfe.StItem
	if err := sth2.UnmarshalB64(*second); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	if err := client.VerifySignedTreeHeadV1(&sth2, cli.Log.Scheme, cli.Log.Key()); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	glog.V(3).Info("verified second sth")

	proof, err := cli.GetConsistencyProof(context.Background(), &sth1, &sth2)
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
