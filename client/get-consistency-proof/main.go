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
	"github.com/system-transparency/stfe/descriptor"
)

var (
	operators = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc=", "base64-encoded log identifier")
	first     = flag.String("first", "AAEjAAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGcAAAF3TqQQZAAAAAAAAACEIEV75viH3o4llUxCqwoTvY38vKUiv2lg4uFd1jTfcCC5AAAAQBoc5JvG6AovqHjZAU77zrsrIN8ZuR3DIwYAFD2mcvyI/b2KcIPxH6XQ7+zTnGJPWfgwvI5sCuu/MBAAHEzZzQk=", "first base64-encoded StItem of type StFormatSignedTreeHeadV1")
	second    = flag.String("second", "AAEjAAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGcAAAF3TrZf7gAAAAAAAACJIEl/yYdMBb6st/D4yQXRXIAphR7i2y10jB/BbnQljy8rAAAAQBzYrWNidZ8bCdaHqi5zgxGJ6HQNfYihDhRQy20lu36a/yxKqgrvoH+dv969c4aeBEAGz5TSSAn5CwqmqUFSAQo=", "second base64-encoded StItem of type StFormatSignedTreeHeadV1")
)

func main() {
	flag.Parse()

	cli, err := client.NewClient(mustLoad(*operators, *logId), &http.Client{}, true, nil)
	if err != nil {
		glog.Fatal(err)
	}
	ns, err := cli.Log.Namespace()
	if err != nil {
		glog.Fatalf("bad log namespace: %v", err)
	}

	// Check first STH
	var sth1 stfe.StItem
	if err := sth1.UnmarshalB64(*first); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	th1, err := sth1.SignedTreeHeadV1.TreeHead.Marshal()
	if err != nil {
		glog.Fatalf("cannot marshal tree head: %v", err)
	}
	if err := ns.Verify(th1, sth1.SignedTreeHeadV1.Signature); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	glog.V(3).Info("verified first sth")

	// Check second STH
	var sth2 stfe.StItem
	if err := sth2.UnmarshalB64(*second); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	th2, err := sth2.SignedTreeHeadV1.TreeHead.Marshal()
	if err != nil {
		glog.Fatalf("cannot marshal tree head: %v", err)
	}
	if err := ns.Verify(th2, sth2.SignedTreeHeadV1.Signature); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	glog.V(3).Info("verified second sth")

	// Check consistency
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

func mustLoad(operators, logId string) *descriptor.Log {
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
	return log
}
