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
	operators      = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId          = flag.String("log_id", "AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc=", "base64-encoded log identifier")
	signedTreeHead = flag.String("sth", "AAEjAAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGcAAAF3Ts1DPAAAAAAAAACKIOjuyYlimCylCNmIliPWn+O+oOPpvdtllbJnp+xKV3qhAAAAQKW2+4+3a2cgERULDrbwoeevo6q1JxY8mcj73XPLAhcmlR/YmtuWv6PEJYiLP/bclN6ZQ5ttQq1/9hG+VvgLvA4=", "base64-encoded StItem of type StFormatSignedTreeHeadV1")
	entry          = flag.String("entry", "AAUFZGViaTYw50e7967bce266a506f8f614bb5096beba580d205046b918f47d23b2ec626d75eAAEgHOQFUkKNWpjYAhNKTyWCzahlI7RDtf5123kHD2LACj0=", "base64-encoded StItem of type StFormatChecksumV1")
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

	// Check STH
	var sth stfe.StItem
	if err := sth.UnmarshalB64(*signedTreeHead); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	th, err := sth.SignedTreeHeadV1.TreeHead.Marshal()
	if err != nil {
		glog.Fatalf("cannot marshal tree head: %v", err)
	}
	if err := ns.Verify(th, sth.SignedTreeHeadV1.Signature); err != nil {
		glog.Fatalf("bad signed tree head: %v", err)
	}
	glog.V(3).Info("verified sth")

	// Check inclusion
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
