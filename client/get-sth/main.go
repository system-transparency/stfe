package main

import (
	"context"
	"flag"
	"fmt"

	"encoding/base64"
	"net/http"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe/client"
	"github.com/system-transparency/stfe/descriptor"
)

var (
	operators = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "AAEgFKl1V+J3ib3Aav86UgGD7GRRtcKIdDhgc0G4vVD/TGc=", "base64-encoded log identifier")
)

func main() {
	flag.Parse()

	client, err := client.NewClient(mustLoad(*operators, *logId), &http.Client{}, true, nil)
	if err != nil {
		glog.Fatal(err)
	}

	sth, err := client.GetSth(context.Background())
	if err != nil {
		glog.Fatalf("get-sth failed: %v", err)
	}

	str, err := sth.MarshalB64()
	if err != nil {
		glog.Fatalf("failed encoding valid signed tree head: %v", err)
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
