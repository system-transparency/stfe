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
	operators = flag.String("operators", "../../descriptor/stfe.json", "path to json-encoded list of log operators")
	logId     = flag.String("log_id", "B9oCJk4XIOMXba8dBM5yUj+NLtqTE6xHwbvR9dYkHPM=", "base64-encoded log identifier")
)

func main() {
	flag.Parse()

	client, err := client.NewClientFromPath(*logId, "", "", *operators, &http.Client{}, true)
	if err != nil {
		glog.Fatal(err)
	}

	anchors, err := client.GetAnchors(context.Background())
	if err != nil {
		glog.Fatal(err)
	}
	for i, anchor := range anchors {
		glog.V(3).Infof("anchor[%d] serial number: %x", i, anchor.SerialNumber)
		fmt.Printf("anchor[%d]: %s\n", i, base64.StdEncoding.EncodeToString(anchor.Raw))
	}

	glog.Flush()
}
