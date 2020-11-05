package main

import (
	"context"
	"flag"
	"fmt"

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
