package main

import (
	"flag"
	"os"

	"crypto/sha256"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/system-transparency/stfe"
)

var (
	name = flag.String("name", "foobar-1.2.3", "a package identifier")
	dir  = flag.String("dir", "stitem", "directory path where output is stored")
)

func main() {
	flag.Parse()

	// Use H(name) as a dummy checksum
	hasher := sha256.New()
	hasher.Write([]byte(*name))
	checksum := hasher.Sum(nil)

	// Create and serialize an StItem of type checksum_v1
	serialized, err := stfe.NewChecksumV1([]byte(*name), checksum).Marshal()
	if err != nil {
		glog.Fatalf("%v", err)
	}

	// Store the serialized item in *dir/name
	if err := os.MkdirAll(*dir, 0755); err != nil {
		glog.Fatalf("creating directory %s failed: %v", *dir, err)
	}
	path := *dir + "/" + *name
	if err := ioutil.WriteFile(path, serialized, 0644); err != nil {
		glog.Fatalf("writing to %s failed: %v", path, err)
	}

	glog.Infof("Created serialized checksum_v1 StItem: %s", path)
	glog.Flush()
}
