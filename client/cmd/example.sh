#!/bin/bash

echo "fetching sth..."
go run get-sth/main.go --logtostderr -v 3 | tee sth1.output
echo "" && sleep 1

echo "adding an entry..."
go run add-entry/main.go --logtostderr -v 3 \
	--identifier "example.sh v0.0.1-$(cat /dev/urandom | base64 | head -c 10)" \
	--checksum $(sha256sum example.sh) | tee add-entry.output
echo "" && sleep 1

echo "fetching another sth..."
go run get-sth/main.go --logtostderr -v 3 | tee sth2.output
echo "" && sleep 1

echo "verifying inclusion..."
go run get-proof-by-hash/main.go --logtostderr -v 3 \
	--leaf_hash $(cat add-entry.output | awk '{print $3}') \
	--sth $(cat sth2.output | awk '{print $2}')
echo "" && sleep 1

echo "verifying consistency..."
go run get-consistency-proof/main.go --logtostderr -v 3 \
	--first $(cat sth1.output | awk '{print $2}') \
	--second $(cat sth2.output | awk '{print $2}')
echo "" && sleep 1

echo "fetching the log's first entry..."
go run get-entries/main.go --logtostderr -v 3 --start 0 --end 0
echo ""

rm *.output
