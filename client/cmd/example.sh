#!/bin/bash
set -eu

log_url=http://tlog-poc.system-transparency.org:4780/st/v1
log_id=AAG+ZW+UesWdMFytUGkp28csBcziomSB3U2vvkAW55MVZQ==
tmpdir=$(mktemp -dt stfe.XXXXXXXX)
cp $0 $tmpdir/
cd $tmpdir

commonargs="--log_id $log_id --log_url $log_url" # --logtostderr -v 3
pause="sleep 1"

echo "arguments used:"
echo $commonargs
echo ""

echo "fetching sth..."
get-sth $commonargs | tee sth1.output
echo "" && $pause

echo "adding an entry..."
add-entry $commonargs \
	--identifier "example.sh v0.0.1-$(cat /dev/urandom | base64 | head -c 10)" \
	--checksum $(sha256sum "$0") | tee add-entry.output
echo "" && $pause

echo "fetching another sth..."
get-sth $commonargs | tee sth2.output
echo "" && $pause

echo "verifying inclusion..."
get-proof-by-hash $commonargs \
	--leaf_hash $(cat add-entry.output | awk '{print $3}') \
	--sth $(cat sth2.output | awk '{print $2}')
echo "" && $pause

echo "verifying consistency..."
get-consistency-proof $commonargs \
	--first $(cat sth1.output | awk '{print $2}') \
	--second $(cat sth2.output | awk '{print $2}')
echo "" && $pause

echo "fetching the log's first entry..."
get-entries $commonargs --start 0 --end 0
echo ""

rm *.output $0
cd
rmdir $tmpdir
