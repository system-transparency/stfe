# Run Trillian + STFE locally
Trillian uses a database.  So, we will need to set that up.  It is documented
[here](https://github.com/google/trillian#mysql-setup), and how to check that it
is setup properly
[here](https://github.com/google/certificate-transparency-go/blob/master/trillian/docs/ManualDeployment.md#data-storage).

Other than the database we need the Trillian log signer, Trillian log server,
and STFE server.
```
$ go install github.com/google/trillian/cmd/trillian_log_signer
$ go install github.com/google/trillian/cmd/trillian_log_server
$ go install
```

Start Trillian log signer:
```
trillian_log_signer --logtostderr -v 9 --force_master --rpc_endpoint=localhost:6961 --http_endpoint=localhost:6964 --num_sequencers 1 --sequencer_interval 100ms --batch_size 100
```

Start Trillian log server:
```
trillian_log_server --logtostderr -v 9 --rpc_endpoint=localhost:6962 --http_endpoint=localhost:6963
```

As described in more detail
[here](https://github.com/google/certificate-transparency-go/blob/master/trillian/docs/ManualDeployment.md#trillian-services),
we need to provision a Merkle tree once:
```
$ go install github.com/google/trillian/cmd/createtree
$ createtree --admin_server localhost:6962
<tree id>
```

Hang on to `<tree id>`.  Our STFE server will use it when talking to the
Trillian log server to specify which Merkle tree we are working against.

(If you take a look in the `Trees` table you will see that the tree has been
provisioned.)

We will also need a public key-pair and log identifier for the STFE server.
```
$ go install github.com/system-transparency/stfe/types/cmd/new-namespace
sk: <sk>
vk: <vk>
ed25519_v1: <namespace>
```

The log's identifier is `<namespace>` and contains the public verification key
`<vk>`.  The log's corresponding secret signing key is `<sk>`.

Start STFE server:
```
$ ./server --logtostderr -v 9 --http_endpoint localhost:6965 --log_rpc_server localhost:6962 --trillian_id <tree id> --key <sk>
```

If the log is responsive on, e.g., `GET http://localhost:6965/st/v1/get-latest-sth` you
may want to try running
`github.com/system-transparency/stfe/client/cmd/example.sh`.  You need to
configure the log's id though for verification to work (flag `log_id`, which
should be set to the `<namespace>` output above).
