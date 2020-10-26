# Create `item` and `signature` for the add-entry endpoint

## Create a serialized `checksum_v1` entry
The following creates a serialized `checksum_v1` StItem, such that the package
name is `foobar-0.0.1` and the checksum `SHA256(foobar-0.0.1)`.  The result is
stored in the `stitem` directory as `foobar-0.0.1`.
```
$ go run . --logtostderr --name foobar-0.0.1 --dir stitem 
```

## Sign the generated file using an end-entity certificate
Let's use our ECDSA end-entity certificate using SHA256 as the hash function.
```
$ openssl dgst -sha256 -sign "../chain/rgdd-ecdsa.key" -out stitem/foobar-0.0.1.sig stitem/foobar-0.0.1
```

## Encode the resulting StItem and its signature as base-64
```
$ openssl base64 -A -in stitem/foobar-0.0.1 -out stitem/foobar-0.0.1.b64
$ openssl base64 -A -in stitem/foobar-0.0.1.sig -out stitem/foobar-0.0.1.sig.b64
```
