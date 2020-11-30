# Create new certificate chains
## Initial setup
```
$ touch index
$ echo 1000 > serial
```

## Root certificate
```
$ openssl genpkey -algorithm ed25519 -out root.key
$ openssl req -new -x509 -config ca.conf -extensions v3_ca -days 4096 -key root.key -out root.pem
$ openssl x509 -in root.pem -text -noout
```

## Intermediate certificate
```
$ openssl genpkey -algorithm ed25519 -out intermediate.key
$ openssl req -new -config ca.conf -extensions v3_intermediate_ca -key intermediate.key -out intermediate.csr
$ openssl ca -config ca.conf -extensions v3_intermediate_ca -days 4096 -in intermediate.csr -notext -out intermediate.pem
$ openssl x509 -in intermediate.pem -text -noout
```

## End-entity certificate
```
$ openssl genpkey -algorithm ed25519 -out end-entity.key
$ openssl req -new -key end-entity.key -out end-entity.csr
$ openssl x509 -req -days 4096 -CA intermediate.pem -CAkey intermediate.key -CAcreateserial -in end-entity.csr -out end-entity.pem
$ openssl x509 -in end-entity.pem -text -noout
```

## Make chain
```
$ cat end-entity.pem > chain.pem
$ cat intermediate.pem >> chain.pem
```
