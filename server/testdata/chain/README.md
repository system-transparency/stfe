# Create new certificate chains
A more in-depth explanation of the different commands and parameters can be
found in the man pages, e.g., `man openssl-genpkey` and `man openssl-req`

## Root certificate
```
# Generate ed25519 private key
$ openssl genpkey -algorithm ed25519 -out rgdd-root.key

###
# Create and self-sign a root certificate
# -x509 => output a self-signed certificate
# -new => prompt the user for relevant field values
# -key => file to read private key from
# -days => number of days that the certificate is valid
# -out => where to write the resulting PEM-encoded certificate
###
$ openssl req -x509 -new -key rgdd-root.key -days 2048 -out rgdd-root.pem

# View the generated certificate
$ openssl x509 -in rgdd-root.pem -text -noout
```

## End-entity certificates
Let's generate two different end-entity certificates.  One that uses ECDSA, and
another one that uses RSA.  Note that `-CAcreateserial` creates a file with the
next serial number if it does not exist.  After a certificate is issued, this
number is incremented.

### NIST P-256
```
$ openssl ecparam -genkey -name prime256v1 -noout -out rgdd-ecdsa.key
$ openssl req -new -key rgdd-ecdsa.key -out rgdd-ecdsa.csr
$ openssl x509 -req -in rgdd-ecdsa.csr -CA rgdd-root.pem -CAkey rgdd-root.key -CAcreateserial -out rgdd-ecdsa.pem -days 1024
$ openssl x509 -in rgdd-ecdsa.pem -text -noout
```

### RSA
```
$ openssl genrsa -out rgdd-rsa.key 4096
$ openssl req -new -key rgdd-rsa.key -out rgdd-rsa.csr
$ openssl x509 -req -in rgdd-rsa.csr -CA rgdd-root.pem -CAkey rgdd-root.key -CAcreateserial -out rgdd-rsa.pem -days 1024
$ openssl x509 -in rgdd-rsa.pem -text -noout
```
