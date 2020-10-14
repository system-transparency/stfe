# System Transparency Log
This document provides a sketch of System Transparency (ST) logging.  The basic
idea is to insert hashes of system artifacts into a public, append-only, and
tamper-evident transparency log, such that any enforcing client can be sure that
they see the same system artifacts as everyone else.  A system artifact could
be a Debian package, an operating system image, or something similar that
ideally builds reproducibly.

An ST log can be implemented on-top of
[Trillian](https://trillian.transparency.dev) using a custom STFE personality.
For reference you may look at Certificate Transparency (CT) logging and
[CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe),
which implements [RFC 6962](https://tools.ietf.org/html/rfc6962).

Disclaimer: to the largest extent possible we will reuse RFC 6962 and/or its
follow-up specification
[CT/bis](https://datatracker.ietf.org/doc/draft-ietf-trans-rfc6962-bis/).

## Log parameters
A log is defined by the following immutable parameters:
- Log identifier: a unique identifier
- Public key: a unique public key
- Base URL: where can this log be reached?  E.g., example.com:1234/log
- Hash algorithm: e.g., SHA256
- Signature algorithm: e.g., ECDSA on a given curve.

Note that **there is no MMD**.  The idea is to merge added entries as soon as
possible, and no client should trust that something is logged until an inclusion
proof can be provided that references a trustworthy STH.  **SCTs are not
promises of public logging, and should only be used for debugging purposes**.

To avoid confusion we shall refer to our "debugging SCT" as... TODO: name.

## Minimum acceptance criteria
A log should accept a submission if it is:
- Well-formed, see below.
- Digitally signed
	- Proves who submitted the entry for logging
	- TODO: can we avoid the complexity of trust anchors?

## Merkle tree leaf data
```
struct {
	uint64 timestamp; // defined in RFC 6962/bis
	opaque artifact<0..2^8-1>; // a string that identifies a system artifact
	opaque hash<32..2^8-1>; // an artifact hash, produced with the log's H()
	ArtifactInfo info; // additional info that may be artifact-dependent
	opaque signature<0..2^16-1> // submitter signature, covers the above fields
} LeafData;
```

A leaf hash is computed as described in RFC 6962.

### Artifact types
Each type identifies a group of artifacts that share common properties.
```
enum {
	none(65535)
} ArtifactType;

struct {
	ArtifactType type;
	opaque data<0..2^16-1>;  // defined based on the artifact type
} ArtifactInfo;
```

TODO: examples of needed extra-info for, say, reproducible Debian packages?

#### None
The `none` type references a group of artifacts that need no further
information.  For example, Firefox could use it to [enforce public binary
logging before accepting a new software
update](https://wiki.mozilla.org/Security/Binary_Transparency).  It is assumed
that the entities relying on the `none` type know how to find the source (if
not already at hand) and then reproduce the logged hash from it.

The opaque `data` field must be empty if the `none` type is used.

## Merkle tree leaf appendix
TODO: captures who submitted this entry for logging

## Serialization
Similar to RFC 6962 we encode everything that is digitally signed as in [RFC
5246](https://tools.ietf.org/html/rfc5246).

## Public endpoints
The log's Merkle tree follows the specification in [RFC 6962,
§2](https://tools.ietf.org/html/rfc6962#section-2).  We reuse the signed tree
head (STH) as specified in [§3.5](https://tools.ietf.org/html/rfc6962#section-3.5),
and clients talk to the log with HTTPS GET/POST requests as in
[§4](https://tools.ietf.org/html/rfc6962#section-4).  Namely, POST parameters
are JSON objects, GET parameters are URL encoded, and binary data is first
expressed as base-64.

### add-entry
### get-entries
### get-trust-anchors
TODO: can we avoid this complexity?
### get-proof-by-hash
### get-consistency-proof
### get-sth
