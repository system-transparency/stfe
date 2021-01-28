# System Transparency Log
This document provides a sketch of System Transparency (ST) logging.  The basic
idea is to insert hashes of system artifacts into a public, append-only, and
tamper-evident transparency log, such that any enforcing client can be sure that
they see the same system artifacts as everyone else.  A system artifact could
be an operating system image, a Debian package, or a browser update (to mention
a few examples).

An ST log can be implemented on-top of
[Trillian](https://trillian.transparency.dev) using a custom STFE personality.
For reference you may look at Certificate Transparency (CT) logging and
[CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe),
which implements [RFC 6962](https://tools.ietf.org/html/rfc6962).

We take inspiration from from RFC 6962 and its follow-up specification [RFC
6962/bis](https://datatracker.ietf.org/doc/draft-ietf-trans-rfc6962-bis/).

## Log parameters
A log is defined by the following immutable parameters:
- Log identifier: serialized namespace of type `ed25519_v1` that defines the
log's signing algorithm and public verification key.
- Supported namespaces: a list of namespace types the log supports.  Submitters
must use a supported namespace type when adding new entries.
- Base URL: where can this log be reached?  E.g., example.com:1234/log

Note that **there is no Maximum Merge Delay (MMD)**, which is in contrast to RFC
6962.  New entries are merged into the log as soon as possible, and no client
should trust that something is logged until an inclusion proof can be provided
that references a trustworthy STH. 

We use the same hash strategy as described in RFC 6962: SHA256 with `0x00` as
leaf node prefix and `0x01` as interior node prefix.

## Minimum acceptance criteria
A log should accept a submission if it is:
- Well-formed, see below.
- Digitally signed
	- Verification key must be registered in the log as a namespace
	- Proves which namespace submitted an entry for logging

## Data structure definitions
Data structures are defined and serialized using the presentation language in
[RFC 5246, §4](https://tools.ietf.org/html/rfc5246).  A definition of the log's
Merkle tree can be found in [RFC 6962,
§2](https://tools.ietf.org/html/rfc6962#section-2).

### Repurposing `TransItem` as `StItem`
A general-purpose `TransItem` is defined in [RFC 6962/bis,
§4.5](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.5).
We define our own `TransItem`, but name it `STItem` to emphasize that they are
not the same.  Some definitions are re-used while others are added.

```
enum {
	reserved(0),
	signed_tree_head_v1(1), // defined in RFC 6962/bis, §4.10
	signed_debug_info_v1(2), // defined below, think "almost SCT"
	consistency_proof_v1(3), // defined in RFC 6962/bis, §4.11
	inclusion_proof_v1(4), // defined in RFC 6962/bis, §4.12
	checksum_v1(5), // defined below, think "leaf data"
	(65535)
} StFormat;

struct {
	StFormat format;
	select (format) {
		case signed_tree_head_v1: SignedTreeHeadV1;
		case signed_debug_info_v1: SignedDebugInfoV1;
		case consistency_proof_v1: ConsistencyProofV1;
		case inclusion_proof_v1: InclusionProofV1;
		case checksum_v1: ChecksumV1;
	} message;
} StItem;
```

### Namespace
A _namespace_ is a versioned data structure that contains a public verification
key (or fingerprint), as well as enough information to determine its format,
signing, and verification operations.  Namespaces are used as identifiers, both
for the log itself and the parties that submit artifact hashes.
```
enum {
	reserved(0),
	ed25519_v1(1),
	(65535)
} NamespaceFormat;

struct {
	NamespaceFormat format;
	select (format) {
		case ed25519_v1: Ed25519V1;
	} message;
} Namespace;
```

A log may reject submissions that correspond to an unknown namespace, or because
a trusted namespace exceeded a configured rate limit.  As such, it is possible
to use namespaces as an anti-spam feature.

Namespaces also allow us to separate different ecosystems.  For example,
software publisher _A_ can be sure that publicly logged artifact hashes are only
considered valid if signed by their own namespace(s).

(Credit: our namespace format is inspired by Keybase's
key-id](https://keybase.io/docs/api/1.0/kid).)

#### Ed25519V1
At this time the only supported namespace type is based on Ed25519, see [RFC
8032](https://tools.ietf.org/html/rfc8032).  The namespace field contains the
full verification key.
```
struct {
	opaque namespace<32>; // public verification key
} Ed25519V1;
```

#### Other
In the future we will support other key types, such as RSA.  For example, we
could add [RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2)
as follows:
1. Add `rsa_v1` format and RSAV1 namespace.  This is what we would register on
the server-side such that the server knows the namespace and complete key.
```
struct {
	opaque namespace<32>; // key fingerprint
	// + some encoding of public key
} RSAV1;
```
2. Add `rsassa_pkcs1_5_v1` format and `RSASSAPKCS1_5_v1`.  This is what the
submitter would use to communicate namespace and RSA signature mode.
```
struct {
	opaque namespace<32>; // key fingerprint
	// + necessary parameters, e.g., SHA256 as hash function
} RSASSAPKCS1_5V1;
```

This is just one of several options.  To be decided later on.

### Merkle tree leaf types
In the future there might be several types of leaves.  Say, one for operating
system packages, another one for Debian packages, and a third one for
general-purpose checksums.  For now we only define the latter.

TODO: scope of this spec should only be checksum

#### Checksum

```
struct {
	opaque package<1..2^8-1>; // package identifier
	opaque checksum<1..64>; // hash of some artifact
	Namespace namespace;
} ChecksumV1;
```

A checksum entry contains a package identifier such as `foobar-1.2.3` and an
artifact hash.  For example, the checksum type could be used by Firefox to
[enforce public binary logging before accepting a new software
update](https://wiki.mozilla.org/Security/Binary_Transparency).  It is assumed
that the entities relying on the checksum type know how to find the artifact
source (if not already at hand) and then reproduce the logged hash from it.

Namespace is used to determine which ecosystem an artifact belongs to.  However,
note that we do not connect namespaces to real-world identities: it is up to the
respective ecosystems to communicate their own namespaces, e.g., by establishing
namespaces based on trusted verification keys that already sign their artifacts.

### Signed Debug Info
RFC 6962 uses Signed Certificate Timestamps (SCTs) as promises of public
logging within a time known as the Maximum Merge Delay (MMD).  We provide no
such promise: a Signed Debug Info (SDI) is an intent to log because the
submitter is authorized to do so and the entry appears to be valid.  It will be
merged into the log's Merkle tree as soon as possible on a best-effort basis.
If an unexpected delay is encountered, the submitter can present the issued SDI
to the log operator (who can then investigate the underlying reason further).
```
struct {
	Namespace log_id;
	opaque message<1..2^16-1> // debug string that is only meant for the log
	opaque signature <1..2^16-1; // computed over a leaf-type StItem
} SignedDebugInfoV1;
```

Signature formatting and verification operations follow from the log's
namespace identifier.

TODO: remove SDI?

## Public endpoints
Clients talk to the log with HTTPS GET/POST requests.  POST parameters
are JSON objects, GET parameters are URL encoded, and serialized data is
expressed as base-64.  See details in as in RFC 6962,
[§4](https://tools.ietf.org/html/rfc6962#section-4).

TODO: remove json
TODO: and b64?

Unless specified otherwise, the data in question is serialized.

### add-entry
```
POST https://<base url>/st/v1/add-entry
```

Input:
- item: an `StItem` that corresponds to a valid leaf type.  Only
`checksum_v1` at this time.
- signature: covers the submitted item.

Output:
- an `StItem` structure of type `signed_debug_info_v1` that covers the added
item.

### get-entries
```
GET https://<base url>/st/v1/get-entries
```

Input:
- start: 0-based index of first entry to retrieve in decimal.
- end: 0-based index of last entry to retrieve in decimal.

Output:
- an array of objects, each consisting of
	- leaf: `StItem` that corresponds to the leaf's type.
	- signature: signature that covers the retrieved item using the below
	signature scheme.

### get-namespaces
```
GET https://<base url>/st/v1/get-namespaces
```

No input.

Output:
- an array of base-64 encoded namespaces that the log accept.

### get-proof-by-hash
```
GET https://<base url>/st/v1/get-proof-by-hash
```

Input:
- hash: a base-64 encoded leaf hash.
- tree_size: the tree size that the proof should be based on in decimal.

The leaf hash value is computed as in RFC 6962/bis,
[§4.7](https://datatracker.ietf.org/doc/html/draft-ietf-trans-rfc6962-bis-34#section-4.7).

Output:
- an `StItem` of type `inclusion_proof_v1`.  Note that this structure includes
both the leaf index and an audit path for the tree size.

### get-consistency-proof
```
GET https://<base url>/st/v1/get-consistency-proof
```

Input:
- first: the `tree_size` of the older tree in decimal.
- second: the `tree_size` of the newer tree in decimal.

Output:
- an `StItem` of type `consistency_proof_v1` that corresponds to
the requested tree sizes.

### get-sth
```
GET https://<base url>/st/v1/get-sth
```

No input.

Output:
- an `StItem` of type `signed_tree_head_v1`, which corresponds to the most
recently known STH.
