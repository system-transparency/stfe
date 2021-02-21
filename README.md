# System Transparency Logging
This document provides a sketch of System Transparency (ST) logging.  The basic
idea is to insert hashes of system artifacts into a public, append-only, and
tamper-evident transparency log, such that any enforcing client can be sure that
they see the same system artifacts as everyone else.  A system artifact could
be a browser update, an operating system image, a Debian package, or more
generally something that is opaque.

We take inspiration from the Certificate Transparency Front-End
([CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe))
that implements [RFC 6962](https://tools.ietf.org/html/rfc6962) for
[Trillian](https://transparency.dev).

## Log parameters
An ST log is defined by the following parameters:
- `log_identifier`: a `Namespace` of type `ed25519_v1` that defines the log's
signing algorithm and public verification key.
- `supported_namespaces`: a list of namespace types that the log supports.
Entities must use a supported namespace type when posting signed data to the
log.
- `base_url`: prefix used by clients that contact the log, e.g.,
example.com:1234/log.
- `final_cosigned_tree_head`: an `StItem` of type `cosigned_tree_head_v*`.  Not
set until the log is turned into read-only mode in preparation of a shutdown.

ST logs use the same hash strategy as described in RFC 6962: SHA256 with `0x00`
as leaf node prefix and `0x01` as interior node prefix.

In contrast to Certificate Transparency (CT) **there is no Maximum Merge Delay
(MMD)**.  New entries are merged into the log as soon as possible, and no client
should trust that something is logged until an inclusion proof can be provided
that references a trustworthy STH.  Therefore, **there are no "promises" of
public logging** as in CT.

To produce trustworthy STHs a simple form of [witness
cosigning](https://arxiv.org/pdf/1503.08768.pdf) is built into the log.
Witnesses poll the log for the next stable STH, and verify that it is consistent
before posting a cosignature that can then be served by the log.

## Acceptance criteria and scope
A log should accept a leaf submission if it is:
- Well-formed, see data structure definitions below.
- Digitally signed by a registered namespace.

Rate limits may be applied per namespace to combat spam.  Namespaces may also be
used by clients to determine which entries belong to who.  It is up to the
submitters to communicate trusted namespaces to their own clients.  In other
words, there are no mappings from namespaces to identities built into the log.
There is also no revocation of namespaces: **we facilitate _detection_ of
compromised signing keys by making artifact hashes public, which is not to be
confused with _prevention_ or even _recovery_ after detection**.

## Data structure definitions
Data structures are defined and serialized using the presentation language in
[RFC 5246, §4](https://tools.ietf.org/html/rfc5246).  A definition of the log's
Merkle tree can be found in [RFC 6962,
§2](https://tools.ietf.org/html/rfc6962#section-2).

### Namespace
A _namespace_ is a versioned data structure that contains a public verification
key (or fingerprint), as well as enough information to determine its format,
signing, and verification operations.  Namespaces are used as identifiers, both
for the log itself and the parties that submit artifact hashes and cosignatures.

```
enum {
	reserved(0),
	ed25519_v1(1),
	(2^16-1)
} NamespaceFormat;

struct {
	NamespaceFormat format;
	select (format) {
		case ed25519_v1: Ed25519V1;
	} message;
} Namespace;
```

Our namespace format is inspired by Keybase's
[key-id](https://keybase.io/docs/api/1.0/kid).

#### Ed25519V1
At this time the only supported namespace type is based on Ed25519.  The
namespace field contains the full verification key.  Signing operations and
serialized formats are defined by [RFC
8032](https://tools.ietf.org/html/rfc8032).
```
struct {
	opaque namespace[32]; // public verification key
} Ed25519V1;
```

### `StItem`
A general-purpose `TransItem` is defined in [RFC 6962/bis,
§4.5](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.5).
We define our own `TransItem`, but name it `StItem` to emphasize that they are
not the same.

```
enum {
	reserved(0),
	signed_tree_head_v1(1),
	cosigned_tree_head_v1(2),
	consistency_proof_v1(3),
	inclusion_proof_v1(4),
	signed_checksum_v1(5), // leaf type
	(2^16-1)
} StFormat;

struct {
	StFormat format;
	select (format) {
		case signed_tree_head_v1: SignedTreeHeadV1;
		case cosigned_tree_head_v1: CosignedTreeHeadV1;
		case consistency_proof_v1: ConsistencyProofV1;
		case inclusion_proof_v1: InclusionProofV1;
		case signed_checksum_v1: SignedChecksumV1;
	} message;
} StItem;

struct {
	StItem item<0..2^32-1>;
} StItemList;
```

#### `signed_tree_head_v1`
We use the same tree head definition as in [RFC 6962/bis,
§4.9](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.9).
The resulting _signed_ tree head is packaged differently: a namespace is used as
log identifier, and it is communicated in a `SignatureV1` structure.
```
struct {
	TreeHeadV1 tree_head;
	SignatureV1 signature;
} SignedTreeHeadV1;

struct {
	uint64 timestamp;
	uint64 tree_size;
	NodeHash root_hash;
	Extension extensions<0..2^16-1>;
} TreeHeadV1;
opaque NodeHash<32..2^8-1>;

struct {
	Namespace namespace;
	opaque signature<0..2^16-1>;
} SignatureV1;
```

#### `cosigned_tree_head_v1`
Transparency logs were designed to be cryptographically verifiable in the
presence of a gossip-audit model that ensures everyone observes _the same
cryptographically verifiable log_.  The gossip-audit model is largely undefined
in today's existing transparency logging ecosystems, which means that the logs
must be trusted to play by the rules.   We wanted to avoid that outcome in our
ecosystem.  Therefore, a gossip-audit model is built into the log.

The basic idea is that an STH should only be considered valid if it is cosigned
by a number of witnesses that verify the append-only property.  Which witnesses
to trust and under what circumstances is defined by a client-side _witness
cosigning policy_.  For example,
	"require no witness cosigning",
	"must have at least `k` signatures from witnesses A...J", and
	"must have at least `k` signatures from witnesses A...J where one is from
		witness B".

Witness cosigning policies are beyond the scope of this specification.

A cosigned STH is composed of an STH and a list of cosignatures.  A cosignature
must cover the serialized STH as an `StItem`, and be produced with a witness
namespace of type `ed25519_v1`.

```
struct {
	SignedTreeHeadV1 sth;
	SignatureV1 cosignatures<0..2^32-1>; // vector of cosignatures
} CosignedTreeHeadV1;
```

#### `consistency_proof_v1`
For the most part we use the same consistency proof definition as in [RFC
6962/bis,
§4.11](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.11).
There are two modifications: our log identifier is a namespace rather than an
[OID](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.4),
and a consistency proof may be empty.

```
struct {
	Namespace namespace; // log identifier
	uint64 tree_size_1;
	uint64 tree_size_2;
	NodeHash consistency_path<0..2^16-1>;
} ConsistencyProofV1;
```

#### `inclusion_proof_v1`
For the most part we use the same inclusion proof definition as in [RFC
6962/bis,
§4.12](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.12).
There are two modifications: our log identifier is a namespace rather than an
[OID](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-34#section-4.4),
and an inclusion proof may be empty.
```
struct {
	Namespace namespace; // log identifier
	uint64 tree_size;
	uint64 leaf_index;
	NodeHash inclusion_path<0..2^16-1>;
} InclusionProofV1;
```

#### `signed_checksum_v1`
A checksum entry contains a package identifier like `foobar-1.2.3` and an
artifact hash.   It is then signed so that clients can distinguish artifact
hashes from two different software publishers A and B.  For example, the
`signed_checksum_v1` type can help [enforce public binary logging before
accepting a new software
update](https://wiki.mozilla.org/Security/Binary_Transparency).

```
struct {
	ChecksumDataV1 data;
	SignatureV1 signature;
} SignedChecksumV1;

struct {
	opaque identifier<1..128>;
	opaque checksum<1..64>;
} ChecksumV1;
```

It is assumed that clients know how to find the real artifact source (if not
already at hand), such that the logged hash can be recomputed and compared for
equality.  The log is not aware of how artifact hashes are computed, which means
that it is up to the submitters to define hash functions, data formats, and
such.

## Public endpoints
Clients talk to the log using HTTP(S). Parameters for HTTP GET requests are
URL-encoded with `Content-Type: application/x-www-form-urlencoded`. In
contrast, HTTP POST requests post a single base64-encoded serialized `StItem`
with `Content-Type: text/plain`.  The log returns HTTP Status `200 OK` to
signal success, and the response (if any) is serialized and then base64-encoded
with `Content-Type: text/plain`.

### add-entry
```
POST https://<base url>/st/v1/add-entry
```

Input:
- An `StItem` of type `signed_checksum_v1`.

No output.

### add-cosignature
```
POST https://<base url>/st/v1/add-cosignature
```

Input:
- An `StItem` of type `cosigned_tree_head_v1`.  The list of cosignatures must
be of length one, the witness signature must cover the item's STH, and that STH
must additionally match the log's stable STH that is currently being cosigned.

No output.

### get-latest-sth
```
GET https://<base url>/st/v1/get-latest-sth
```

No input.

Output:
- An `StItem` of type `signed_tree_head_v1` that corresponds to the most
recent STH.

### get-stable-sth
```
GET https://<base url>/st/v1/get-stable-sth
```

No input.

Output:
- An `StItem` of type `signed_tree_head_v1` that corresponds to a stable STH
that witnesses should cosign.  The same STH is returned for a period of time.

### get-cosigned-sth
```
GET https://<base url>/st/v1/get-cosigned-sth
```

No input.

Output:
- An `StItem` of type `cosigned_tree_head_v1` that corresponds to the most
recent cosigned STH.

### get-proof-by-hash
```
GET https://<base url>/st/v1/get-proof-by-hash
```

Input:
- `hash`: a base-64 encoded leaf hash using the log's hash function.
- `tree_size`: the tree size that the proof should be based on in decimal.

Output:
- An `StItem` of type `inclusion_proof_v1`.

### get-consistency-proof
```
GET https://<base url>/st/v1/get-consistency-proof
```

Input:
- first: the `tree_size` of the older tree in decimal.
- second: the `tree_size` of the newer tree in decimal.

Output:
- An `StItem` of type `consistency_proof_v1`.

### get-entries
```
GET https://<base url>/st/v1/get-entries
```

Input:
- `start`: 0-based index of first entry to retrieve in decimal.
- `end`: 0-based index of last entry to retrieve in decimal.

Output:
- An `StItem` list where each entry is of type `signed_checksum_v1`.  The first
`StItem` corresponds to the start index, the second one to `start+1`, etc.  The
log may return fewer entries than requested.

# Appendix A
In the future other namespace types might be supported.  For example, we could
add [RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) as
follows:
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
