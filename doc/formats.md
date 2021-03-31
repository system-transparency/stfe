# Formats
This document defines data structures and data formats.

## Overview
Here we give an overview of our presentation language / serialization rules.

All integers are represented by 64-bit unsigned integers in network byte order.

Variable length lists have an integer specifying its length.  Then each list
item is enumerated.

TODO: fixme.

## Items
Every item type start with a versioned format specifier.  Protocol version 1
uses format specifiers in the range 1--X.

### Request data structures
Log endpoints that take input data use the following request data structures.

#### `get_entries_v1`
```
0  Format  8                16               24
+----------+----------------+----------------+
|    1     |   Start Size   |    End Size    |
+----------+----------------+----------------+
   uint64        uint64           uint64
```
- Format is always 1 for items of type `get_entries_v1`.
- Start size specifies the index of the first Merkle tree leaf to retrieve.
- End size specifies the index of the last Merkle tree leaf to retrieve.

#### `get_proof_by_hash_v1`
```
0  Format  8                16               48
+----------+----------------+----------------+
|    2     |   Tree size    |    Leaf hash   |
+----------+----------------+----------------+
   uint64        uint64      fixed byte array
```
- Format is always 2 for items of type `get_proof_by_hash_v1`.
- Leaf hash is computed as described in [RFC 6962/bis, §2.1.1](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-35#section-2.1.1).
- Tree size specifies which Merkle tree root inclusion should be proven for.

#### `get_consistency_proof_v1`
```
0  Format  8                16               24
+----------+----------------+----------------+
|    3     |    Old size    |    New size    |
+----------+----------------+----------------+
   uint64        uint64           uint64
```
- Format is always 3 for items of type `get_consistency_proof_v1`.
- Old size specifies the tree size of an older Merkle tree head.
- New size specifies the tree size of a newer Merkle tree head.

### Proof and log data structures
#### `inclusion_proof_v1`
```
                                                                               --zero or more node hashes-->
0  Format  8                48               56               64               72                 72+Length
+----------+----------------+----------------+----------------+----------------+--------//--------+
|    4     |   Identifier   |    Tree size   |    Leaf index  |     Length     |    Node hashes   |
+----------+----------------+----------------+----------------+----------------+--------//--------+
   uint64      ed25519_v1         uint64           uint64           uint64           list body
```
- Format is always 4 for items of type `inclusion_proof_v1`.
- Identifier identifies the log uniquely as an `ed25519_v1` item.
- Tree size is the size of the Merkle tree that the proof is based on.
- Leaf index is a zero-based index of the log entry that the proof is based on.
- The remaining part is a list of node hashes.
	- Length specifies the full byte size of the list.  It must be `32 * m`,
	where `m >= 0`.  This means that an inclusion needs zero or more node
	hashes to be well-formed.
	- Node hash is a node hash in the Merkle tree that the proof is based on.

Remark: the list of node hashes is generated and verified as in [RFC 6962/bis,
§2.1.3](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-35#section-2.1.3).

#### `consistency_proof_v1`
```
                                                                               --zero or more node hashes-->
0  Format  8                48               56               64               72                 72+Length
+----------+----------------+----------------+----------------+----------------+--------//--------+
|    5     |   Identifier   |    Old size    |    New size    |     Length     |    Node hashes   |
+----------+----------------+----------------+----------------+----------------+--------//--------+
   uint64     ed25519_v1          uint64           uint64           uint64           list body
```
- Format is always 5 for items of type `consistency_proof_v1`.
- Identifier identifies the log uniquely as an `ed25519_v1` item.
- Old size is the tree size of the older Merkle tree.
- New size is the tree size of the newer Merkle tree.
- The remaining part is a list of node hashes.
	- Length specifies the full byte size of the list.  It must be `32 * m`,
	where `m >= 0`.  This means that a consistenty proof needs zero or more node
	hashes to be well-formed.
	- Node hash is a node hash from the older or the newer Merkle tree.

Remark: the list of node hashes is generated and verified as in [RFC 6962/bis,
§2.1.4](https://tools.ietf.org/html/draft-ietf-trans-rfc6962-bis-35#section-2.1.4).

#### `signed_tree_head_v1`
```
                                                                               ----one or more signature-identifier pairs------->
0  Format  8               16               24               56                64               128              168    64+Length
+----------+----------------+----------------+----------------+----------------+----------------+----------------+--//--+
|    6     |   Timestamp    |   Tree size    |    Root hash   |     Length     |    Signature   |   Identifier   | .... |
+----------+----------------+----------------+----------------+----------------+----------------+----------------+--//--+
   uint64        uint64           uint64      fixed byte array      uint64      fixed byte array     ed25519_v1   cont. list body
```
- Format is always 6 for items of type `signed_tree_head_v1`.
- Timestamp is the time since the UNIX epoch (January 1, 1970 00:00:00 UTC) in
milliseconds.
- Tree size is the number of leaves in the current Merkle tree.
- Root hash is the root hash of the current Merkle tree.
- The remaining part is a list of signature-identifier pairs. 
	- Length specifies the full byte size of the list.  It must be `104 * m`,
	where `m > 1`.  This means that a signed tree head needs at least one
	signature-identifier pair to be well-formed.
	- Signature is an Ed25519 signature over bytes 0--56.  The signature is
	encodes as in [RFC 8032, §3.3](https://tools.ietf.org/html/rfc8032#section-3.3).
	- Identifier identifies the signer uniquely as an `ed25519_v1` item.

Remark: there may be multiple signature-identifier pairs if the log is cosigned.

#### `signed_checksum32_ed25519_v1`
```
0  Format  8                40               56                 56+Length        120+Length         160+Length
+----------+----------------+----------------+-------//---------+----------------+--------//--------+
|    7     |     Checksum   |     Length     |    Identifier    |    Signature   |    Namespace     |
+----------+----------------+----------------+-------//---------+----------------+--------//--------+
   uint64   fixed byte array      uint64          byte array     fixed byte array      ed25519_v1
```
- Format is always 7 for items of type `signed_checksum32_ed25519_v1`.
- Checksum is a 32-byte checksum that represents a data item of opaque type.
- Length specified the full byte size of the following identifier.  It must be
larger than zero and less than 128.
- Identifier identifies what the checksum represents.  The aforementioned length
constraint means that the identifier cannot be omitted or exceed 128 bytes.
- Signature is an Ed25519 signature over bytes 0--56+Length.  The signature is
encodes as in [RFC 8032, §3.3](https://tools.ietf.org/html/rfc8032#section-3.3).
- Namespace is an `ed25519_v1` item that identifies the signer uniquely.

Remark: to keep this checksum entry as simple as possible it does not have a
variable length checksum or any agility with regards to the signing namespace.
This means that we need to have multiple leaf types that follow the pattern
`signed_checksum{32,64}_namespace_v1`.

### Namespace data structures
#### `ed25519_v1`
```
0  Format  8                40
+----------+----------------+
|    8     |   public key   |
+----------+----------------+
   uint64   fixed byte array
```
- The format is always 8 for items of type `ed25519_v1`.
- The public Ed25519 verification key is always 32 bytes.  See encoding in [RFC
8032, §3.2](https://tools.ietf.org/html/rfc8032#section-3.2).
