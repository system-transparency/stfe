# System Transparency Logging: Design v0
We propose System Transparency logging.  It is similar to Certificate
Transparency, expect that cryptographically signed checksums are logged as
opposed to X.509 certificates.  Publicly logging signed checksums allow anyone
to discover which keys signed what.  As such, malicious and unintended key-usage
can be _discovered_.  We present our design and discuss how two possible
use-cases influenced it: binary transparency and reproducible builds.

**Target audience.**
You are most likely interested in transparency logs or supply-chain security.

**Preliminaries.**
You have basic understanding of cryptographic primitives like digital
signatures, hash functions, and Merkle trees.  You roughly know what problem
Certificate Transparency solves and how.  You may never have heard the term
_gossip-audit model_, or know how it is related to trust assumptions and
detectability properties.

**Warning.**
This is a work-in-progress document that may be moved or modified.

## Introduction
Transparency logs make it possible to detect unwanted events.  For example,
	are there any (mis-)issued TLS certificates [\[CT\]](https://tools.ietf.org/html/rfc6962),
	did you get a different Go module than everyone else [\[ChecksumDB\]](https://go.googlesource.com/proposal/+/master/design/25530-sumdb.md),
	or is someone running unexpected commands on your server [\[AuditLog\]](https://transparency.dev/application/reliably-log-all-actions-performed-on-your-servers/).
System Transparency logging makes signed checksums transparent.  The goal is to
_detect_ unwanted key-usage without making assumptions about the signed data.

## Threat model and (non-)goals

## Design
