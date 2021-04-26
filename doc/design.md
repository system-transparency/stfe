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
We consider a powerful attacker that gained control of a target's signing and
release infrastructure.  This covers a weaker form of attacker that is able to
sign data and distribute it to a subset of isolated users.  For example, this is
essentially what FBI requested from Apple in the San Bernardino case [\[FBI-Apple\]](https://www.eff.org/cases/apple-challenges-fbi-all-writs-act-order).
The fact that signing keys and related infrastructure components get
compromised should not be controversial [\[SolarWinds\]](https://www.zdnet.com/article/third-malware-strain-discovered-in-solarwinds-supply-chain-attack/).

The attacker can also gain control of the transparency log's signing key and
infrastructure.  This covers a weaker form of attacker that is able to sign log
data and distribute it to a subset of isolated users.  For example, this could
have been the case when a remote code execution was found for a Certificate
Transparency Log [\[DigiCert\]](https://groups.google.com/a/chromium.org/g/ct-policy/c/aKNbZuJzwfM).

Any attacker that is able to position itself to control these components will
likely be _risk-averse_.  This is at minimum due to two factors.  First,
detection would result in a significant loss of capability that is by no means
trivial to come by.  Second, detection means that some part of the attacker's
malicious behavior will be disclosed publicly.

Our goal is to facilitate _detection_ of compromised signing keys.  Therefore,
we transparency log signed checksums.  We assume that clients _fail closed_ if a
checksum does not appear in a public log.  We also assume that the attacker
controls at most a threshold of independent parties to achieve our goal
("strength in numbers").

It is a non-goal to disclose the data that a signed checksum represents.  For
example, the log cannot distinguish between a checksum that represents a tax
declaration, an ISO image, or a Debian package.  This means that the type of
detection we support is _courser-grained_ when compared to Certificate
Transparency.

## Design
