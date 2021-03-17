# System Transparency Front-End (STFE)
STFE is a Trillian personality that allows you to log signed artifact checksums.
A client consuming artifacts (such as a browser update, a Debian package, a document,
or more generally anything opaque) may enforce that such logging takes place by
mandating that there is a public trace of each artifact before even considering
to trust it.  We refer to such a trace as a signed checksum entry: it is
composed of
	an arbitrary identifier like `stfe_client v0.0.1`,
	a checksum,
	a signature, and
	a namespace that is derived from the public verification key.
Tracking checksums as opposed to full-on artifacts makes it less costly to
operate, monitor, and audit the log.  Because these checksum entries are signed
we can:
1. **Facilitate detection of compromised signing keys**, e.g., a software
publisher can inspect the log to see if there are any unexpected artifact
checksums in their namespace.
2. **Ensure that everyone observes the same artifacts**, e.g., there should
never be two signed checksum entries with identical identifiers and namespaces
but different checksums.

The scope of STFE should not be confused with properties such as _prevention_ or
even _recovery_ after detection.  We are in the business of making things
transparent and _that is it_.

## What does it take to make an artifact public?
We glanced over the term _public trace_ a bit to quickly before.  Simply adding
something into a transparency log serves a limited purpose unless (i) clients
_fail-close_ if an artifact does not appear in a log, and (ii) everyone observes
the same consistent transparency logs; meaning append-only, and that you and I
both get the same entries and cryptographic proofs when consuming the logs.  The
first criteria requires several independent logs, such that the log ecosystem is
reliable enough.  The second criteria is often overlooked and requires a
gossip-audit model.  Therefore, we decided to build witness cosigning directly
into STFE.

The idea is that many independent witnesses _cosign_ the log's signed tree head
(STH) if and only if they see a consistent append-only log.  If enough reputable
parties signed-off the log's cryptographic state, you can be pretty sure that
you see the same log (and thus the same artifacts) as everyone else.  Moreover,
if you already rely on witness cosigning for security, all you need from your
software publisher is an artifact, a public verification key, a cosigned
STH, and an inclusion proof that is based on it.  Let me clarify why that is
excellent: client-side verification becomes completely non-interactive!

## What has been done?
STFE is in a proof-of-concept stage.  We have a
[sketch](https://github.com/system-transparency/stfe/blob/main/doc/sketch.md) of
the log's API, which basically defines data structures, data formats, and
HTTP(S) endpoints.   Be warned that it is a living design document that may be
incomplete and subject to major revisions.  For example, we are currently
thinking about data formats and which parsers are reasonable to (not) force onto
the client-side tooling.

In the near future we will setup a public STFE prototype with zero promises of
uptime, stability, etc.  In the meantime you may get your hands dirty by running
things locally.  Rough documentation is available
[here](https://github.com/system-transparency/stfe/blob/main/server/README.md).

There is a basic client (warning: _basic_) that can be used to interact with the
log, e.g., to add-entries and verify inclusion proofs against an STH.  We have
yet to add client-side support for STFE's witness cosigning APIs.
