# Claimant model
## **System<sup>CHECKSUM</sup>**:
System<sup>CHECKSUM</sup> is about the claims made by a _data publisher_.
* **Claim<sup>CHECKSUM</sup>**:
	_I, data publisher, claim that the data_:
	1. has cryptographic hash X
	2. can be located using X as an identifier
	3. has properties Y (_"ecosystem specific_")
* **Statement<sup>CHECKSUM</sup>**: signed checksum<br>
* **Claimant<sup>CHECKSUM</sup>**: data publisher<br>
	The data publisher is a party that wants to publish some data to an
	end-user.
* **Believer<sup>CHECKSUM</sup>**: end-user<br>
	Belief is based on seeing a valid Statement<sup>CHECKSUM</sup>.
* **Verifier<sup>CHECKSUM</sup>**: any interested party<br>
	These parties try to verify the above claims.  For example:
	* the data publisher itself (_"has my identity been compromised?"_)
	* third-parties that want to look further into the data (_"ecosystem
	specific_")
* **Arbiter<sup>CHECKSUM</sup>**:<br>
    There's no official body.  Invalidated claims would affect reputation.

**Example.**
The published data could be an executable binary from a reproducible build.  The
ecosystem-specific claim would be that the corresponding source code can be
looked-up in a public database using X as an identifier.  A rebuilder would
verify this claim by compiling the source, comparing the hashed output to the
claimed value.

## **System<sup>CHECKSUM-LOG</sup>**:
System<sup>CHECKSUM-LOG</sup> is about the claims made by a _log operator_.
It adds _discoverability_ into System<sup>CHECKSUM</sup>.  Discoverability means
that Verifier<sup>CHECKSUM</sup> can see all Statement<sup>CHECKSUM</sup> that
Believer<sup>CHECKSUM</sup> will accept.

* **Claim<sup>CHECKSUM-LOG</sup>**:
	_I, log operator, make available:_
	1. a globally consistent append-only log of Statement<sup>CHECKSUM</sup>
* **Statement<sup>CHECKSUM-LOG</sup>**: signed tree head
* **Claimant<sup>CHECKSUM-LOG</sup>**: log operator<br>
   Possible operators might be:
	* a small subset of data publishers
	* members of relevant consortia
* **Believer<sup>CHECKSUM-LOG</sup>**:
		Believer<sup>CHECKSUM</sup> and
		Verifier<sup>CHECKSUM</sup><br>
	Belief is based on two factors:
	1. seeing a valid Statement<sup>CHECKSUM-LOG</sup>
	2. seeing a number of valid Statement<sup>CHECKSUM-WITNESS</sup> from
	independent instances on System<sup>CHECKSUM-WITNESS</sup>.
* **Verifier<sup>CHECKSUM-LOG</sup>**: System<sup>CHECKSUM-WITNESS</sup><br>
	Witnesses verify the log's append-only property from their own local
	vantage point(s).
* **Arbiter<sup>CHECKSUM-LOG</sup>**:<br>
	There is no official body.  The ecosystem at large should stop using an
	instance of System<sup>CHECKSUM-LOG</sup> if cryptographic proofs of log
	misbehavior are preseneted by some Verifier<sup>CHECKSUM-LOG</sup>.

## **System<sup>CHECKSUM-WITNESS</sup>**:
System<sup>CHECKSUM-WITNESS</sup> is about making the claims of a log operator
_trustworthy_.
* **Claim<sup>CHECKSUM-WITNESS</sup>**:
	_I, witness, claim that_:
	1. System<sup>CHECKSUM-LOG</sup> provides a locally consistent append-only
	log
* **Statement<sup>CHECKSUM-WITNESS</sup>**: signed tree head
* **Claimant<sup>CHECKSUM-WITNESS</sup>**: third party<br>
	Examples of parties that may take on this role include:
	* members of relevant consortia
	* non-profits and other reputable organizations
	* security enthusiasts and researchers
	* log operators (cross-ecosystem)
	* monitors (cross-ecosystem)
	* a small subset of data publishers (cross-ecosystem)
* **Believer<sup>CHECKSUM-WITNESS</sup>**:
		Believer<sup>CHECKSUM</sup> and
		Verifier<sup>CHECKSUM</sup><br>
	Belief is based on seeing a valid Statement<sup>CHECKSUM-WITNESS</sup>.
* **Verifier<sup>CHECKSUM-WITNESS</sup>**: n/a <br>
	Witnesses are trusted parties.  Security is based on _strength in numbers_.
* **Arbiter<sup>CHECKSUM-WITNESS</sup>**:<br>
	There is no official body.  Invalidated claims would affect reputation.
