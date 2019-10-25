---
title: Stateless OpenPGP CLI (sop)
author: Daniel Kahn Gillmor
date: 2019-10-25
colorlinks: true
---

This document defines a generic stateless command-line interface for
dealing with OpenPGP messages, known as `sop`.  It aims for a minimal,
well-structured API.

"Stateless" in "Stateless OpenPGP" means that the user is responsible
for managing all OpenPGP certificates and secret keys themselves, and
passing them to `sop` as needed.  The `sop` command should leave no
trace on the system, and its behavior should not be affected by
anything other than command-line arguments and input.

Obviously, the user will need to manage their secret keys (and their
peers' certificates) somehow, but the goal of this interface is to
separate out that task from the task of interacting with OpenPGP
messages.

While this document identifies a command-line interface, the rough
outlines of this interface should also be amenable to relatively
straightforward library implementations in different languages.

Examples
========

These examples show no error checking, but give a flavor of how `sop`
might be used in practice from a shell.

```
sop generate "Alice Lovelace <alice@openpgp.example>" > alice.sec
sop convert < alice.sec > alice.pgp

sop sign --as=text alice.sec < announcement.txt > announcement.txt.asc
sop verify announcement.txt.asc alice.pgp < announcement.txt

sop encrypt --sign-with=alice.sec --as=mime bob.pgp < msg.eml > encrypted.asc
sop decrypt alice.sec < ciphertext.asc > cleartext.out
```

Subcommands
===========

If the user supplies a subcommand that `sop` does not implement, it
fails with a return code of 69.  If a `sop` implementation does not
handle a supplied option for a given subcommand, it fails with a
return code of 37.

For all commands that have an `--armor|--no-armor` option, it defaults
to `--armor`, meaning that any output OpenPGP material should be
[ASCII-armored](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-6)
by default.

Version Information
-------------------

    sop version

 - Standard Input: ignored
 - Standard Output: version string

The version string emitted should contain the name of the `sop`
implementation, followed by a single space, followed by the version
number.


Generate a Secret Key
---------------------

    sop generate [--armor|--no-armor] [--] [USERID…]

 - Standard Input: ignored
 - Standard Output: `KEY`

Generate a single default OpenPGP certificate with zero or more User
IDs.

Convert a Secret Key to a Certificate
-------------------------------------

    sop convert [--armor|--no-armor]

 - Standard Input: `KEY`
 - Standard Output: `CERT`


Create a Detached Signature
---------------------------

    sop sign [--armor|--no-armor]
         [--as={binary|text}] [--] KEY [KEY...]

 - Standard Input: `DATA`
 - Standard Output: `SIGNATURE`

`--as` defaults to `binary`.  If `--as=text` and the input `DATA` is
not valid `UTF-8`, `sop sign` fails with a return code of 53.

Verify a Detached Signature
---------------------------

    sop verify [--not-before=DATE] [--not-after=DATE]
        [--] SIGNATURE CERT [CERT...]

 - Standard Input: `DATA`
 - Standard Output: `VERIFICATIONS`

`--not-before` and `--not-after` indicate that only signatures with
dates in a certain range should be considered as possibly valid.

`--not-before` defaults to the beginning of time.

`--not-after` defaults to "now".

`sop verify` only returns 0 if at least one of the supplied `CERT`s
made a valid signature in the range over the `DATA` supplied.

For details about the valid signatures, the user MUST inspect the
`VERIFICATIONS` output.

If no `CERT` is supplied, `sop verify` fails with a return code of 19.

If at least one `CERT` is supplied, but no valid signatures are found,
`sop verify` fails with a return code of 3.

Crypto nerd alert: a signature should be considered valid only if all
of these conditions are met (other conditions may also apply):

 * The signatures must be made by a signing-capable public key that is present in one of the supplied `CERT`s
 * The `CERT` and signing subkey must have been created before or at the signature time
 * The `CERT` and signing subkey must not have been expired at the signature time
 * The `CERT` and signing subkey must not be revoked with a "hard" revocation
 * If the `CERT` or signing subkey is revoked with a "soft" revocation, then the signature time must predate the revocation
 * The signing subkey must be properly bound to the primary key, and cross-signed
 * The signature (and any dependent signature, such as the cross-sig or subkey binding signatures) must be made with strong cryptographic algorithms (e.g., not `MD5` or a 1024-bit `RSA` key)

Signature validity is a complex topic, and this documentation cannot
list all possible details.

Encrypt a Message
-----------------

    sop encrypt [--as={binary|text|mime}]
        [--armor|--no-armor]
        [--mode={any|communications|storage}]
        [--with-password=PASSWORD...]
        [--session-key=SESSIONKEY]
        [--sign-with=KEY...]
        [--] [CERT...]

 - Standard Input: `DATA`
 - Standard Output: `ENCRYPTED-DATA`

`--as` defaults to `binary`.

`--mode` defaults to `any`, meaning any encryption-capable subkey may be used.

`--with-password` enables symmetric encryption (and can be used
multiple times if multiple passwords are desired).  If `sop encrypt`
encounters a `PASSWORD` which is not a valid `UTF-8` string, it fails
with a return code of 31.  If `sop encrypt` sees trailing whitespace
at the end of a `PASSWORD`, it will trim the trailing whitespace
before using the password.

`--session-key` permits the encryptor to select the symmetric
encryption algorithm and specific session key.

`--sign-with` enables signing by a secret key (and can be used
multiple times if multiple signatures are desired).

If `--as` is set to either `--text` or `--mime`, then `--sign-with`
will sign as a canonical text document.  In this case, if the input
`DATA` is not valid `UTF-8`, `sop encrypt` fails with a return code of
53.

The resulting `ENCRYPTED-DATA` should be decryptable by the secret
keys corresponding to each identified `CERT`.

If no `CERT` or `--with-password` options are present, `sop encrypt`
fails with a return code of 19.

Decrypt a Message
-----------------

    sop decrypt [--session-key-out=SESSIONKEY]
        [--with-password=PASSWORD...]
        [--verify-out=VERIFICATIONS
         [--verify-with=CERT...]
         [--verify-not-before=DATE]
         [--verify-not-after=DATE] ]
        [--] [KEY...]

 - Standard Input: `ENCRYPTED-DATA`
 - Standard Output: `DATA`

`--session-key-out` can be used to learn the session key on
successful decryption.

If `sop decrypt` fails for any reason and the identified `SESSIONKEY`
file already exists in the filesystem, the file will be unlinked.

`--with-password` enables symmetric decryption (and can be used
multiple times if the user wants to try more password are tried).

If `sop decrypt` tries and fails to use a supplied `PASSWORD`, and it
observes that there is trailing `UTF-8` whitespace at the end of the
`PASSWORD`, it will retry with the trailing whitespace stripped.

`--verify-out` produces signature verification status to the
designated file.

`sop decrypt` does not fail (that is, the return code is not modified)
based on the results of signature verification.  The caller MUST check
the returned `VERIFICATIONS` to confirm signature status.  An empty
`VERIFICATIONS` output indicates that no valid signatures were found.
If `sop decrypt` itself fails for any reason, and the identified
`VERIFICATIONS` file already exists in the filesystem, the file will
be unlinked.

`--verify-with` identifies a certificate whose signatures would be
acceptable for signatures over this message.

If the caller is interested in signature verification, both
`--verify-out` and at least one `--verify-with` must be supplied.  If
only one of these arguments is supplied, `sop decrypt` fails with a
return code of 19.

`--verify-not-before` and `--verify-not-after` provide a date range
for acceptable signatures, by analogy with the options for `sop
verify`.  They should only be supplied when doing signature
verification.

If no `KEY` or `--with-password` options are present, `sop decrypt`
fails with a return code of 23.

If unable to decrypt, `sop decrypt` fails with a return code of 29.

`sop decrypt` only returns cleartext to Standard Output that was
successfully decrypted.

Input String Types
==================

Some material is passed to `sop` directly as a string on the command line.

DATE
----

This is an ISO-8601 compliant date format in UTC, like
`2019-10-25T00:18:10Z`.  A flexible implementation of `sop` MAY accept
date inputs in other unambigious forms.

USERID
------

This is an arbitrary `UTF-8` string.  By convention, most User IDs are
of the form `Display Name <email.address@example.com>`, but they do
not need to be.

Input/Output Indirect Types
===========================

Some material is passed to `sop` indirectly, typically by referring to
a filename containing the data in question.  This type of data may
also be passed to `sop` on Standard Input, or delivered by `sop` to
Standard Output.

If the filename for any indirect material used as input has the
special form `@ENV:xxx`, then contents of environment variable `$xxx`
is used instead of looking in the filesystem.

If the filename for any indirect material used as either input or
output has the special form `@FD:nnn` where `nnn` is a decimal
integer, then the associated data is read from file descriptor `nnn`.

If any input data does not meet the requirements described below,
`sop` will fail with a return code of 17.

CERT
----

One [OpenPGP
certificate](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-11.1),
aka "Transferable Public Key".  May be armored.

KEY
---

One [OpenPGP Transferable Secret
Key](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-11.2).
May be armored.

Secret key material should be in cleartext (that is, it should not be
locked with a password).  If the secret key maerial is locked with a
password, `sop` may fail to use the key.

ENCRYPTED-DATA
--------------

`sop` accepts only a restricted subset of the arbitrarily-nested
grammar allowed by the [OpenPGP Messages
definition](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-11.3).

In particular, it accepts and generates only:

An OpenPGP message, consisting of a sequence of
[PKESK](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-5.1)s
and
[SKESK](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-5.3)s,
followed by one
[SEIPD](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-5.14).

The SEIPD can decrypt into one of two things:

  - "Maybe Signed Data" (see below), or

  - Compressed data packet that contains "Maybe Signed Data"

"Maybe Signed Data" is a sequence of:

  - N (zero or more) one-pass signature packets, followed by
  - zero or more signature packets, followed by
  - one Literal data packet, followed by
  - N signature packets (corresponding to the outer one-pass signatures packets)

FIXME: does any tool do compression inside signing?  Do we need to
handle that?

May be armored.

SIGNATURE
---------
One or more OpenPGP Signature packets.  May be armored.

SESSIONKEY
----------

This documentation uses the GnuPG defacto `ASCII` representation:

`ALGONUM:HEXKEY`

where `ALGONUM` is the decimal value associated with the [OpenPGP
Symmetric Key
Algorithms](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-9.3).

As input, `ALGONUM:` alone (with an empty `HEXKEY`) means "user
specifies the algorithm, but the implementation chooses an arbitrary
key for the cipher."

Example AES256 session key:

    9:FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD

PASSWORD
--------

This is expected to be a `UTF-8` string, but for `sop decrypt`, any
bytestring that the user supplies will be accepted.  Note the details
in `sop encrypt` and `sop decrypt` about trailing whitespace!

VERIFICATIONS
-------------

One line per successful signature validation.  Each line has two
structured fields delimited by a single space, followed by arbitary
text to the end of the line.

 - ISO-8601 UTC datestamp
 - Fingerprint of primary key of signing certificate
 - arbitrary text

Example:

    2019-10-24T23:48:29Z C4BC2DDB38CCE96485EBE9C2F20691179038E5C6 signed by dkg!

DATA
----

Cleartext, arbitrary data.  This is either a bytestream or `UTF-8`
text.

It MUST only be `UTF-8` text in the case of input supplied to `sop
sign --as=text` or `encrypt --as={mime|text}`


Failure modes
=============

When `sop` succeeds, it will return 0 and emit nothing to Standard
Error.  When `sop` fails, it fails with a non-zero return code, and
emits one or more warning messages on Standard Error.


Future Work
===========

 * `dearmor` subcommand (remove ASCII armor)
 * `armor {sig|key|cert|message}` subcommand (add ASCII armor)
 * `split` subcommand (split a clearsigned message into a message and a detached signature)
 * certificate transformation into popular publication forms:
   - WKD
   - DANE OPENPGPKEY
   - Autocrypt
 * `sop encrypt` -- specify compression?
 * `sop encrypt` -- specify padding policy/mechanism?
 * `sop decrypt` -- how can it more safely handle zip bombs?
 * `sop decrypt` -- what should it do when encountering weakly-encrypted (or unencrypted) input?

Acknowledgements
================

This work was inspired by Justus Winter's [OpenPGP Interoperability
Test Suite](https://tests.sequoia-pgp.org/), and discussions with
Justus.  Problems with this spec are not his fault.
