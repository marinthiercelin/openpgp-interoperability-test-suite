# OpenPGP interoperability test suite

This is a test suite designed to chart and improve interoperability of
OpenPGP implementations.  It uses a simple black-box API implemented
by several backends, and maps test over all implementations.

# Configuration

The back ends are configured using a JSON file.  Copy
`config.json.dist` to `config.json`, and point the various backends to
the OpenPGP implementations that you want to test.  It is perfectly
fine to test different versions using the same backend.

# Adding a backend

There are two ways of writing backends for implementations.  The
preferred way is to implement it in Rust, which allows for
specialization and a more robust error handling and reporting.  The
alternative is to use the generic backend, and write some glue code.

## Rust

To add a new backend, copy an existing backend (say `src/sq.rs`) to a
new file, and adapt it.  Then, add a new variant to `enum
Implementation` in `src/main.rs`, and handle it in
`Config::implementations`.

Test drivers should "shell out" to the OpenPGP implementations being
tested, even if the implementation is written in Rust.  This way, we
can easily retarget the test suite to a different version, and test
different versions at the same time.

## Generic

To use the generic backend, you need to write some glue code that
implements the protocol described below.  The glue code will be called
with a series of arguments, and it is expected to signal success by
exiting with status zero, and failure using any non-zero status code
(see below).  Any artifact produced must be written to stdout, error
and diagnostic messages must be written to stderr, and input is fed to
stdin.

```
$GLUE STATE-DIRECTORY COMMAND
```

where `$GLUE` is your glue code, `STATE-DIRECTORY` is a temporary
directory that you may freely store any state in, and `COMMAND` is one
of:

### Commands

```
version
```

Identifies the name of the implementation, followed by a space,
followed by the version.  This command MUST be implemented.

```
encrypt CERT-FILE [CERT-FILE...]
```

Encrypts to the given recipients, reading cleartext on stdin and
producing the encrypted message on stdout.

```
decrypt KEY-FILE [KEY-FILE...]
```

Decrypts using the given key material, reading ciphertext on stdin,
producing cleartext on stdout.

```
generate [USERID...]
```

Generates a TSK with default options, and the given userids (if any),
writing the result to stdout.

### Exit status codes

- 0: Success
- 69: Command not implemented by the glue code

# Adding a test

Currently, only Producer-Consumer tests are supported.  To add a test,
add it to `src/tests.rs`.
