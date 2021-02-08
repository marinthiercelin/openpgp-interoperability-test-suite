# OpenPGP interoperability test suite

This is a test suite designed to chart and improve interoperability of
OpenPGP implementations.  It uses the [Stateless OpenPGP Command Line
Interface] that can be implemented by all OpenPGP implementations.

  [Stateless OpenPGP Command Line Interface]: https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-02">

# Configuration

The back ends are configured using a JSON file.  Copy
`config.json.dist` to `config.json`, and point the various backends to
the OpenPGP implementations that you want to test.  It is perfectly
fine to test different versions of an implementation.

# Adding a backend

To add an backend, your implementation must implement the [Stateless
OpenPGP Command Line Interface].  The glue code will be called with a
series of arguments, and it is expected to signal success by exiting
with status zero, and failure using any non-zero status code.  Any
artifact produced must be written to stdout, error and diagnostic
messages must be written to stderr, and input is fed to stdin.

# Adding a test

Currently, only Producer-Consumer tests are supported.  To add a test,
add it to `src/tests.rs`.
