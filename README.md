# OpenPGP interoperability test suite

This is a test suite designed to chart and improve interoperability of
OpenPGP implementations.  It uses the [Stateless OpenPGP Command Line
Interface] (*SOP* for short) that can be implemented by all OpenPGP
implementations.

  [Stateless OpenPGP Command Line Interface]: https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-02">

The result of running the test suite can be seen here:
https://tests.sequoia-pgp.org/

# How to run the test suite

To run the test suite, you first need to install some build
dependencies.  On Debian-derived systems, this can be done using:

    $ sudo apt install git rustc cargo clang llvm pkg-config nettle-dev

Next, you need some implementations to test.  For starters, you can
install Sequoia's SOP frontend:

    $ sudo apt install sqop

Finally, you can clone the repository, copy the stock configuration
file (which points to `/usr/bin/sop` as the sole implementation), and
run the test suite:

    $ git clone https://gitlab.com/sequoia-pgp/openpgp-interoperability-test-suite
    $ cd openpgp-interoperability-test-suite
    $ cp config.json.dist config.json
    $ cargo run -- --html-out results.html

# Configuration

The backends are configured using a JSON file.  It contains a list of
drivers.  Every driver needs a `path` that points to the SOP
executable, and may have an `env` map to set environment variables.
Additionally, you can configure process limits (see `man 2
setrlimit`).  You should at least limit the size of the processes'
data segments to avoid trashing when runaway allocations occur in an
implementation.

This is an example configuration that showcases all the fields:

```json
{
  "drivers": [
    {
      "path": "/usr/bin/sqop"
    },
    {
      "path": "glue/sopgpy"
      "env": { "PYTHONPATH": "..." }
    }
  ],
  "rlimits": {
    "DATA": 2147483648
  }
}
```

# Adding a backend

To add an backend, your implementation must implement the [Stateless
OpenPGP Command Line Interface].  The glue code will be called with a
series of arguments, and it is expected to signal success by exiting
with status zero, and failure using any non-zero status code.  Any
artifact produced must be written to stdout, error and diagnostic
messages must be written to stderr, and input is fed to stdin.

If you have written a SOP frontend for your implementation and would
like to include it in https://tests.sequoia-pgp.org/, please [open an
issue].

[open an issue]: https://gitlab.com/sequoia-pgp/openpgp-interoperability-test-suite/-/issues

# Adding a test

If you have an idea for a test, please [open an issue].  You can also
take a stab at implementing a test, of course.  The tests are in the
`src/tests` directory.
