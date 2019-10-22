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

To add a new backend, copy an existing backend (say `src/sq.rs`) to a
new file, and adapt it.  Then, add a new variant to `enum
Implementation` in `src/main.rs`, and handle it in
`Config::implementations`.

Test drivers should "shell out" to the OpenPGP implementations being
tested, even if the implementation is written in Rust.  This way, we
can easily retarget the test suite to a different version, and test
different versions at the same time.

# Adding a test

Currently, only Producer-Consumer tests are supported.  To add a test,
add it to `src/tests.rs`.
