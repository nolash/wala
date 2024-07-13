Wala


HTTP service that makes uploaded content available at the path of its
digests(s)

Currently only SHA256 is supported.

Wala is not intended to be used by itself in a production environment.
Please consider setting a reverse proxy in front of it.

Build

Rustup example:

rustup run 1.67 cargo build -v --bin --all-features --release

Running

./target/release/wala -d <storage_directory>

Logging output detail can be adjusted by setting environment variable
RUST_LOG to debug, info, warn or error.

./target/release/wala --help for more options.

Example interaction

    curl -X PUT http://localhost:8000 --data "foo"
    2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    curl -X GET http://localhost:8000/2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    foo

Known issues

wala_send is broken :'(
