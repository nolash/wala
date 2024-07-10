Make sure you use the following toolchain (rustup):

nightly-2022-11-14-x86_64-unknown-linux-gnu

Build the binaries:

$ cargo build --all-features --release

Build the Docker image:

$ docker build -t wala:latest . 

or

$ docker buildx build -t wala:latest . 

Running the server

$ ./target/release/wala -d <storage_directory>

Logging output detail can be adjusted by setting environment variable RUST_LOG to debug, info, warn or error.


Upload the string "foo" using the send tool

$ ./target/release/wala_send -u http://localhost:8000 foo


Upload the string "xyzzy" under a mutable reference with keyword "foo" using the send tool:

$ ./target/release/wala_send -u http://localhost:8000 -k <pgp key fingerprint> -i bar xyzzy


Note!

Wala is not intended to be used by itself in a production environment. Please consider setting a reverse proxy in front of it.
