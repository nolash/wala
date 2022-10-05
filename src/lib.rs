#![crate_name = "wala"]

//! wala is a content-adressed HTTP file server.
//! When content is uploaded, the URL to the content is automatcally generated from the contents of the request body. The URL will always be the same for the same content.
//! These will be referred to as _immutable references_.
//! 
//! The content of the URL is the SHA256 hash of the content, in hex, lowercase, without a 0x
//! prefix.
//!
//! ## Content metadata
//!
//! If built with the `meta` feature, the content type specified in the `PUT` will be stored and used
//! when the file is retrieved. `wala` will _not_ double-check the content type against the actual
//! content.
//!
//! ## Mutable references
//!
//! wala also provides a way to generate URL aliases to content based on cryptographic identities.
//! These will be referred to as _mutable references_.
//! See the [wala::auth](crate::auth) module for more details. 
//! 
//! ## Running the daemon
//!
//! The wala daemon will listen to all ip addresses on port 8000 by default, aswell as store and
//! serve uploaded files from the current directory. This behavior can be modified by the argument
//! options. See `cargo run -- --help` for details.
//!
//! ## Uploading content
//!
//! Content is stored by making `PUT` requests to the server. With a server running on
//! `localhost:8000` a `PUT` with the content body `foo` can in turn be retrieved at:
//!
//! ``` ignore,
//! http://localhost:8000/2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae 
//! ```
//!
//! A helper tool [wala_send](../wala_send/index.html) is provided to make mutable reference uploads more
//! convenient.

/// Handle the custom PUBSIG HTTP authentication scheme to generate mutable references.
pub mod auth;

/// Encapsulates an incoming remote request.
pub mod request;

/// Encapsulates an outgoing response to remote.
pub mod response;

/// Interfaces a single content record lookup.
pub mod record;

#[cfg(feature = "meta")]
/// Store and serve MIME metadata for content.
pub mod meta;

#[cfg(feature = "trace")]
/// Log all successful requests to spool directory
pub mod trace;
