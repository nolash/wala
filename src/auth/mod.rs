//! Using HTTP Authentication, a mutable reference can be generated to mutable content.
//!
//! The mutable reference is generated from the identity value of the authenticating client,
//! together with an identifier, which can be any arbitrary byte value.
//!
//! Mutable references are generated using [record::ResourceKey](record::ResourceKey) together with
//! the [auth::AuthResult](auth::AuthResult) struct.
//!
//! # How to authenticate
//!
//! Authentication in `wala` uses the `Authorization` HTTP header with the custom `PUBSIG` scheme
//! to determine the identity for which a client wishes to generate a mutable reference. The header
//! uses the following format:
//! 
//! ``` ignore,
//! Authorization: PUBSIG <scheme>:<identity>:<signature>
//! ```
//!
//! In the above, `scheme` specifies the authentication module to use (submodules of
//! [wala::auth](crate::auth). `identity` is the key against which the `signature` will be
//! validated.
//!
//! There is no access control for which key may store mutable references. All that is required is
//! a valid signature.
//!
//! # Mutable reference
//!
//! The generated mutable reference is a digest of the `identity` from the authentication, and the
//! local part of the `URL`.
//!
//! For example, given the request:
//!
//! ``` ignore, 
//! PUT /xyzzy HTTP/1.1
//! Authorization: PUBSIG foo:123:456
//! Content-Length: 3
//!
//! bar
//! ```
//! 
//! If we pretend that `456` is a valid signature for the `123` under the fictional `foo`
//! authentication scheme, then the mutable reference generated will be `SHA256(SHA256("xyzzy") | "123")`
//! which is `925b268b49dbd2455742082134c72291b5afb2b332c8dcb6d60f06eb8e26b350`
//!
//! The immutable reference (generated from the content body "bar") will simultaneously be stored,
//! under `SHA256("bar")`, which is `fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9`.
//!
//! Consequtively, for a `wala` server running on `localhost:8000`, the content can be retrieved using
//! both of the following `URLs`:
//!
//! ``` ignore,
//! http://localhost:8000/925b268b49dbd2455742082134c72291b5afb2b332c8dcb6d60f06eb8e26b350
//! http://localhost:8000/fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
//! ```
//! 
//! # Overwriting a reference
//!
//! If a subsequent mutable reference is generated for different content, then the existing mutable
//! reference will be overwritten. `wala` provides no feature to write-protect existing mutable
//! references.
//!
//! Of course, for immutable references, the reference for the same content will always be the
//! same.
//!
//! # Authentication schemes
//!
//! Every submodule of [wala::auth](crate::auth) defines individual authentication schemes.
//!
//! All schemes, even the [mock](crate::auth::mock) one, must be explicitly be included as a
//! feature during build.
//!
//! For any scheme included during build, a module function `auth_check` will be called to verify
//! the data. See [auth::mock::auth_check](crate::auth::mock::auth_check) for an example.
//!
//! Details on input formats for each scheme is documented within the modules themselves.
use std::str::FromStr;
use std::error::Error;
use std::fmt;

/// Holds the result of a client authentication request.
pub struct AuthResult {
    /// The resolved identity value. An unsuccessful authentication will result in an empty vector.
    pub identity: Vec<u8>,
    /// If true, authentication verification has been attempted and failed.
    pub error: bool,
}

/// Encapsulates the input provided by the client for authentication.
pub struct AuthSpec {
    /// Authentication method. This determines which authentication submodule will be used.
    pub method: String,
    /// The key corrdsponding to the signature.
    pub key: String,
    /// Signature over the content of the request. The signature must match against the given key.
    pub signature: String,
}

impl AuthSpec {
    /// Resturns true if the `signature` matches the `key` using the given `method` for the
    /// `auth::AuthSpec`.
    pub fn valid(&self) -> bool {
        self.key.len() > 0
    }
}

impl AuthResult {
    /// True if authentication has been successfully executed.
    pub fn active(&self) -> bool {
        self.identity.len() > 0
    }

    /// True if no error occurred during verification. Also returns true if no verification has been attmpted.
    pub fn valid(&self) -> bool {
        !self.error
    }
}

impl fmt::Debug for AuthResult {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(&hex::encode(&self.identity))
    }
}

#[derive(Debug)]
/// Indicates invalid authentication data from client.
pub struct AuthSpecError;

impl Error for AuthSpecError {
    fn description(&self) -> &str{
        "auth string malformed"
    }
}

impl fmt::Display for AuthSpecError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.description())
    }
}


impl FromStr for AuthSpec {
    type Err = AuthSpecError;

    fn from_str(s: &str) -> Result<AuthSpec, AuthSpecError> {
        let mut auth_kv = s.split(" ");
        match auth_kv.next() {
            Some(v) => {
                if v != "PUBSIG" {
                    return Err(AuthSpecError{});
                }
            },
            _ => {},
        };

        let ss = match auth_kv.next() {
            Some(v) => {
                v
            },
            _ => {
                return Err(AuthSpecError{});
            },
        };

        let mut auth_fields = ss.split(":");
        if auth_fields.clone().count() != 3 {
            return Err(AuthSpecError{})
        }
        let auth_type: String = auth_fields.next().unwrap().to_string();
        let auth_key: String = auth_fields.next().unwrap().to_string();
        let auth_signature: String = auth_fields.next().unwrap().to_string();

        let r = AuthSpec{
            method: auth_type,
            key: auth_key,
            signature: auth_signature,
        };
        Ok(r)
    }
}

impl fmt::Debug for AuthSpec {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(
            format!(
                "{} key {:?}",
                self.method,
                self.key,
                ).as_str()
            )
    }
}

#[derive(Debug)]
/// Error type indicating that an error has occurred during authentication.
pub struct AuthError;

impl fmt::Display for AuthError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl Error for AuthError {
    fn description(&self) -> &str{
        "auth key signature mismatch"
    }
}


#[cfg(feature = "dev")]
pub mod mock;

#[cfg(feature = "pgpauth")]
pub mod pgp;
