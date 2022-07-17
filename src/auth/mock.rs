//! The `mock` auth module is provided to facilitate testing.
//!
//! If active, it will be executed for the `mock` authentication scheme.
//!
//! Under the `mock` scheme, a valid signature is simply the same value as the identity key.
use std::io::{
    Read,
};
use crate::auth::{
    AuthSpec,
    AuthError,
    AuthResult,
};


/// Verifies the given [auth::AuthSpec](crate::auth::AuthSpec) structure against the `mock` scheme.
///
/// # Arguments
///
/// * `auth` - Authentication data submitted by client.
/// * `data` - Content body submitted by client, to match signature against.
/// * `data_length` - Length of content body
pub fn auth_check(auth: &AuthSpec, data: impl Read, data_length: usize) -> Result<AuthResult, AuthError> {
    if auth.method != "mock" {
        return Err(AuthError{});
    }
    if auth.key != auth.signature {
        return Err(AuthError{});
    }
    let res = AuthResult{
        identity: auth.key.as_bytes().to_vec(),
        error: false,
    };
    Ok(res)
}


#[cfg(test)]
mod tests {
    use super::auth_check;
    use super::{AuthSpec, AuthResult};
    use std::str::FromStr;
    use std::io::empty;

    #[test]
    fn test_mock_auth_check() {
        let mut auth_spec = AuthSpec::from_str("PUBSIG foo:bar:baz").unwrap();
        match auth_check(&auth_spec, empty(), 0) {
            Ok(v) => {
                panic!("expected invalid auth");
            },
            Err(e) => {
            },
        }

        auth_spec = AuthSpec::from_str("PUBSIG mock:bar:baz").unwrap();
        match auth_check(&auth_spec, empty(), 0) {
            Ok(v) => {
                panic!("expected invalid auth");
            },
            Err(e) => {
            },
        }

        auth_spec = AuthSpec::from_str("PUBSIG mock:bar:bar").unwrap();
        match auth_check(&auth_spec, empty(), 0) {
            Ok(v) => {
            },
            Err(e) => {
                panic!("{}", e);
            },
        }
    }
}
