use std::fmt;
use std::error::Error;

use crate::auth::AuthSpec;

#[derive(Debug)]
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

pub fn auth_check(auth: AuthSpec) -> bool {
    if auth.method != "mock" {
        return false;
    }
    if auth.key != auth.signature {
        return false;
    }
    true
}


#[test]
fn test_mock_auth_check() {
    use super::mock::auth_check;
    use super::AuthSpec;
    use std::str::FromStr;

    let mut auth_spec = AuthSpec::from_str("foo:bar:baz").unwrap();
    assert!(!auth_check(auth_spec));

    auth_spec = AuthSpec::from_str("mock:bar:baz").unwrap();
    assert!(!auth_check(auth_spec));

    auth_spec = AuthSpec::from_str("mock:bar:bar").unwrap();
    assert!(auth_check(auth_spec));
}
