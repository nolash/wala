use crate::auth::{
    AuthSpec,
    AuthError,
    AuthResult,
};


pub fn auth_check(auth: &AuthSpec) -> Result<AuthResult, AuthError> {
    if auth.method != "mock" {
        return Err(AuthError{});
    }
    if auth.key != auth.signature {
        return Err(AuthError{});
    }
    let res = AuthResult{
        identity: auth.key.as_bytes().to_vec(),
    };
    Ok(res)
}


#[cfg(test)]
mod tests {
    use super::auth_check;
    use super::{AuthSpec, AuthResult};
    use std::str::FromStr;

    #[test]
    fn test_mock_auth_check() {
        let mut auth_spec = AuthSpec::from_str("foo:bar:baz").unwrap();
        match auth_check(&auth_spec) {
            Ok(v) => {
                panic!("expected invalid auth");
            },
            Err(e) => {
            },
        }

        auth_spec = AuthSpec::from_str("mock:bar:baz").unwrap();
        match auth_check(&auth_spec) {
            Ok(v) => {
                panic!("expected invalid auth");
            },
            Err(e) => {
            },
        }

        auth_spec = AuthSpec::from_str("mock:bar:bar").unwrap();
        match auth_check(&auth_spec) {
            Ok(v) => {
            },
            Err(e) => {
                panic!("{}", e);
            },
        }
    }
}
