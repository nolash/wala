use std::str::FromStr;
use std::error::Error;
use std::fmt;

pub struct AuthSpec {
    pub method: String,
    key: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug)]
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
        let mut auth_fields = s.split(":");
        if auth_fields.clone().count() != 3 {
            return Err(AuthSpecError{})
        }
        let auth_type: String = auth_fields.next().unwrap().to_string();
        let r = AuthSpec{
            method: auth_type,
            key: vec!(),
            signature: vec!(),
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
