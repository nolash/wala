use std::str::FromStr;
use std::error::Error;
use std::fmt;

pub struct AuthSpec {
    pub method: String,
    pub key: String,
    pub signature: String,
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

#[cfg(feature = "dev")]
pub mod mock;
