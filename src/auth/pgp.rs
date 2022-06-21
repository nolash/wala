use crate::auth::{
    AuthSpec,
    AuthError,
    AuthResult,
};
use pgp::packet::{
    PublicKey,
};
use pgp::types::{
    Version,
    KeyTrait,
};
use base64;

fn check_key_single(data: Vec<u8>) -> Option<PublicKey> {
    match PublicKey::from_slice(Version::Old, &data) {
        Ok(v) => {
            return Some(v);
        },
        Err(e) => {
        },
    };
    None
}

pub fn auth_check(auth: &AuthSpec) -> Result<AuthResult, AuthError> {
    if auth.method != "pgp" {
        return Err(AuthError{});
    }
    let key_data = match base64::decode(&auth.key) {
        Ok(v) => {
            v
        },
        Err(e) => {
            return Err(AuthError{});
        }
    };
    
    let key = match check_key_single(key_data) {
        Some(v) => {
            v
        },
        None => {
            return Err(AuthError{});
        },
    };

    println!("key {:?}", key);

    let res = AuthResult {
        identity: key.fingerprint(),
    };
    Ok(res)
}

#[cfg(test)]
mod tests { 

    use super::auth_check;
    use super::AuthSpec;
    use std::str::FromStr;

    #[test]
    fn test_single() {
        let key_single_hex = "0462a9f5a916092b06010401da470f0101074061f06baae76d5115553019e50353890e498652fac873d78003e9e192dd9f3e13";
        let sig_foo_single_hex = "0401160a0006050262a9f5a9002109108b21a9d88b4a0c7f1621044ab95b491980f89789ae8fde8b21a9d88b4a0c7f2aba0100b7b06c424cdb67bba97463d2eb3035ead329f62c92fb6100b629df003748131200fd17e8b6dc866aa1662b93a17ff599334002de273b800fc7160634516187b41407";

        let key_single = hex::decode(&key_single_hex).unwrap();
        let key_single_base64 = base64::encode(&key_single);

        let sig_foo_single = hex::decode(&sig_foo_single_hex).unwrap();
        let sig_foo_single_base64 = base64::encode(&sig_foo_single);

        let auth_spec_str = format!("pgp:{}:{}", key_single_base64, sig_foo_single_base64);
        let auth_spec = AuthSpec::from_str(&auth_spec_str).unwrap();

        match auth_check(&auth_spec) {
            Ok(v) => {
            },
            Err(e) => {
                panic!("{}", e);
            },
        }
    }
}
