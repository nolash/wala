use std::str::FromStr;
use std::convert::Infallible;

use sha2::{Sha256, Digest};

use crate::auth::AuthResult;

pub struct ResourceKey { 
    v: Vec<u8>,
}

impl FromStr for ResourceKey {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<ResourceKey, Infallible> {
            let mut h = Sha256::new();
            h.update(&s[..]);
            let k = ResourceKey{
                v: h.finalize().to_vec(),
            };
            Ok(k)
    }
}

impl ResourceKey {
    pub fn pointer_for(&self, subject: &AuthResult) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(&self.v);
        h.update(&subject.identity);
        h.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceKey;
    use super::AuthResult;
    use hex;

    #[test]
    fn test_pointer() {
        let resource = ResourceKey{
            v: vec!(0x66, 0x6f, 0x6f),
        };
        let subject = AuthResult{
            identity: vec!(0x62, 0x61, 0x72),
        };
        let r = resource.pointer_for(&subject);

        let foobar_digest = hex::decode("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2").unwrap();
        assert_eq!(r, foobar_digest);
    }
}
