//! This module provides authentication using PGP signatures.
//!
//! The public key and signature may be provided both as literal values from the individual PGP packets (i.e. raw public key and signature),
//! or as the conventional packet bundle.
//!
//! If using bundle, the encoded data must be from the binary content, e.g. the output value of:
//! 
//! ``` ignore,
//! gpg -b <file>
//! ```
//!
//! Does not work for ECC secp256k1 signature.
use std::io::Read;
use crate::auth::{
    AuthSpec,
    AuthError,
    AuthResult,
};
use pgp::packet::{
    PublicKey,
    PacketParser,
    Signature,
};
//use pgp::errors::Error;
use pgp::types::{
    Tag,
    Version,
    KeyTrait,
};
use pgp::composed::{
    SignedPublicKey,
    Deserializable,
    StandaloneSignature,
};
use pgp::ser::Serialize;
use pgp::de::Deserialize;
use base64;

use log::{debug, info, error};


fn check_key_single(data: &Vec<u8>) -> Option<PublicKey> {
    match PublicKey::from_slice(Version::Old, &data) {
        Ok(v) => {
            return Some(v);
        },
        Err(e) => {
        },
    };
    None
}

fn check_key_bundle(data: &Vec<u8>) -> Option<PublicKey> {
    match SignedPublicKey::from_bytes(&data[..]) {
        Ok(v) => {
            return Some(v.primary_key);
        },
        Err(e) => {},
    };
    None

//    let mut packets = PacketParser::new(&data[..]);
//    loop {
//        match packets.next() {
//            Some(packet) => {
//                let v = packet.unwrap();
//                if v.tag() == Tag::PublicKey {
//                //Some(v) => {
//                    let packet_bytes = v.to_bytes().unwrap();
//                    //let key_pub = PublicKey::from_slice(v.packet_version(), &packet_bytes[..]).unwrap();
//                    let key_pub_composed = SignedPublicKey::from_bytes(&packet_bytes[..]).unwrap();
//                    return Some(key_pub_composed.primary_key);
//                }
//            },
//            None => {
//                break;
//            },
//        //},
//        //_ => {},
//        };
//    };
//    None
}

fn check_sig_single(public_key: &PublicKey, signature_data: Vec<u8>, mut message: impl Read, message_length: usize) -> bool {
    match Signature::from_slice(Version::Old, &signature_data) {
        Ok(v) => {
            match v.verify(public_key, message) {
                Ok(v) => {
                    return true;
                },
                _ => {},
            };
        },
        _ => {},
    };
    false
}

fn check_sig_bundle(public_key: &PublicKey, signature_data: Vec<u8>, mut message: impl Read, message_length: usize) -> bool {
    match StandaloneSignature::from_bytes(&signature_data[..]) {
        Ok(v) => {
            let mut data: Vec<u8> = vec!();
            let r = message.read_to_end(&mut data);
            match v.verify(public_key, &data) {
                Ok(v) => {
                    return true;
                },
                _ => {},
            };
        },
        _ => {},
    };
    false
}

/// Verifies the given [auth::AuthSpec](crate::auth::AuthSpec) structure against the `pgp` scheme.
///
/// The `key` and `signature` fields of the [auth::AuthSpec](crate::auth::AuthSpec) **MUST** be
/// base64 encoded.
///
/// # Arguments
///
/// * `auth` - Authentication data submitted by client.
/// * `data` - Content body submitted by client, to match signature against.
/// * `data_length` - Length of content body.
pub fn auth_check(auth: &AuthSpec, data: impl Read, data_length: usize) -> Result<AuthResult, AuthError> {
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

    debug!("signature data {:?}", auth.signature);
    let sig_data = match base64::decode(&auth.signature) {
        Ok(v) => {
            v
        },
        Err(e) => {
            return Err(AuthError{});
        }
    };

    
    let key = match check_key_single(&key_data) {
        Some(v) => {
            debug!("using public key (raw) {:?}", v.key_id());
            if !check_sig_single(&v, sig_data, data, data_length) {
                error!("invalid raw signature for {:?}", hex::encode(&v.fingerprint()));
                return Err(AuthError{});
            }
            debug!("found valid raw key {:?}", hex::encode(&v.fingerprint()));
            v
        },
        None => {
            let key = match check_key_bundle(&key_data) {
                Some(v) => {
                    debug!("using public key (bundle) {:?}", v.key_id());
                    if !check_sig_bundle(&v, sig_data, data, data_length) {
                        error!("invalid bundle signature for {:?}", hex::encode(&v.fingerprint()));
                        return Err(AuthError{});
                    }
                    debug!("found valid key bundle {:?}", hex::encode(&v.fingerprint()));
                    v
                },
                None => {
                    return Err(AuthError{});
                },
            };
            key
        },
    };


    let res = AuthResult {
        identity: key.fingerprint(),
        error: false,
    };
    Ok(res)
}

#[cfg(test)]
mod tests { 

    use super::auth_check;
    use super::AuthSpec;
    use std::str::FromStr;
    use super::{
        check_key_bundle,
        check_key_single,
        check_sig_single,
        check_sig_bundle,
    };


    #[test]
    fn test_pgp_single() {
        let key_single_hex = "0462a9f5a916092b06010401da470f0101074061f06baae76d5115553019e50353890e498652fac873d78003e9e192dd9f3e13";
        let sig_foo_single_hex = "0401160a0006050262a9f5a9002109108b21a9d88b4a0c7f1621044ab95b491980f89789ae8fde8b21a9d88b4a0c7f2aba0100b7b06c424cdb67bba97463d2eb3035ead329f62c92fb6100b629df003748131200fd17e8b6dc866aa1662b93a17ff599334002de273b800fc7160634516187b41407";

        let key_single = hex::decode(&key_single_hex).unwrap();
        let key_single_base64 = base64::encode(&key_single);

        let sig_foo_single = hex::decode(&sig_foo_single_hex).unwrap();
        let sig_foo_single_base64 = base64::encode(&sig_foo_single);

        let auth_spec_str = format!("PUBSIG pgp:{}:{}", key_single_base64, sig_foo_single_base64);
        let auth_spec = AuthSpec::from_str(&auth_spec_str).unwrap();

        let data = b"foo";
        let r = match check_key_single(&key_single) {
            Some(v) => {
                if !check_sig_single(&v, sig_foo_single, &data[..], 0) {
                    panic!("invalid");
                }
            },
            None => {
                panic!("no public key");
            },
        };

    }

 
    #[test]
    fn test_pgp_bundle() {
        let key_bundle_hex = "99018d045fa148e8010c00a990f4048c00e39d0b63980b1d3d8a71e4df8e3090588f50c0a0862c0ed57abdb701250b7de0e9b7c65ed1061bfd9b6a0b8333ec891c230841515b2352bb4054a790858dc5df9b44b82b67a0c787ab1674e74920bd4bab6654dad53445ef49c13ab0a027989ec9357d44c49b848963db50345627586823df8047ef0438d78944ba3f8f4369f92e081439f43ecc5d4fe481d06634cf6704823be3a0faf8956f4801bf05b7d4c3629fa63b37a39f5160ec2b88ae5051480bfeb23edb550c35e5d8754a96f0b52e71c6e6c26bc1311062380725e6797751d0a649f8403992c3b4892b10ffa8a948e75283e8b49e2382945366d4ffce85b52c600c4251f897eb9e05327db3a315411232777bb974a47ee4b6875ac4472d3e87d02c103d2d20d421e8ea26c5349e9c3f0c70c3daebf11befc0ea5815f4bf044e5be0a7c47378e09fd9b1ee88a618cfceedc6f905c2c5e0535f936716e4fa6b4205b9e0b153cb35aad8fca1a45492feca1707443d0f978c1751de9ab90b98eaf43d02e2a2093d567b6b0011010001b41e4d6572204d616e203c6d65726d616e4067726579736b756c6c2e636f6d3e8901d404130108003e162104f3faf668e82ef5124d5187baef26f4682343f69205025fa148e8021b03050903c26700050b0908070206150a09080b020416020301021e01021780000a0910ef26f4682343f692f08b0c0084525b03250ad394c929f0f3f35ef9ecde3bd924ed07cb1faf46aec2646bf19b35bad1d154cd1bfe39234eea38b8936bed85552932a013bfab27ea70866df0953438e0b54b8c1c96022ffb35683713d6f67a59beaa47e09bf45f16ddef92e3b1192c99c8814587efedc2fea20013efafac3b319c2b15a4b450fde0d5519ae5316a83a28dc6877d1ff80f2f1bf8e65bad5dfdd5bc1653269af5a719fb68b1e51731322203596cffcdd50178e064ab37f9340df2fadf5b198dab945da6576e2e711ac28a098c09d60deae7cee98ba9937535779f484a815ba2a4ef211b2e7ef9878ebfe857b02c43c3267e4a1bfea9abddfd26a9c58802744b9ebb038d2057ec22c58277748272329789c4d310532ef27bc199fef1ba8da1bfabc43b1a228e55d5fb82e41abb24741f19320f0fcb0131e832e60e89209c08532eb4dcd5285b90eb50df23638f214aec10e9aa86ec25a97a77c4a96e171c5092dea5a4a6b24d02809b138e1025e84c17d046204e8de43f97d272aadb0fc57041a4fc09c138ac2578b9018d045fa148e8010c00c7b694d3d64e31fba14de4e794469280688b283c7821909da56fac969844826be0da47a19700a95b7742fd50c7172ea9da0a7e12a59bdb7fc84fe1f251816751979b9537fae6c956d92d456333c35c55d15122b4ec372bb898b066c9d737880ffdd2c09310e8fd7bb0d2bf12e698b163a70339c572ddeb3d25ebef46fb0a0d980457552dd5fd1af2167b72282dc04c2a95949a10046e394e3da0308ba7a5a7532575a6762a28a1e196dec2de52fe4c33df26481e128ca46526a18f363c7994ee8c9896d979767f2ff68ee84b175100f687cd96a61965e2ba466163e21d3098a99622a8d62be84df1529cdcbd6569dee09854958fe83b35d7ba7b068c8a573d34cb10bd95e745ddea6992d656a85568c02322850137ebbe8bdc30d366c9c97f5ffcc4a521e54d8c8f7941be396f08408a8b4d2aa3c6f59a7fce9254232794f85b34eb1fa5feff3a5ecfc6649ad70e6b21dd50a0ffeb8ae867d7576d71bf869e40f945a3f2849560a83640d03002767e6a2676295444fd8eb50c280583a09cc7f700110100018901bc041801080026162104f3faf668e82ef5124d5187baef26f4682343f69205025fa148e8021b0c050903c26700000a0910ef26f4682343f69220f70bff78ea2f60364a60beb3404ee2f30f11f0a96b6819fefa356b3ce3522799bb95a12316f98a4d15e93ef9116e45d0e7998fda97234ea05be20cf3e0ba226520691de5e3b52306204fabeb8a3bd42e4ff9ceb5b4acd9d5e84cd08b31037b325add5018b1fa59ea6591920e087a9ffb95c80630f12878737ff7b611d4891ef1cd5286c402834fc2e8563847b214f362e42af0caa57efc1523878448b6abc90f98fa3e7e54b0f348b80f0279c8a85fee8b62508de7c9c66fd52e860d68f00676aa33feefd1d139b3f786d951f2e3810683a14a67c58cb02b624695fde63d9dcf3568f1273b904c5e467b96f3fd3ca59d1608c814fb283ee868a1ceeb67e10db60f2787fde2264de01ea79d301e3f7e3314396451b5f8007b9d5d4edbbf14f939493dc7d736b63ef1c3140768486adbe26c616d04570dbb44b85bca69c17cb8d555492d345d27406bd4d93128730e29af66640c74244a795b35ae24ba394bed5cdba67120c8e9a2e5eafd19a22e5525400e8bc1bbea73fcebf5cbfde351ef2167f2a579";
        let sig_foo_bundle_hex = "8901b304000108001d162104f3faf668e82ef5124d5187baef26f4682343f692050262b426d7000a0910ef26f4682343f6922fc50bff526ff1fb6de59bd022f4f71389b7d429040fcf4f3c6889b015de95dd1562b9ff197c7cb24040370c7a68c08c0b2430e034456f71a0c3b1c8c4bfacf6dd37e3d3305563b59c157c015d33a360395daefd9f4cd9370fd3e75c201d491a2008bead964f31955cd9bd3b09ef3647d4b92188fedcabbbfdefdb70a5c345c4f94ad1cacfe10b12782731d49ef516d2223dc2e01c4dedaffa558794339ee866244f7bcf4e2daeffb1d2501dd969837163e8eebc9b58fa0d6e75e6e119753c9bd7b621ef4a73f1953bd2ab69e8241d17ae5dcb900cf6f9575d2038152769dece1baf446cd1adcfb6e742ed0980519de3ca4c7360ef70e4cf38cafb504d5b04144fae0786e8d8c65c5c1475ca723bbbb5fed2416f10f0fd82a4e2bd6c5590e8f018c85941f63dd4ca5f3784760facca9a5c68a01b5ddde25887a492475ae611bfbb359a281b0052c1674d1cf6646f84b75293f1820bb5cf5a2a029e02b7c54177fb92e1184b14b646a80d37da28c9715aad37f9609d7c866881a2efe51e931cccc38d438f";

        let key_bundle = hex::decode(&key_bundle_hex).unwrap();
        let key_bundle_base64 = base64::encode(&key_bundle);

        let sig_foo_bundle = hex::decode(&sig_foo_bundle_hex).unwrap();
        let sig_foo_bundle_base64 = base64::encode(&sig_foo_bundle);

        let data = b"foo";

        let r = match check_key_bundle(&key_bundle) {
            Some(v) => {
                if !check_sig_bundle(&v, sig_foo_bundle, &data[..], 0) {
                    panic!("invalid");
                }
            },
            None => {
                panic!("no public key");
            },
        };
    }


    #[test]
    fn test_pgp_auth_single() {
        let key_single_hex = "0462a9f5a916092b06010401da470f0101074061f06baae76d5115553019e50353890e498652fac873d78003e9e192dd9f3e13";
        let sig_foo_single_hex = "0401160a0006050262a9f5a9002109108b21a9d88b4a0c7f1621044ab95b491980f89789ae8fde8b21a9d88b4a0c7f2aba0100b7b06c424cdb67bba97463d2eb3035ead329f62c92fb6100b629df003748131200fd17e8b6dc866aa1662b93a17ff599334002de273b800fc7160634516187b41407";

        let key_single = hex::decode(&key_single_hex).unwrap();
        let key_single_base64 = base64::encode(&key_single);

        let sig_foo_single = hex::decode(&sig_foo_single_hex).unwrap();
        let sig_foo_single_base64 = base64::encode(&sig_foo_single);

        let auth_spec_str = format!("PUBSIG pgp:{}:{}", key_single_base64, sig_foo_single_base64);
        let auth_spec = AuthSpec::from_str(&auth_spec_str).unwrap();

        let data = b"foo";

        match auth_check(&auth_spec, &data[..], 0) {
            Ok(v) => {
            },
            Err(e) => {
                panic!("{}", e);
            },
        }
    }

    #[test]
    fn test_pgp_auth_bundle() {
        let key_bundle_hex = "99018d045fa148e8010c00a990f4048c00e39d0b63980b1d3d8a71e4df8e3090588f50c0a0862c0ed57abdb701250b7de0e9b7c65ed1061bfd9b6a0b8333ec891c230841515b2352bb4054a790858dc5df9b44b82b67a0c787ab1674e74920bd4bab6654dad53445ef49c13ab0a027989ec9357d44c49b848963db50345627586823df8047ef0438d78944ba3f8f4369f92e081439f43ecc5d4fe481d06634cf6704823be3a0faf8956f4801bf05b7d4c3629fa63b37a39f5160ec2b88ae5051480bfeb23edb550c35e5d8754a96f0b52e71c6e6c26bc1311062380725e6797751d0a649f8403992c3b4892b10ffa8a948e75283e8b49e2382945366d4ffce85b52c600c4251f897eb9e05327db3a315411232777bb974a47ee4b6875ac4472d3e87d02c103d2d20d421e8ea26c5349e9c3f0c70c3daebf11befc0ea5815f4bf044e5be0a7c47378e09fd9b1ee88a618cfceedc6f905c2c5e0535f936716e4fa6b4205b9e0b153cb35aad8fca1a45492feca1707443d0f978c1751de9ab90b98eaf43d02e2a2093d567b6b0011010001b41e4d6572204d616e203c6d65726d616e4067726579736b756c6c2e636f6d3e8901d404130108003e162104f3faf668e82ef5124d5187baef26f4682343f69205025fa148e8021b03050903c26700050b0908070206150a09080b020416020301021e01021780000a0910ef26f4682343f692f08b0c0084525b03250ad394c929f0f3f35ef9ecde3bd924ed07cb1faf46aec2646bf19b35bad1d154cd1bfe39234eea38b8936bed85552932a013bfab27ea70866df0953438e0b54b8c1c96022ffb35683713d6f67a59beaa47e09bf45f16ddef92e3b1192c99c8814587efedc2fea20013efafac3b319c2b15a4b450fde0d5519ae5316a83a28dc6877d1ff80f2f1bf8e65bad5dfdd5bc1653269af5a719fb68b1e51731322203596cffcdd50178e064ab37f9340df2fadf5b198dab945da6576e2e711ac28a098c09d60deae7cee98ba9937535779f484a815ba2a4ef211b2e7ef9878ebfe857b02c43c3267e4a1bfea9abddfd26a9c58802744b9ebb038d2057ec22c58277748272329789c4d310532ef27bc199fef1ba8da1bfabc43b1a228e55d5fb82e41abb24741f19320f0fcb0131e832e60e89209c08532eb4dcd5285b90eb50df23638f214aec10e9aa86ec25a97a77c4a96e171c5092dea5a4a6b24d02809b138e1025e84c17d046204e8de43f97d272aadb0fc57041a4fc09c138ac2578b9018d045fa148e8010c00c7b694d3d64e31fba14de4e794469280688b283c7821909da56fac969844826be0da47a19700a95b7742fd50c7172ea9da0a7e12a59bdb7fc84fe1f251816751979b9537fae6c956d92d456333c35c55d15122b4ec372bb898b066c9d737880ffdd2c09310e8fd7bb0d2bf12e698b163a70339c572ddeb3d25ebef46fb0a0d980457552dd5fd1af2167b72282dc04c2a95949a10046e394e3da0308ba7a5a7532575a6762a28a1e196dec2de52fe4c33df26481e128ca46526a18f363c7994ee8c9896d979767f2ff68ee84b175100f687cd96a61965e2ba466163e21d3098a99622a8d62be84df1529cdcbd6569dee09854958fe83b35d7ba7b068c8a573d34cb10bd95e745ddea6992d656a85568c02322850137ebbe8bdc30d366c9c97f5ffcc4a521e54d8c8f7941be396f08408a8b4d2aa3c6f59a7fce9254232794f85b34eb1fa5feff3a5ecfc6649ad70e6b21dd50a0ffeb8ae867d7576d71bf869e40f945a3f2849560a83640d03002767e6a2676295444fd8eb50c280583a09cc7f700110100018901bc041801080026162104f3faf668e82ef5124d5187baef26f4682343f69205025fa148e8021b0c050903c26700000a0910ef26f4682343f69220f70bff78ea2f60364a60beb3404ee2f30f11f0a96b6819fefa356b3ce3522799bb95a12316f98a4d15e93ef9116e45d0e7998fda97234ea05be20cf3e0ba226520691de5e3b52306204fabeb8a3bd42e4ff9ceb5b4acd9d5e84cd08b31037b325add5018b1fa59ea6591920e087a9ffb95c80630f12878737ff7b611d4891ef1cd5286c402834fc2e8563847b214f362e42af0caa57efc1523878448b6abc90f98fa3e7e54b0f348b80f0279c8a85fee8b62508de7c9c66fd52e860d68f00676aa33feefd1d139b3f786d951f2e3810683a14a67c58cb02b624695fde63d9dcf3568f1273b904c5e467b96f3fd3ca59d1608c814fb283ee868a1ceeb67e10db60f2787fde2264de01ea79d301e3f7e3314396451b5f8007b9d5d4edbbf14f939493dc7d736b63ef1c3140768486adbe26c616d04570dbb44b85bca69c17cb8d555492d345d27406bd4d93128730e29af66640c74244a795b35ae24ba394bed5cdba67120c8e9a2e5eafd19a22e5525400e8bc1bbea73fcebf5cbfde351ef2167f2a579";
        let sig_foo_bundle_hex = "8901b304000108001d162104f3faf668e82ef5124d5187baef26f4682343f692050262b426d7000a0910ef26f4682343f6922fc50bff526ff1fb6de59bd022f4f71389b7d429040fcf4f3c6889b015de95dd1562b9ff197c7cb24040370c7a68c08c0b2430e034456f71a0c3b1c8c4bfacf6dd37e3d3305563b59c157c015d33a360395daefd9f4cd9370fd3e75c201d491a2008bead964f31955cd9bd3b09ef3647d4b92188fedcabbbfdefdb70a5c345c4f94ad1cacfe10b12782731d49ef516d2223dc2e01c4dedaffa558794339ee866244f7bcf4e2daeffb1d2501dd969837163e8eebc9b58fa0d6e75e6e119753c9bd7b621ef4a73f1953bd2ab69e8241d17ae5dcb900cf6f9575d2038152769dece1baf446cd1adcfb6e742ed0980519de3ca4c7360ef70e4cf38cafb504d5b04144fae0786e8d8c65c5c1475ca723bbbb5fed2416f10f0fd82a4e2bd6c5590e8f018c85941f63dd4ca5f3784760facca9a5c68a01b5ddde25887a492475ae611bfbb359a281b0052c1674d1cf6646f84b75293f1820bb5cf5a2a029e02b7c54177fb92e1184b14b646a80d37da28c9715aad37f9609d7c866881a2efe51e931cccc38d438f";

        let key_bundle = hex::decode(&key_bundle_hex).unwrap();
        let key_bundle_base64 = base64::encode(&key_bundle);

        let sig_foo_bundle = hex::decode(&sig_foo_bundle_hex).unwrap();
        let sig_foo_bundle_base64 = base64::encode(&sig_foo_bundle);

        let auth_spec_str = format!("PUBSIG pgp:{}:{}", key_bundle_base64, sig_foo_bundle_base64);
        let auth_spec = AuthSpec::from_str(&auth_spec_str).unwrap();

        let data = b"foo";

        match auth_check(&auth_spec, &data[..], 0) {
            Ok(v) => {
            },
            Err(e) => {
                panic!("{}", e);
            },
        }
    }
}
