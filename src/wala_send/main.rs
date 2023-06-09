#![crate_name = "wala_send"]

//! This is a convenience tool to upload content to wala under mutable references.
//!
//! It is still in a very unsophisticated state, and has two notable limitations:
//!
//! - Content to upload must be provided as a literal argument
//! - It only uses gnupg private keys stored in the keyring in `~/.gnupg/`.
//!
//! ## Examples
//!
//! Assuming that `wala` is running on default host and port - localhost:8000.
//!
//! ### Upload content to a content address
//!
//! ``` ignore,
//! wala_send -u http://localhost:8000 foo
//! ```
//!
//! ### Upload content to a mutable reference 
//!
//! ``` ignore,
//! wala_send -u http://localhost:8000 -k <pgp_fingerprint> -i <keyword> foo
//! ```
//!
//! For more details on what funcionality [wala](wala) provides, please consult the
//! [library crate documentation](wala).

use std::env::home_dir;
use std::io::stdout;
use std::io::copy;
use std::io::Write;

use env_logger;

use url::Url;

use log::{info, debug};

use ureq::{Agent, AgentBuilder};

use clap::{
    App, 
    Arg,
};

use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::cert::prelude::CertParser;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::PacketParser;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::SecretParts;
use sequoia_openpgp::packet::key::PublicParts;
use sequoia_openpgp::packet::key::UnspecifiedRole;
use sequoia_openpgp::packet::key::PrimaryRole;
use sequoia_openpgp::serialize::stream::Message;
use sequoia_openpgp::serialize::stream::Signer;
use sequoia_openpgp::serialize::stream::LiteralWriter;

use base64::encode;

use wala::record::{ResourceKey};
use wala::auth::{AuthResult};


#[doc(hidden)]
fn main() {
    env_logger::init();

    let mut o = App::new("wala_send");
    o = o.version("0.1.0");
    o = o.author("Louis Holbrook <dev@holbrook.no>");

    o = o.arg(Arg::with_name("DATA")
              .required(true)
              );

    o = o.arg(Arg::with_name("url")
              .short("u")
              .long("url")
              .takes_value(true)
              .required(true)
              );

    o = o.arg(Arg::with_name("ref_id")
              .short("i")
              .long("id")
              .takes_value(true)
              .multiple(true)
              .number_of_values(1)
              );

    o = o.arg(Arg::with_name("key")
              .short("k")
              .long("key")
              .takes_value(true)
              );


    let args = o.get_matches();

    let mut d: Vec<u8> = vec!();
    let mut nv = String::from("0");

    match args.values_of("ref_id") {
        Some(vs) => {
            for mut v in vs {
                if v.len() < 2 {
                    continue;
                }
                if &v[..2] == "0x" {
                    v = &v[2..];
                    if v.len() % 2 > 0 {
                        nv.push_str(v);
                        v = nv.as_ref();
                    }
                    debug!("hex input {:?}", &v);
                    let mut r = hex::decode(v).unwrap();
                    d.append(&mut r);
                } else {
                    d.append(&mut v.as_bytes().to_vec());
                }
            }
        },
        None => {},
    }
    
    let data = args.value_of("DATA").unwrap();
    
    let mut auth: Option<AuthResult> = None;

    let url_src = args.value_of("url").unwrap();
    let mut url = Url::parse(url_src).unwrap();

    let mut have_auth = false;
    let mut rk = ResourceKey {
        v: Vec::new(),
    };
    let mut auth_data = AuthResult {
        identity: Vec::new(),
        error: false,
    };

    match args.value_of("key") {
        Some(mut v) => {
            if v.len() > 1 {
                if &v[..2] == "0x" {
                    v = &v[2..];
                }
            }
            if v.len() % 2 > 0 {
                nv.push_str(v);
                v = nv.as_ref();
            }
            auth_data.identity = hex::decode(&v).unwrap();
            rk.v = d.clone();
            let url_postfix = rk.pointer_for(&auth_data);
            let url_postfix_hex = hex::encode(url_postfix);
            url = url.join(&url_postfix_hex).unwrap();
        },
        None => {},
    }

    let mut sk: Option<Key<SecretParts, PrimaryRole>> = None;
    let p = StandardPolicy::new();
    if rk.v.len() > 0 {
        let fp_stem = home_dir().unwrap();
        let fp = fp_stem.join(".gnupg/secring.gpg");
        let pp = PacketParser::from_file(fp).unwrap();

        // find a way to stop iter when key found
        for v in CertParser::from(pp) {
            match v {
                Ok(r) => {
                    for k in r.keys()
                        .with_policy(&p, None)
                        .alive()
                        .revoked(false)
                        .for_signing()
                        .secret()
                        .map(|kk| kk.key()) {
                            if k.fingerprint().as_bytes() == auth_data.identity {
                                sk = Some(k.clone().role_into_primary());
                            }
                        }
                   
                },
                Err(e) => {
                    panic!("keyparse fail: {:?}", e);
                }
            };
        }
    }

    let mut sig_bsf = String::new();
    let mut pubkey_bsf = String::new();

    match sk {
        Some(mut k) => {
            let mut sig_sink = vec!();
            let mut pubkey_sink = vec!();

            let mut pwd = String::new();
            if k.secret().is_encrypted() {
                pwd = rpassword::prompt_password("Key passphrase: ").unwrap();
                let algo = k.pk_algo();
                k.secret_mut()
                    .decrypt_in_place(algo, &pwd.into());

            }

            let mut sig_msg = Message::new(&mut sig_sink);

            let kp =  k.clone().into_keypair().unwrap();
            let pk: Key<PublicParts, PrimaryRole> = kp.public().clone().role_into_primary();
            let mut signer = Signer::new(sig_msg, kp)
                .detached()
                .build()
                .unwrap();
            signer.write_all(&data.as_bytes());
            signer.finalize();

            Packet::from(pk).serialize(&mut pubkey_sink);
           
            sig_bsf = base64::encode(sig_sink);
            pubkey_bsf = base64::encode(pubkey_sink);
        }, 
        None => {},
    };

    let ua = AgentBuilder::new().build();
    let mut rq = ua.put(url.as_str());

    if sig_bsf.len() > 0 {
        let hdr_val = format!("PUBSIG pgp:{}:{}", pubkey_bsf, sig_bsf);
        rq = rq.set("Authorization", hdr_val.as_str());
    }
    let rs = rq.send_bytes(&data.as_bytes());

    println!("{}", rs.unwrap().into_string().unwrap());
}
