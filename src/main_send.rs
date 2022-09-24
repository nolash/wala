use std::env::home_dir;
use std::io::stdout;
use std::io::copy;
use std::io::Write;

use log::{info, debug};
use ureq::{Agent, AgentBuilder};
use env_logger;
use clap::{
    App, 
    Arg,
};
use url::Url;

use sequoia_openpgp::packet::prelude::*;
//use sequoia_openpgp::key::prelude::*;
use sequoia_openpgp::cert::prelude::CertParser;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::PacketParser;
use sequoia_openpgp::policy::StandardPolicy;
//use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::SecretParts;
use sequoia_openpgp::packet::key::UnspecifiedRole;
use sequoia_openpgp::packet::key::PrimaryRole;
use sequoia_openpgp::serialize::stream::Message;
use sequoia_openpgp::serialize::stream::Signer;
use sequoia_openpgp::serialize::stream::LiteralWriter;

use wala::record::{ResourceKey};
use wala::auth::{AuthResult};


//fn clean_hex(s: &[u8]) -> &[u8] {

//}

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
            debug!("have key {:?}", v);
            if v.len() > 1 {
                if &v[..2] == "0x" {
                    v = &v[2..];
                }
            }
            if v.len() % 2 > 0 {
                nv.push_str(v);
                v = nv.as_ref();
            }
            debug!("hex key input {:?}", &v);
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
                            debug!("check key {} {}", k.fingerprint(), hex::encode(&auth_data.identity));
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

    let mut sig_sink = vec!();
    let mut pubkey_sink = vec!();

    match sk {
        Some(mut k) => {
            debug!("have key {:?}", &k);
            //let sig = data.as_bytes();
            let mut pwd = String::new();
            if k.secret().is_encrypted() {
                pwd = rpassword::prompt_password("Key passphrase: ").unwrap();
                let algo = k.pk_algo();
                k.secret_mut()
                    .decrypt_in_place(algo, &pwd.into());

            }

            let mut sig_msg = Message::new(&mut sig_sink);

            let kp =  k.clone().into_keypair().unwrap();
            let mut signer = Signer::new(sig_msg, kp)
                .detached()
                .build()
                .unwrap();
            signer.write_all(&data.as_bytes());
            signer.finalize();

            Packet::from(k.clone()).serialize(&mut pubkey_sink);
            debug!("sig data {:?}", &sig_sink);
            debug!("pubkey data {:?}", &pubkey_sink);
        }, 
        None => {},
    };

    let ua = AgentBuilder::new().build();
    let r = ua.put(url.as_str())
        .send_bytes(&data.as_bytes());

    debug!("r {:?}", r.unwrap().into_string());
}
