use std::env::home_dir;

use log::{info, debug};
use ureq::{Agent, AgentBuilder};
use env_logger;
use clap::{
    App, 
    Arg,
};
use url::Url;

use sequoia_openpgp::cert::prelude::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::PacketParser;
use sequoia_openpgp::policy::StandardPolicy;

use wala::record::{ResourceKey};
use wala::auth::{AuthResult};


//fn clean_hex(s: &[u8]) -> &[u8] {

//}

fn main() {
    env_logger::init();

    let mut o = App::new("wala_send");
    o = o.version("0.1.0");
    o = o.author("Louis Holbrook <dev@holbrook.no>");

    o = o.arg(clap::Arg::with_name("id")
              .short("i")
              .long("id")
              .takes_value(true)
              .multiple(true)
              );

    o = o.arg(clap::Arg::with_name("key")
              .short("k")
              .long("key")
              .takes_value(true)
              );

    o = o.arg(clap::Arg::with_name("URL")
              .required(true)
              .index(1)
              );

    let args = o.get_matches();

    let mut d: Vec<u8> = vec!();
    let mut nv = String::from("0");
    for mut v in args.values_of("id").unwrap() {
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
    
    let mut auth: Option<AuthResult> = None;

    let url_src = args.value_of("URL").unwrap();
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

    let mut match_fp: Vec<u8> = Vec::new();
    if rk.v.len() > 0 {
        let p = StandardPolicy::new();
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
                                match_fp = auth_data.identity.clone();
                            }
                        }
                   
                },
                Err(e) => {
                    panic!("keyparse fail: {:?}", e);
                }
            };
        }
    }

    info!("signing with {}", hex::encode(&match_fp));

    let ua = AgentBuilder::new().build();
    let r = ua.put(url.as_str())
        .send_bytes(&d);

    debug!("r {:?}", r.unwrap().into_string());
}
