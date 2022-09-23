use log::{debug};
use ureq::{Agent, AgentBuilder};
use env_logger;
use clap::{
    App, 
    Arg,
};
use url::Url;

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
            let auth_data = AuthResult {
                identity: v.as_bytes().to_vec(),
                error: false,
            };

            let rk = ResourceKey {
                v: d.clone(),
            };
            let url_postfix = rk.pointer_for(&auth_data);
            //let url_postfix_str = String::from_utf8(url_postfix).unwrap();
            let url_postfix_hex = hex::encode(url_postfix);
            url = url.join(&url_postfix_hex).unwrap();
        },
        None => {},
    }



    let ua = AgentBuilder::new().build();
    let r = ua.put(url.as_str())
        .send_bytes(&d);

    debug!("r {:?}", r.unwrap().into_string());
}
