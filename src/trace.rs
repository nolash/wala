use std::path::Path;
use std::fs::File;
use std::io::Write;
    
use hex;

use log::{debug};

use crate::record::{
    RequestResult,
    RequestResultType,
};


pub fn trace_request(p: &Path, res: &RequestResult) {
    if (res.typ != RequestResultType::Changed) {
        return;
    }
    let mut rf = String::new();
    match &res.v {
        Some(v) => {
            rf.push_str(v);
        },
        None => {
        },
    };
    if rf.len() == 0 {
        return;
    }
    let mut content = String::new();
    match &res.a {
        Some(auth) => {
            if auth.active() {
                let identity = hex::encode(&auth.identity);
                content.push_str(&identity);
                //content.push('\t');
                //content.push_str("foo");
            }
        },
        None => {},
    }
    let fp = p.join(rf);
    let mut f = File::create(fp).unwrap();
    f.write(content.as_ref());
}
