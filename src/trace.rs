use std::path::Path;
use std::fs::{
    File,
    OpenOptions,
};
use std::io::Write;
    
use hex;

use log::{debug};

use crate::record::{
    RequestResult,
    RequestResultType,
};


pub fn trace_request(p: &Path, res: &RequestResult, store_identity: bool) {
    if res.typ != RequestResultType::Changed {
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
    //let mut content = String::new();
    let mut content: Vec<u8> = vec!();
    let mut identity = String::new();
    match &res.a {
        Some(auth) => {
            if auth.active() && store_identity {
                content = auth.identity.clone();
                identity = hex::encode(&content);
            }
        },
        None => {
        },
    }
    let fp = p.join(&rf);
    let mut f = File::create(fp).unwrap();
    f.write(content.as_ref());

    // useless update because we can always resolve mutable to immutable from data dir
//    if content.len() != 0 {
//        let rf_content_hex = res.s.as_ref().unwrap();
//        let rf_content = hex::decode(rf_content_hex).unwrap();
//        //let rf_content = s.clone();
//        let fp = p.join(&identity);
//    
//        let mut f = OpenOptions::new()
//            .write(true)
//            .append(true)
//            .create(true)
//            .open(fp)
//            .unwrap();
//
//        let rf_bin = hex::decode(rf).unwrap();
//        f.write(rf_bin.as_ref());
//        f.write(rf_content.as_ref());
//    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::fs::File;

    use tempfile::tempdir;

    use log::{debug};

    use crate::record::{
        RequestResult,
        RequestResultType,
    };
    use crate::auth::{
        AuthResult,
    };

    use super::trace_request;

    #[test]
    fn test_trace_immutable() {
        let d = tempdir().unwrap();
        let p = d.path();
        let url = String::from("deadbeef");
        let mut r = RequestResult::new(RequestResultType::Changed);
        r = r.with_content(url);
        trace_request(&p, &r);
        let fp = p.join(&r.v.unwrap());
        let f = File::open(fp).unwrap();
        let meta = f.metadata().unwrap();
        assert_eq!(meta.len(), 0);
    }

    #[test]
    fn test_trace_typchk() {
        let d = tempdir().unwrap();
        let p = d.path();
        let url = String::from("deadbeef");
        let mut r = RequestResult::new(RequestResultType::Found);
        r = r.with_content(url);
        trace_request(&p, &r);
        let fp = p.join(&r.v.unwrap());
        let f = File::open(fp);
        match f {
            Ok(v) => {
                panic!("should not have file {:?}", v);
            },
            Err(e) => {
            },
        }
    }

    #[test]
    fn test_trace_auth_inactive() {
        let d = tempdir().unwrap();
        let p = d.path();
        let url = String::from("deadbeef");
        let a = AuthResult{
            identity: vec!(),
            error: false,
        };
        let mut r = RequestResult::new(RequestResultType::Changed);
        r = r.with_content(url);
        r = r.with_auth(a);
        trace_request(&p, &r);
        let fp = p.join(&r.v.unwrap());
        let f = File::open(fp);
        match f {
            Ok(v) => {
                panic!("should not have file {:?}", v);
            },
            Err(e) => {
            },
        }
    }

    #[test]
    fn test_trace_mutable() {
        let d = tempdir().unwrap();
        let p = d.path();
        let url = String::from("deadbeef");
        let id_b = b"moradi";
        let a = AuthResult{
            identity: id_b.to_vec(),
            error: false,
        };
        let mut r = RequestResult::new(RequestResultType::Changed);
        r = r.with_content(url);
        r = r.with_auth(a);
        trace_request(&p, &r);
        let fp = p.join(r.v.unwrap());
        let f = File::open(fp).unwrap();
        let meta = f.metadata().unwrap();
        //let id_l = (id_b.len() * 2) as u64;
        let id_l = id_b.len() as u64;
        let r_l = meta.len();
        assert_eq!(r_l, id_l);
    }
}
