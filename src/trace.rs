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
    let mut content = String::new();
    match &res.a {
        Some(auth) => {
            if auth.active() {
                let identity = hex::encode(&auth.identity);
                content.push_str(&identity);
                //content.push('\t');
                //content.push_str("foo");
            } else {
                rf = String::new();
            }
        },
        None => {
        },
    }
    if rf.len() == 0 {
        return;
    }
    let fp = p.join(rf);
    let mut f = File::create(fp).unwrap();
    f.write(content.as_ref());
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
        let r = RequestResult{
            typ: RequestResultType::Changed,
            v: Some(url),
            f: None,
            m: None,
            n: None,
            a: None,
        };
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
        let r = RequestResult{
            typ: RequestResultType::Found,
            v: Some(url),
            f: None,
            m: None,
            n: None,
            a: None,
        };
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
        let r = RequestResult{
            typ: RequestResultType::Changed,
            v: Some(url),
            f: None,
            m: None,
            n: None,
            a: Some(a),
        };
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
        let r = RequestResult{
            typ: RequestResultType::Changed,
            v: Some(url),
            f: None,
            m: None,
            n: None,
            a: Some(a),
        };
        trace_request(&p, &r);
        let fp = p.join(&r.v.unwrap());
        let f = File::open(fp).unwrap();
        let meta = f.metadata().unwrap();
        let id_l = (id_b.len() * 2) as u64;
        let r_l = meta.len();
        assert_eq!(r_l, id_l);
    }
}
