#![crate_name = "wala"]


use tiny_http::{
    Server,
    ServerConfig,
    Request,
    Response,
    StatusCode,
    Header,
    HeaderField,
    Method,
};
use ascii::AsciiString;
use mime::Mime;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::path::{PathBuf, Path};
use std::fs::File;
use std::error::Error;
use std::fmt;
use std::io::{
    copy as io_copy,
    Read,
    Seek,
    empty,
};

use env_logger;

use wala::auth::{
    AuthSpec,
    AuthResult,
};

use wala::record::{
    RequestResult,
    RequestResultType,
};

use wala::request::process_method;

mod arg;
use arg::Settings;

use log::{info, error};

use tempfile::tempfile;

#[cfg(feature = "dev")]
use wala::auth::mock::auth_check as mock_auth_check;

#[cfg(feature = "pgpauth")]
use wala::auth::pgp::auth_check as pgp_auth_check;


#[derive(Debug)]
pub struct NoAuthError;

impl Error for NoAuthError {
    fn description(&self) -> &str{
        "no auth"
    }
}

impl fmt::Display for NoAuthError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.description())
    }
}


fn exec_response(req: Request, r: RequestResult) {
    let res_status: StatusCode;
    match r.typ {
        RequestResultType::Found => {
            res_status = StatusCode(200);
        },
        RequestResultType::Changed => {
            res_status = StatusCode(200);
        },
        RequestResultType::WriteError => {
            res_status = StatusCode(500);
        },
        RequestResultType::AuthError => {
            res_status = StatusCode(403);
        },
        RequestResultType::InputError => {
            res_status = StatusCode(400);
        },
        RequestResultType::RecordError => {
            res_status = StatusCode(404);
        },
        _ => {
            res_status = StatusCode(500);
        },
    }
    match r.v {
        Some(v) => {
            let mut res = Response::from_string(v);
            res = res.with_status_code(res_status);
            req.respond(res);
            return;
        },
        None => {
            match r.f {
                Some(v) => {
                    let mut res = Response::from_file(v);
                    match r.m {
                        Some(v) => {
                            let h = Header{
                                field: HeaderField::from_str("Content-Type").unwrap(),
                                value: AsciiString::from_ascii(v.as_ref()).unwrap(),
                            };
                            res.add_header(h);
                        }, 
                        _ => {},
                    }
                    res = res.with_status_code(res_status);
                    req.respond(res);
                    return;
                },
                None => {
                    let res = Response::empty(res_status);
                    req.respond(res);
                    return;
                },
            }
        }
    }
}


fn exec_auth(auth_spec: AuthSpec, data: &File, data_length: usize) -> Option<AuthResult> {
    #[cfg(feature = "dev")]
    match mock_auth_check(&auth_spec, data, data_length) {
        Ok(v) => {
            return Some(v);
        },
        Err(e) => {
        },
    }

    #[cfg(feature = "pgpauth")]
    match pgp_auth_check(&auth_spec, data, data_length) {
        Ok(v) => {
            return Some(v);
        },
        Err(e) => {
        },
    }

    None
}


fn process_auth(auth_spec: AuthSpec, data: &File, data_length: usize) -> Option<AuthResult> {
    if !auth_spec.valid() {
        let r = AuthResult{
            identity: vec!(),
            error: true,
        };
        return Some(r);
    }
    exec_auth(auth_spec, data, data_length)
}


fn auth_from_headers(headers: &[Header], method: &Method) -> Option<AuthSpec> {
    for h in headers {
        let k = &h.field;
        if k.equiv("Authorization") {
            let v = &h.value;
            let r = AuthSpec::from_str(v.as_str());
            match r {
                Ok(v) => {
                    return Some(v);
                },
                Err(e) => {
                    error!("malformed auth string: {}", &h.value);
                    let r = AuthSpec{
                        method: String::from(method.as_str()),
                        key: String::new(),
                        signature: String::new(),
                    };
                    return Some(r);
                }
            }
        }
    }
    None
}


fn process_request(req: &mut Request, f: &File) -> AuthResult {
    let headers = req.headers();
    let method = req.method();

    let r: Option<AuthResult>;
    
    r = match auth_from_headers(headers, method) {
        Some(v) => {
            process_auth(v, f, 0)
        },
        _ => {
            None
        },
    };

    match r {
        Some(v) => {
            return v;
        },
        _ => {},
    };
    
    // is not auth
    AuthResult{
         identity: vec!(),
         error: false,
    }
}

fn process_meta(req: &Request, path: &Path, digest: Vec<u8>) -> Option<Mime> {
    let headers = req.headers();
    let mut m: Option<mime::Mime> = None;
   
    for h in headers {
        let k = &h.field;
        if k.equiv("Content-Type") {
            let v = &h.value;
            m = match Mime::from_str(v.as_str()) {
                Err(e) => {
                    error!("invalid mime type");
                    return None;
                },
                Ok(v) => {
                    Some(v)
                },
            };
        }
    }

    #[cfg(feature = "meta")]
    match m {
        Some(v) => {
            match wala::meta::register_type(path, digest, v) {
                Err(e) => {
                    error!("could not register content type: {}", &e);
                },
                _ => {},
            };
        },
        _ => {},
    };

    None
}


fn main() {
    env_logger::init();

    let settings = Settings::from_args();
    let base_path = settings.dir.as_path();
    info!("Using data dir: {:?}", &base_path);

    let ip_addr = Ipv4Addr::from_str(&settings.host).unwrap();
    let tcp_port: u16 = settings.port;
    let sock_addr = SocketAddrV4::new(ip_addr, tcp_port);
    let srv_cfg = ServerConfig{
        addr: sock_addr,
        ssl: None,
    };
    let srv = Server::new(srv_cfg).unwrap();

    loop {
        let b = srv.recv();
        let mut req: Request;
        match b {
            Ok(v) => req = v,
            Err(e) => {
                error!("{}", e);
                break;
            }
        };


        let url = String::from(&req.url()[1..]);
        let method = req.method().clone();
        let expected_size = match req.body_length() {
                Some(v) => {
                    v 
                },
                None => {
                    0
                },
            };
        let f = req.as_reader();
        let mut path = base_path.clone();
        let mut res: AuthResult = AuthResult{
            identity: vec!(), 
            error: false,
        };
        let rw: Option<File> = match tempfile() {
            Ok(mut v) => {
                io_copy(f, &mut v);
                v.rewind();
                res = process_request(&mut req, &mut v);
                v.rewind();
                Some(v)
            },
            Err(e) => {
                None
            },
        };

        let mut result: RequestResult;
        match rw {
            Some(v) => {
                result = process_method(&method, url, v, expected_size, &path, res);
            },
            None => {
                let v = empty();
                result = process_method(&method, url, v, expected_size, &path, res);
            },
        };

        match &result.typ {
            RequestResultType::Changed => {
                let digest_hex = result.v.clone().unwrap();
                let digest = hex::decode(&digest_hex).unwrap();
                process_meta(&req, &path, digest);
            },
            RequestResultType::Found => {

            },
            _ => {},
        }

        exec_response(req, result);
    }
}
