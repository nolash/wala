use tiny_http::{
    Server,
    ServerConfig,
    Request,
    Response,
    StatusCode,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::path::{PathBuf, Path};
use std::fs::File;
use std::error::Error;
use std::fmt;

use env_logger;

mod auth;
use auth::{
    AuthSpec,
    AuthResult,
};

mod record;
use record::{
    RequestResult,
    RequestResultType,
};

mod request;
use request::process_method;

use log::{debug, info, error};

use tempfile::NamedTempFile;


#[cfg(feature = "dev")]
use crate::auth::mock::auth_check as mock_auth_check;

#[cfg(feature = "pgpauth")]
use crate::auth::pgp::auth_check as pgp_auth_check;


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


fn exec_response(mut req: Request, r: RequestResult) {
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


fn exec_auth(auth_spec: AuthSpec) -> Option<AuthResult> {
    #[cfg(feature = "dev")]
    match mock_auth_check(&auth_spec) {
        Ok(v) => {
            return Some(v);
        },
        Err(e) => {
        },
    }

    #[cfg(feature = "pgpauth")]
    match pgp_auth_check(&auth_spec) {
        Ok(v) => {
            return Some(v);
        },
        Err(e) => {
        },
    }

    None
}


fn process_auth(auth_spec: AuthSpec) -> Option<AuthResult> {
    if !auth_spec.valid() {
        let r = AuthResult{
            identity: vec!(),
            error: true,
        };
        return Some(r);
    }
    exec_auth(auth_spec)
}


fn auth_from_headers(req: &Request) -> Option<AuthSpec> {
    for h in req.headers() {
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
                    let method = req.method();
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


fn process_request(mut req: &Request) -> AuthResult {
    let r: Option<AuthResult>;
    
    r = match auth_from_headers(req) {
        Some(v) => {
            process_auth(v)
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

fn main() {
    env_logger::init();

    let base_path = Path::new(".");

    let ip_addr = Ipv4Addr::from_str("0.0.0.0").unwrap();
    let tcp_port: u16 = 8001;
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

        let res  = process_request(&req);

        let mut path = base_path.clone();

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

        let mut result = process_method(&method, url, f, expected_size, &path, res);
        
        exec_response(req, result);
    }
}
