use tiny_http::{
    Server,
    ServerConfig,
    Request,
    Response,
    StatusCode,
    Method,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::path::{PathBuf, Path};
use std::fs::copy as fs_copy;
use std::fs::File;
use std::io::Write;
use sha2::{Sha256, Digest};

use env_logger;

mod auth;

use auth::AuthSpec;

use log::{debug, info, error};

use tempfile::NamedTempFile;


#[cfg(feature = "dev")]
use crate::auth::mock::auth_check as mock_auth_check;

fn exec_auth(auth_spec: AuthSpec) -> bool {
    #[cfg(feature = "dev")]
    if mock_auth_check(auth_spec) {
        return true;
    }

    false
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
        let r = srv.recv();
        let mut req: Request;
        match r {
            Ok(v) => req = v,
            Err(e) => {
                error!("{}", e);
                break;
            }
        };

        let mut res_status: StatusCode;

        let mut auth_spec: Option<AuthSpec> = None;
        let mut is_auth = false;
        let mut is_signed = false;
        let mut is_mut = false;

        for h in req.headers() {
            let k = &h.field;
            if k.equiv("Authorization") {
                is_auth = true;
                let v = &h.value;
                let r = AuthSpec::from_str(v.as_str());
                match r {
                    Ok(v) => {
                        auth_spec = Some(v);
                    },
                    Err(e) => {
                        error!("malformed auth string: {}", &h.value);
                    }
                }
            }
        }
     

        if is_auth {
            match auth_spec {
                Some(v) => {
                    debug!("have auth {:?}", v);
                    is_signed = exec_auth(v);
                },
                None => {
                    debug!("invalid auth");
                    res_status = StatusCode(401);
                    let mut res = Response::empty(res_status);
                    req.respond(res);
                    continue;
                }
            };
        }

        let url = &req.url()[1..];
        let path_base = base_path.clone().join(url);
        let mut path = PathBuf::new();

        match req.method() {
            Method::Put => {
                is_mut = true;
                if !is_signed {
                    res_status = StatusCode(403);
                    let mut res = Response::empty(res_status);
                    req.respond(res);
                    continue;
                }
            },
            Method::Get => {
                match path_base.canonicalize() {
                    Ok(v) => {
                        //path = v;
                        match File::open(v) {
                            Ok(f) => {
                                res_status = StatusCode(200);
                                let mut res = Response::from_file(f);
                                //res = res.with_status(res_status);
                                req.respond(res);
                                continue;
                            },
                            Err(e) => {
                                res_status = StatusCode(404);
                                let mut res = Response::empty(res_status);
                                req.respond(res);
                                continue;
                            },
                        }
                    },
                    Err(e) => {
                        if !is_mut {
                            res_status = StatusCode(404);
                            let mut res = Response::empty(res_status);
                            req.respond(res);
                            continue;
                        }
                    },
                }
            },
            _ => {
                    res_status = StatusCode(400);
                    let mut res = Response::empty(res_status);
                    req.respond(res);
                    continue;
            },
        }

        info!("processing request {} for {} -> {}", req.method(), url, path.to_str().unwrap());

        if is_mut {
            let hash: String;
            let mut total_size: usize = 0;
            let expected_size = match req.body_length() {
                Some(v) => {
                    v 
                },
                None => {
                   res_status = StatusCode(400);
                   let mut res = Response::empty(res_status);
                   req.respond(res);
                   continue;
                },
            };

            let tempfile = match NamedTempFile::new() {
                Ok(of) => {
                    debug!("writing to tempfile {:?} expected size {}", of.path(), expected_size);

                    let f = req.as_reader();
                    let mut buf: [u8; 65535] = [0; 65535];
                    let mut h = Sha256::new();
                    loop {
                        match f.read(&mut buf[..]) {
                            Ok(v) => {
                                if v == 0 {
                                    break;
                                }
                                total_size += v;
                                let data = &buf[..v];
                                h.update(data);
                                of.as_file().write(data);
                            },
                            Err(e) => {
                                error!("cannot read from request body: {}", e);
                                break;
                            },
                        }
                    }

                    if expected_size != total_size {
                        res_status = StatusCode(400);
                        let mut res = Response::empty(res_status);
                        req.respond(res);
                        continue;
                    }
                    let z = h.finalize();
                    hash = hex::encode(z);
                    info!("have hash {} for content", hash);
                    of
                },
                Err(e) => {
                    res_status = StatusCode(500);
                    let mut res = Response::empty(res_status);
                    req.respond(res);
                    continue;
                }
            };


            path = path.join(hash);
            fs_copy(tempfile.path(), path);
        }

        res_status = StatusCode(200);
        let mut res = Response::from_string("foo");
        res = res.with_status_code(res_status);
        req.respond(res);
    }
}
