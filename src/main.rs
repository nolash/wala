use tiny_http::{
    Server,
    ServerConfig,
    Request,
    Response,
    StatusCode,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use env_logger;

mod auth;

use auth::AuthSpec;

use log::{debug, info, error};

fn main() {
    env_logger::init();

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
        let req: Request;
        match r {
            Ok(v) => req = v,
            Err(e) => {
                error!("{}", e);
                break;
            }
        };

        let mut res_status: StatusCode;
        let mut m: bool = false;

        let mut auth_spec: Option<AuthSpec> = None;

        for h in req.headers() {
            let k = &h.field;
            if k.equiv("Authorization") {
                let v = &h.value;
                let r = AuthSpec::from_str(v.as_str());
                match r {
                    Ok(v) => {
                        m = true;
                        auth_spec = Some(v);
                    },
                    Err(e) => {
                        error!("malformed auth string: {}", &h.value);
                    }
                }
            }
        }
       
        match auth_spec {
            Some(v) => {
                debug!("have auth {:?}", v);
            },
            None => {
                debug!("no auth");
            }
        };

        if m {
            res_status = StatusCode(200);
            let mut res = Response::from_string("foo");
            res = res.with_status_code(res_status);
            req.respond(res);
            continue;
        }

        res_status = StatusCode(404);
        let res = Response::empty(res_status);
        req.respond(res);
    }
}
