use std::str::FromStr;

use log::{debug};

use tiny_http::{
    StatusCode,
    Request,
    Response,
    Header,
    HeaderField,
};
use ascii::AsciiString;

use mime::Mime;
use mime::TEXT;

use crate::record::{
    RequestResult,
    RequestResultType,
};


pub fn origin_headers() -> Vec<Header> {
    let mut headers: Vec<Header> = vec!();
    headers.push(Header{
        field: HeaderField::from_str("Access-Control-Allow-Origin").unwrap(),
        value: AsciiString::from_ascii("*").unwrap(),
    });
    headers.push(Header{
        field: HeaderField::from_str("Access-Control-Allow-Methods").unwrap(),
        value: AsciiString::from_ascii("OPTIONS, PUT, GET").unwrap(),
    });
    headers.push(Header{
        field: HeaderField::from_str("Access-Control-Allow-Headers").unwrap(),
        value: AsciiString::from_ascii("Content-Type,Authorization,X-Filename,X-Wala-Trace").unwrap(),
    });

    let server_header_v = format!("wala/{}, tiny_http (Rust)", env!("CARGO_PKG_VERSION"));
    headers.push(Header{
            field: HeaderField::from_str("Server").unwrap(),
            value: AsciiString::from_ascii(server_header_v).unwrap(),
        });

    let mut cap_headers: Vec<String> = vec!();
    #[cfg(feature="pgpauth")]
    {
        let h = String::from("auth_pgp");
        cap_headers.push(h);
    };

    #[cfg(feature="magic")]
    {
        let h = String::from("magic");
        cap_headers.push(h);
    };

    #[cfg(feature="meta")]
    {
        let h = String::from("meta");
        cap_headers.push(h);
    };

    if cap_headers.len() > 0 {
        let v = cap_headers.join(",");
        headers.push(Header{
            field: HeaderField::from_str("X-Wala-Cap").unwrap(),
            value: AsciiString::from_ascii(v).unwrap(),
        });
    }
    headers
}

pub fn preflight_response(req: Request) {
    let auth_origin_headers = origin_headers();
    let res_status = StatusCode(200);
    let mut res = Response::empty(res_status);
    for v in auth_origin_headers.iter() {
        res.add_header(v.clone());
    }
    req.respond(res);
    debug!("served options request");
    return;
}

pub fn exec_response(req: Request, r: RequestResult) {
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

    let auth_origin_headers = origin_headers();

    match r.v {
        Some(v) => {
            let mut res = Response::from_string(v);
            res = res.with_status_code(res_status);
            for v in auth_origin_headers.iter() {
                res.add_header(v.clone());
            }
            req.respond(res);
            return;
        },
        None => {
            match r.f {
                Some(v) => {
                    let mut content_type = String::new();
                    let mut res = Response::from_file(v);
                    match r.m {
                        Some(v) => {
                            content_type.push_str(v.as_ref());
                            let h = Header{
                                field: HeaderField::from_str("Content-Type").unwrap(),
                                value: AsciiString::from_ascii(content_type.clone()).unwrap(),
                            };
                            res.add_header(h);
                        }, 
                        _ => {
                            content_type.push_str("application/octet-stream");
                        },
                    };
                    match r.n {
                        Some(v) => {
                            let s = format!("attachment; filename=\"{}\"", &v);
                            let h = Header{
                                field: HeaderField::from_str("Content-Disposition").unwrap(),
                                value: AsciiString::from_ascii(s.as_str()).unwrap(),
                            };
                            res.add_header(h);
                        }, 
                        _ => {
                            let m = mime::Mime::from_str(&content_type).unwrap();
                            let s = match m.type_() {
                                mime::TEXT => {
                                    String::from("inline")
                                },
                                mime::IMAGE => {
                                    String::from("inline")
                                },
                                _ => {
                                    String::from("attachment")
                                },
                            };
                            let h = Header{
                                field: HeaderField::from_str("Content-Disposition").unwrap(),
                                value: AsciiString::from_ascii(s.as_str()).unwrap(),
                            };
                            res.add_header(h);
                        },
                    };

                    res = res.with_status_code(res_status);
                    for v in auth_origin_headers.iter() {
                        res.add_header(v.clone());
                    }
                    req.respond(res);
                    return;
                },
                None => {
                    let mut res = Response::empty(res_status);
                    for v in auth_origin_headers.iter() {
                        res.add_header(v.clone());
                    }
                    req.respond(res);
                    return;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tiny_http::Request;
    use crate::record::RequestResult;
    use super::exec_response;

    #[test]
    fn test_response_get_filename() {
//       let r = Request{}
    }
}
