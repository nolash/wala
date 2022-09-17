use std::str::FromStr;

use tiny_http::{
    StatusCode,
    Request,
    Response,
    Header,
    HeaderField,
};
use ascii::AsciiString;

use crate::record::{
    RequestResult,
    RequestResultType,
};


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
                    match r.n {
                        Some(v) => {
                            let s = format!("attachment; filename=\"{}\"", &v);
                            let h = Header{
                                field: HeaderField::from_str("Content-Disposition").unwrap(),
                                value: AsciiString::from_ascii(s.as_str()).unwrap(),
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
