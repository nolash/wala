use std::str::FromStr;
use std::io;
use std::convert::Infallible;
use std::fs::File;
use std::io::{
    Write,
    Read,
};
use std::os::unix::fs::symlink;
use std::path::{
    PathBuf,
    Path,
};
use std::fs::copy as fs_copy;
use std::error::Error;
use sha2::{Sha256, Digest};
use std::fmt;

use crate::auth::AuthResult;
use tiny_http::Request;
use tempfile::NamedTempFile;

use log::{debug, info, error};

#[derive(Debug, PartialEq)]
pub enum RequestResultType {
    Found,
    Changed,
    ReadError,
    WriteError,
    AuthError,
    InputError,
    RecordError,
}

pub struct RequestResult {
    pub typ: RequestResultType,
    pub v: Option<String>,
    pub f: Option<File>,
}

impl fmt::Display for RequestResult {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl fmt::Debug for RequestResult {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        //fmt.write_str(format_args!("{:?}", RequestResultType));
        write!(fmt, "{:?}", self.typ)
    }
}

impl Error for RequestResult {
    fn description(&self) -> &str {
        match &self.v {
            Some(v) => {
                return v.as_str();
            },
            None => {
            },
        }
        ""
    }
}

pub struct Record {
    pub digest: Vec<u8>,
    pub path: PathBuf,
}

pub struct ResourceKey { 
    v: Vec<u8>,
}

impl FromStr for ResourceKey {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<ResourceKey, Infallible> {
            let mut h = Sha256::new();
            h.update(&s[..]);
            let k = ResourceKey{
                v: h.finalize().to_vec(),
            };
            Ok(k)
    }
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(&hex::encode(&self.v))
    }
}

impl ResourceKey {
    pub fn pointer_for(&self, subject: &AuthResult) -> Vec<u8> {
        let mut h = Sha256::new();
        debug!("update {:?} {:?}", hex::encode(&self.v), hex::encode(&subject.identity));
        h.update(&self.v);
        h.update(&subject.identity);
        h.finalize().to_vec()
    }
}


pub fn put_immutable(path: &Path, mut f: impl Read, expected_size: usize) -> Result<Record, RequestResult> {
    let z: Vec<u8>;
    let hash: String;
    let mut total_size: usize = 0;
    let tempfile = match NamedTempFile::new() {
        Ok(of) => {
            debug!("writing to tempfile {:?} expected size {}", of.path(), expected_size);
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
                        let err = RequestResult{
                            typ: RequestResultType::ReadError,
                            v: None,
                            f: None,
                        };
                        return Err(err);
                    },
                }
            }
    
            if expected_size > 0 {
                if expected_size != total_size {
                    let err = RequestResult{
                        typ: RequestResultType::ReadError,
                        v: None,
                        f: None,
                    };
                    return Err(err);
                }
            }

            z = h.finalize().to_vec();
            hash = hex::encode(&z);
            info!("have hash {} for content", hash);
            of
        },
        Err(e) => {
            let err = RequestResult{
                typ: RequestResultType::WriteError,
                v: None,
                f: None,
            };
            return Err(err);
        }
    };

    let final_path_buf = path.join(&hash);
    let final_path = final_path_buf.as_path();
    fs_copy(tempfile.path(), final_path);

    let r = Record{
        digest: z,
        path: final_path_buf,
    };
    Ok(r)
}

pub fn put_mutable(pointer: Vec<u8>, path: &Path, mut f: impl Read, expected_size: usize) -> Result<Record, RequestResult> {
    let mutable_ref = hex::encode(&pointer);
    let link_path_buf = path.join(&mutable_ref);
    
    let record = put_immutable(path, f, expected_size);
    match record {
        Ok(v) => {
            symlink(&v.path, &link_path_buf);
            let r = Record{
                digest: pointer,
                path: link_path_buf.clone(),
            };
            return Ok(r);
        },
        Err(e) => {
            return Err(e);
        }
    }
}

pub fn get(pointer: Vec<u8>, path: &Path) -> Option<File> { //{ impl Read> {
    let path_canon = match path.canonicalize() {
        Ok(v) => {
            v
        },
        Err(e) => {
            return None;
        },
    };
    match File::open(path_canon) {
        Ok(f) => {
            return Some(f);
        },
        _ => {},
    }
    None
}

#[cfg(test)]
mod tests {
    use super::ResourceKey;
    use super::AuthResult;
    use super::{
        put_immutable,
        put_mutable,
    };
    use std::fs::read;
    use tempfile::tempdir;
    use hex;

    use env_logger;
    use log::{debug, info, error};

    #[test]
    fn test_pointer() {
        let resource = ResourceKey{
            v: vec!(0x66, 0x6f, 0x6f),
        };
        let subject = AuthResult{
            identity: vec!(0x62, 0x61, 0x72),
            error: false,
        };
        let r = resource.pointer_for(&subject);

        let foobar_digest = hex::decode("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2").unwrap();
        assert_eq!(r, foobar_digest);
    }

    #[test]
    fn test_immutable() {
        let d = tempdir().unwrap();
        let b = b"foo";
        put_immutable(d.path().clone(), &b[..], 3);
        
        let immutable_path_buf = d.path().join("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae");
        let immutable_path = immutable_path_buf.as_path();
        debug!(">>>>> checking immutable path {:?}", immutable_path);
        assert!(immutable_path.is_file());

        let mut r = read(immutable_path).unwrap();
        assert_eq!(r, b.to_vec());
    }
    
    #[test]
    fn test_mutable() {
        env_logger::init();

        let d = tempdir().unwrap();
        let b = b"foo";
        let ptr = b"foobar";
        put_mutable(ptr.to_vec(), d.path().clone(), &b[..], 3);

        let foobar_hex = hex::encode(ptr);
        let mutable_path_buf = d.path().join(foobar_hex);
        let mutable_path = mutable_path_buf.as_path();
        debug!(">>>>> checking mutable path {:?}", mutable_path);
        assert!(mutable_path.is_symlink());

        let mut r = read(mutable_path).unwrap();
        assert_eq!(r, b.to_vec());
    
        let immutable_path_buf = d.path().join("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae");
        let immutable_path = immutable_path_buf.as_path();
        debug!(">>>>> checking immutable path {:?}", immutable_path);
        assert!(immutable_path.is_file());

        let mut r = read(immutable_path).unwrap();
        assert_eq!(r, b.to_vec());
    }
}
