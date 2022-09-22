use std::str::FromStr;
use std::io;
use std::convert::Infallible;
use std::fs::{
    File,
    remove_file,
};
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

use mime::Mime;

use log::{debug, info, error};

#[derive(Debug, PartialEq)]
/// Status codes to represent the result of a request.
pub enum RequestResultType {
    /// Record has been found.
    Found,
    /// Record has been updated or created.
    Changed,
    /// Cannot find and/or read record.
    ReadError,
    /// Cannot write immutable record to storage.
    WriteError,
    /// Authentication cannot be verified (signature mismatch).
    AuthError,
    /// Invalid request from client.
    InputError,
    /// Cannot store mutable record.
    RecordError,
}

/// Interface to interpret and read the result of a request.
pub struct RequestResult {
    /// Result code of the request.
    pub typ: RequestResultType,
    /// Contains the result body (reference string) of a PUT request.
    pub v: Option<String>,
    /// Contains the result body (as a reader) of a GET request.
    pub f: Option<File>,
    /// Contains the MIME type of the content of a GET response (if build with the `meta` feature).
    pub m: Option<Mime>,
    /// Contains the file name to use for download request requesting a filename.
    pub n: Option<String>,
    /// Contains the authentication result.
    pub a: Option<AuthResult>,
    /// Aliase content, in case of mutable reference.
    pub s: Option<String>,
}

impl RequestResult {
    pub fn new(typ: RequestResultType) -> RequestResult {
        RequestResult {
            typ: typ,
            v: None,
            f: None,
            m: None,
            n: None,
            a: None,
            s: None,
        }
    }

    pub fn with_content(mut self, s: String) -> RequestResult {
        self.v = Some(s);
        self
    }

    pub fn with_auth(mut self, a: AuthResult) -> RequestResult {
        self.a = Some(a);
        self
    }

    pub fn with_file(mut self, f: File) -> RequestResult {
        self.f = Some(f);
        self
    }

    pub fn with_aliased(mut self, s: String) -> RequestResult {
        self.s = Some(s);
        self
    }
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

/// Represents a single record on the server.
pub struct Record {
    /// Digest of content.
    pub digest: Vec<u8>,
    /// Server side path to content.
    pub path: PathBuf,
    /// Alias
    pub alias: Option<Vec<u8>>,
}

/// Identifier part of the for mutable content reference.
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
    /// Create a reference for the identifier using the verified identity from client
    /// authentication.
    pub fn pointer_for(&self, subject: &AuthResult) -> Vec<u8> {
        let mut h = Sha256::new();
        debug!("update {:?} {:?}", hex::encode(&self.v), hex::encode(&subject.identity));
        h.update(&self.v);
        h.update(&subject.identity);
        h.finalize().to_vec()
    }
}


/// Store an immutable record on file.
///
/// # Arguments
///
/// * `path` - Absolute path to storage directory.
/// * `f` - Reader providing the contents of the file.
/// * `expected_size` - Size hint of content.
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
                        let err = RequestResult::new(RequestResultType::ReadError);
                        return Err(err);
                    },
                }
            }
    
            if expected_size > 0 {
                if expected_size != total_size {
                    let err = RequestResult::new(RequestResultType::ReadError);
                    return Err(err);
                }
            }

            z = h.finalize().to_vec();
            hash = hex::encode(&z);
            info!("have hash {} for content", hash);
            of
        },
        Err(e) => {
            let err = RequestResult::new(RequestResultType::WriteError);
            return Err(err);
        }
    };

    let final_path_buf = path.join(&hash);
    let final_path = final_path_buf.as_path();
    fs_copy(tempfile.path(), final_path);

    let r = Record{
        digest: z,
        path: final_path_buf,
        alias: None,
    };
    Ok(r)
}

/// Store an immutable record on file with a mutable reference.
///
/// This method will fail if the provided [auth::AuthResult](crate::auth::AuthResult) is not a
/// successful authentcation.
///
/// # Arguments
///
/// * `path` - Absolute path to storage directory.
/// * `f` - Reader providing the contents of the file.
/// * `expected_size` - Size hint of content.
/// * `key` - Mutable reference generator.
/// * `auth` - Authentication result containing the client identity.
pub fn put_mutable(path: &Path, mut f: impl Read, expected_size: usize, key: &ResourceKey, auth: &AuthResult) -> Result<Record, RequestResult> {
    let pointer = key.pointer_for(auth);
    let mutable_ref = hex::encode(&pointer);
    debug!("generated mutable ref {}", &mutable_ref);
    let link_path_buf = path.join(&mutable_ref);
    
    let record = put_immutable(path, f, expected_size);
    match record {
        Ok(v) => {
            match remove_file(&link_path_buf) {
                Ok(r) => {
                    info!("unlinked mutable ref on {:?}", &link_path_buf);
                },
                Err(e) => {
                    debug!("clear symlink failed {:?}", &e);
                }
            };
            symlink(&v.path, &link_path_buf);
            let r = Record{
                digest: pointer,
                path: link_path_buf.clone(),
                alias: Some(v.digest),
            };
            return Ok(r);
        },
        Err(e) => {
            return Err(e);
        }
    }
}


/// Retrieve the content for a single record.
///
/// # Arguments
///
/// * `pointer` - A reference to the pointer.
/// * `path` - Absolute path to storage directory.
pub fn get(pointer: Vec<u8>, path: &Path) -> Option<File> {
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
    use std::fs::{
        read,
        File,
    };
    use std::io::Read;
    use tempfile::tempdir;
    use hex;
    use std::str::FromStr;

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
        let d = tempdir().unwrap();
        let b = b"foo";
        let k = ResourceKey::from_str("baz").unwrap();
        let auth_result = AuthResult{
            identity: Vec::from("bar"),
            error: false,
        };
        put_mutable(d.path().clone(), &b[..], 3, &k, &auth_result);

        let foobar_hex = "561061c1c6b4fec065f5761e12f072b9591cf3ac55c70fe6fcbb39b0c16c6e20";
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

    #[test]
    fn test_mutable_overwrite() {
        let d = tempdir().unwrap();
        let mut b = b"foo";
        let k = ResourceKey::from_str("baz").unwrap();
        let mut auth_result = AuthResult{
            identity: Vec::from("bar"),
            error: false,
        };
        let result: Vec<u8> = vec!();
        let r = put_mutable(d.path().clone(), &b[..], 3, &k, &auth_result).unwrap();

        let foobar_hex = "561061c1c6b4fec065f5761e12f072b9591cf3ac55c70fe6fcbb39b0c16c6e20";
        let mutable_path_buf = d.path().join(foobar_hex);
        let mutable_path = mutable_path_buf.as_path();

        let mut f = File::open(&mutable_path).unwrap();
        let mut result_behind: Vec<u8> = vec!();
        f.read_to_end(&mut result_behind);
        let mut result_expect = "foo".as_bytes();
        assert_eq!(result_behind, result_expect);

        b = b"bar";
        auth_result = AuthResult{
            identity: Vec::from("bar"),
            error: false,
        };
        let r = put_mutable(d.path().clone(), &b[..], 3, &k, &auth_result).unwrap();

        f = File::open(&mutable_path).unwrap();
        result_behind = vec!();
        f.read_to_end(&mut result_behind);
        result_expect = "bar".as_bytes();
        assert_eq!(result_behind, result_expect);
    }
}
