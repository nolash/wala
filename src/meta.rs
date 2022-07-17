//! The `meta` module is an optional feature which stores the MIME type value from the
//! `Content-Type` header of a client `PUT` request.
//!
//! The MIME type is stored on the server under the same file identifier as the content but with a
//! postfix '.meta'.
//!
//! A check is performed to validate that the specified value is a valid MIME type string. However,
//! no further check is performed to attempt to verify whether the declared MIME type correctly
//! describes the file contents.
//!
//! For subsequent `GET` requests for the same content, the stored MIME type will be used as the
//! `Content-Type` header.
//! 
//! If no MIME type was specified for the content, or if the feature is not enabled, the
//! `Content-Type` header will always be `application/octet-stream`
//!
//! Any subsequent `PUT` for the same content specifying a `Content-Type` header will _overwrite_
//! the previously stored MIME type.
//!
//! There is no feature to _delete_ the MIME type association from the server. However, setting the MIME
//! type explicitly to `application/octet-stream` will achieve the same result as for records that
//! do not have a MIME type association.
use std::fs::{
    File,
    read,
};
use std::path::{
    Path,
    PathBuf,
};
use std::io::Write;
use std::str::FromStr;
use mime::Mime;

use log::{debug, error};


fn meta_path(path: &Path, digest: Vec<u8>) -> Result<PathBuf, std::io::Error> {
    let digest_hex = hex::encode(digest);
    let fp = path.join(digest_hex);

    let mut path_canon = match fp.canonicalize() {
        Ok(v) => {
            v
        },
        Err(e) => {
            return Err(e);
        }
    };

    path_canon.set_extension("meta");
    Ok(path_canon)
}


/// Set a MIME type for the specified content.
///
/// # Arguments
///
/// * `path` - Absolute path to storage diectory.
/// * `digest` - Immutable reference to content.
/// * `typ` - MIME type to store for the content.
pub fn register_type(path: &Path, digest: Vec<u8>, typ: Mime) -> Result<(), std::io::Error> {
    match meta_path(path, digest) {
        Ok(v) => {
            match File::create(v) {
                Ok(mut f) => {
                    f.write(typ.as_ref().as_bytes());
                }
                Err(e) => {
                    return Err(e);
                }
            };
        },
        _ => {},
    };
    Ok(())
}

/// Retrieve the MIME type for the specified content.
///
/// # Arguments
///
/// * `path` - Absolute path to storage diectory.
/// * `digest` - Immutable reference to content.
pub fn get_type(path: &Path, digest: Vec<u8>) -> Option<Mime> {
    let digest_hex = hex::encode(&digest);
    match meta_path(path, digest) {
        Ok(v) => {
            match read(v) {
                Ok(r) => {
                    let mime_str = String::from_utf8(r).unwrap();
                    debug!("content type {} retrieved for {}", &mime_str, &digest_hex);
                    let mime = Mime::from_str(mime_str.as_str()).unwrap();
                    return Some(mime);
                },
                Err(e) => {
                    debug!("meta type file not found for {}: {}", &digest_hex, e);
                },
            };
        },
        _ => {},
    };
    None
}
