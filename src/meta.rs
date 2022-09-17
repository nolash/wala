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
use hex;

use log::{debug, error};


fn meta_path(path: &Path, digest: &Vec<u8>) -> Result<PathBuf, std::io::Error> {
    let digest_hex = hex::encode(digest);
    let fp = path.join(digest_hex);

    let mut path_canon = match fp.canonicalize() {
        Ok(v) => {
            v
        },
        Err(e) => {
            debug!("err {:?} {:?}", e, fp);
            return Err(e);
        }
    };

    path_canon.set_extension("meta");
    Ok(path_canon)
}

fn filename_path(path: &Path, digest: &Vec<u8>) -> Result<PathBuf, std::io::Error> {
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

    path_canon.set_extension("filename");
    Ok(path_canon)
}


/// Set a MIME type for the specified content.
///
/// # Arguments
///
/// * `path` - Absolute path to storage diectory.
/// * `digest` - Immutable reference to content.
/// * `typ` - MIME type to store for the content.
pub fn register_type(path: &Path, digest: &Vec<u8>, typ: Mime) -> Result<(), std::io::Error> {
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


/// Set a MIME type for the specified content.
///
/// # Arguments
///
/// * `path` - Absolute path to storage diectory.
/// * `digest` - Immutable reference to content.
/// * `typ` - MIME type to store for the content.
pub fn register_filename(path: &Path, digest: &Vec<u8>, name: String) -> Result<(), std::io::Error> {
    match filename_path(path, digest) {
        Ok(v) => {
            match File::create(v) {
                Ok(mut f) => {
                    f.write(name.as_str().as_bytes());
                    debug!("wrote to {:?}", f);
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
pub fn get_type(path: &Path, digest: &Vec<u8>) -> Option<Mime> {
    let digest_hex = hex::encode(digest);
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


/// Retrieve the alternate filename for the specified content.
///
/// # Arguments
///
/// * `path` - Absolute path to storage diectory.
/// * `digest` - Immutable reference to content.
pub fn get_filename(path: &Path, digest: &Vec<u8>) -> Option<String> {
    let digest_hex = hex::encode(digest);
    match filename_path(path, digest) {
        Ok(v) => {
            match read(v) {
                Ok(r) => {
                    let filename_str = String::from_utf8(r).unwrap();
                    debug!("filename {} retrieved for {}", &filename_str, &digest_hex);
                    return Some(filename_str);
                },
                Err(e) => {
                    debug!("filename file not found for {}: {}", &digest_hex, e);
                },
            };
        },
        _ => {},
    };
    None
}

#[cfg(test)]
mod tests {
    use hex;
    use std::str::FromStr;
    use tempfile::tempdir;
    use std::path::Path;
    use std::fs::{
        write,
        File,
    };

    use mime::Mime;

    use env_logger;
    use log::{debug, info, error};

    use super::{
        register_type,
        register_filename,
        get_type,
        get_filename,
    };

    #[test]
    fn test_meta_mime() {
        let d = tempdir().unwrap();
        let dp = d.path();
        let url = "deadbeef";
        let digest = hex::decode(&url).unwrap();
        let mime_type = Mime::from_str("application/zip").unwrap();

        let fp = dp.join(&url);
        write(&fp, b"foo");

        register_type(&dp, &digest, mime_type.clone());
        let mime_type_recovered = get_type(&dp, &digest).unwrap();
        assert_eq!(mime_type_recovered, mime_type);
    }

    #[test]
    fn test_meta_filename() {
        let d = tempdir().unwrap();
        let dp = d.path();
        let url = "deadbeef";
        let digest = hex::decode(&url).unwrap();
        let filename = "foo.zip";

        let fp = dp.join(&url);
        write(&fp, b"foo");

        register_filename(&dp, &digest, String::from(filename));
        let filename_recovered = get_filename(&dp, &digest).unwrap();
        assert_eq!(filename_recovered, filename);
    }
}
