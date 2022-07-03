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
