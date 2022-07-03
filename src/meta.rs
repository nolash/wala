use std::fs::File;
use std::path::Path;
use std::io::Write;
use mime::Mime;


pub fn register_type(path: &Path, digest: Vec<u8>, typ: Mime) -> Result<(), std::io::Error> {
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
    match File::create(path_canon) {
        Ok(mut f) => {
            f.write(typ.as_ref().as_bytes());
        }
        Err(e) => {
            return Err(e);
        }
    };
    Ok(())
}
