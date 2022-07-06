use std::path::PathBuf;
use clap::{
    App, 
    Arg,
    ArgMatches,
    SubCommand,
};

pub struct Settings {
    pub host: String,
    pub port: u16,
    pub dir: PathBuf,
}

const BIND_HOST: &str  = "0.0.0.0";
const BIND_PORT: u16 = 8000;
const DATA_DIR: &str = ".";

impl Settings {

    pub fn new() -> Settings {
        Settings {
            host: BIND_HOST.to_string(),
            port: BIND_PORT,
            dir: PathBuf::from(DATA_DIR),
        }
    }

    fn bind_from_args(&mut self, arg: &ArgMatches) {
        match arg.value_of("host") {
            Some(v) => {
                self.host = v.to_string();
            },
            _ => {},
        };

        match arg.value_of("port") {
            Some(v) => {
                let port = u16::from_str_radix(&v, 10);
                self.port = port.unwrap();
            },
            _ => {},
        };

        match arg.value_of("datadir") {
            Some(v) => {
                self.dir = PathBuf::from(v);
            },
            _ => {},

        };
    }

    pub fn from_args() -> Settings {
        let mut o = App::new("wala");
        o = o.version("0.0.1");
        o = o.author("Louis Holbrook <dev@holbrook.no>");
        o = o.arg(
            Arg::with_name("host")
                .long("host")
                .short("h")
                .value_name("Host or ip to bind server to.")
                .takes_value(true)
                );
        o = o.arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .value_name("Port to bind server to")
                .takes_value(true)
                );
        o = o.arg(
            Arg::with_name("datadir")
                .long("data-dir")
                .short("d")
                .value_name("Data directory")
                .takes_value(true)
                );

        let arg_matches = o.get_matches();
        let mut settings = Settings::new();
        settings.bind_from_args(&arg_matches);
        settings
    }
}
