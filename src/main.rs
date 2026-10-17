mod config;
mod conn;
mod http;
mod log;
mod gzip;
mod h2server;
mod instr;
mod net;
mod tls;
mod proxy;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;

pub const VERSION: &str = concat!("ngxrs/", env!("CARGO_PKG_VERSION"));
pub const COMPAT_VERSION: &str = "1.28.0";

fn usage() -> String {
    format!(
        "{VERSION} (nginx-compatible)\n\
         Usage: ngxrs [-c config] [-p prefix] [-t] [-v] [-h]\n\
         \x20 -c FILE   configuration file (default: conf/nginx.conf)\n\
         \x20 -p DIR    prefix path (default: directory of config file)\n\
         \x20 -t        test configuration and exit\n\
         \x20 -v        show version and exit\n"
    )
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ngxrs: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut conf: Option<PathBuf> = None;
    let mut prefix: Option<PathBuf> = None;
    let mut test = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => conf = Some(PathBuf::from(args.next().ok_or("-c requires a file")?)),
            "-p" => prefix = Some(PathBuf::from(args.next().ok_or("-p requires a path")?)),
            "-t" | "-T" => test = true,
            "-v" | "-V" => {
                println!("{VERSION}");
                println!("nginx compatibility target: {COMPAT_VERSION}");
                return Ok(ExitCode::SUCCESS);
            }
            "-h" | "-?" | "--help" => {
                print!("{}", usage());
                return Ok(ExitCode::SUCCESS);
            }
            "-g" => {
                let _ = args.next();
                return Err("-g is not implemented yet".into());
            }
            "-s" => {
                let _ = args.next();
                return Err("signal control (-s) is not implemented yet".into());
            }
            other => return Err(format!("invalid option: {other}").into()),
        }
    }

    let conf = conf.unwrap_or_else(|| PathBuf::from("conf/nginx.conf"));
    let cfg = config::load_full(&conf, prefix.as_deref())?;

    for w in &cfg.warnings {
        eprintln!("ngxrs: [warn] {w}");
    }

    if test {
        eprintln!("ngxrs: the configuration file {conf:?} syntax is ok");
        eprintln!("ngxrs: configuration file {conf:?} test is successful");
        return Ok(ExitCode::SUCCESS);
    }

    net::serve(cfg)?;
    Ok(ExitCode::SUCCESS)
}
