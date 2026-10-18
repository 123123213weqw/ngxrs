mod cache;
mod config;
mod conn;
mod http;
mod limit;
mod cookie;
mod geo;
mod log;
mod mail;
mod mapping;
mod fastcgi;
mod gzip;
mod h2server;
mod h3server;
mod instr;
mod net;
mod tls;
mod grpc;
mod proxy;
mod resolver;
mod stream;
mod uwsgi_scgi;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;

pub const VERSION: &str = concat!("ngxrs/", env!("CARGO_PKG_VERSION"));
pub const COMPAT_VERSION: &str = "1.28.0";

fn usage() -> String {
    format!(
        "{VERSION} (nginx-compatible)\n\
         Usage: ngxrs [-c config] [-p prefix] [-t|-T] [-e log] [-g directives] [-s signal] [-v] [-h]\n\
         \x20 -c FILE   configuration file (default: conf/nginx.conf)\n\
         \x20 -p DIR    prefix path\n\
         \x20 -t        test configuration and exit\n\
         \x20 -T        test, dump configuration and exit\n\
         \x20 -e FILE   error log file\n\
         \x20 -g TEXT   extra global directives\n\
         \x20 -s SIGNAL stop|quit|reload (needs a pid file)\n\
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
    let mut dump = false;
    let mut error_log: Option<PathBuf> = None;
    let mut globals: Vec<String> = Vec::new();
    let mut signal: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => conf = Some(PathBuf::from(args.next().ok_or("-c requires a file")?)),
            "-p" => prefix = Some(PathBuf::from(args.next().ok_or("-p requires a path")?)),
            "-t" => test = true,
            "-T" => {
                test = true;
                dump = true;
            }
            "-e" => error_log = Some(PathBuf::from(args.next().ok_or("-e requires a file")?)),
            "-g" => globals.push(args.next().ok_or("-g requires a value")?),
            "-s" => signal = Some(args.next().ok_or("-s requires a signal")?),
            "-q" => {}
            "-v" | "-V" => {
                println!("{VERSION}");
                if a == "-V" {
                    // Test::Nginx decides which suites can run by matching this
                    // text: known features use a regex from its own table, and
                    // anything else is matched as a literal substring. Printing
                    // only the version made it skip TLS/HTTP2/stream suites
                    // silently, so they read as "0/0, both skipped" instead of
                    // showing a real gap.
                    //
                    // Only modules that are actually implemented are listed.
                    // Absent upstream modules are named explicitly with
                    // `--without-`, which is how nginx reports a build that
                    // lacks them.
                    println!("built by ngxrs (Rust)");
                    println!("TLS SNI support enabled");
                    println!(
                        "configure arguments: --with-http_ssl_module \
                         --with-http_v2_module --with-stream --with-stream_ssl_module \
            --with-http_v3_module \
                         --with-http_grpc_module --without-http_ssi_module \
                         --without-http_auth_request_module --without-http_sub_module \
                         --without-http_dav_module --without-http_slice_module \
                         --with-mail --with-mail_ssl_module --without-http_memcached_module \
                         --without-http_flv_module --without-http_mp4_module \
                         --without-http_geoip_module --without-http_image_filter_module \
                         --without-http_xslt_module --without-http_perl_module \
                         --without-http_random_index_module \
                         --without-http_secure_link_module --without-http_stub_status_module \
                         --without-http_gzip_static_module --without-http_userid_module \
                         --without-http_split_clients_module --without-http_referer_module \
                         --without-http_browser_module --without-http_mirror_module \
                         --without-http_empty_gif_module"
                    );
                }
                println!("nginx compatibility target: {COMPAT_VERSION}");
                return Ok(ExitCode::SUCCESS);
            }
            "-h" | "-?" | "--help" => {
                print!("{}", usage());
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("invalid option: {other}").into()),
        }
    }

    let conf = conf.unwrap_or_else(|| PathBuf::from("conf/nginx.conf"));

    if let Some(sig) = signal {
        return send_signal(&conf, prefix.as_deref(), &sig);
    }

    let cfg = config::load_global(&conf, prefix.as_deref(), &globals, error_log.as_deref())?;

    for w in &cfg.warnings {
        eprintln!("ngxrs: [warn] {w}");
    }

    if test {
        eprintln!(
            "ngxrs: the configuration file {} syntax is ok",
            conf.display()
        );
        eprintln!(
            "ngxrs: configuration file {} test is successful",
            conf.display()
        );
        if dump {
            print!("{}", config::dump(&cfg));
        }
        return Ok(ExitCode::SUCCESS);
    }

    net::serve(cfg)?;
    Ok(ExitCode::SUCCESS)
}

/// `-s stop|quit|reload`: nginx reads the pid file and signals that process.
fn send_signal(conf: &std::path::Path, prefix: Option<&std::path::Path>, sig: &str) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cfg = config::load_light(conf, prefix)?;
    let pid_path = cfg
        .pid
        .clone()
        .ok_or("no pid file configured, cannot send signals")?;
    let text = std::fs::read_to_string(&pid_path)
        .map_err(|e| format!("cannot read pid file {}: {e}", pid_path.display()))?;
    let pid: i32 = text
        .trim()
        .parse()
        .map_err(|_| format!("invalid pid in {}", pid_path.display()))?;

    let signo = match sig {
        "stop" => libc::SIGTERM,
        "quit" => libc::SIGQUIT,
        "reload" => libc::SIGHUP,
        "reopen" => libc::SIGUSR1,
        other => return Err(format!("invalid signal name \"{other}\"").into()),
    };
    let rc = unsafe { libc::kill(pid, signo) };
    if rc != 0 {
        return Err(format!("kill({pid}) failed: {}", std::io::Error::last_os_error()).into());
    }
    Ok(ExitCode::SUCCESS)
}
