//! nginx configuration loading.

pub mod lexer;
pub mod parser;
pub mod typed;

pub use parser::{ConfigError, Directive};
pub use typed::{
    access_denied, access_denied_for, next_upstream, parse_time, AccessLog, AccessRule,
    AutoindexFormat, CacheZone, Escape, Symlinks,
    Config, FastcgiParam, FastcgiPass, Http, IfBlock, IfCond, KeepaliveDisable, LbMethod,
    ListenGroup, LocCfg, Match, ProxyPass, ProxyTarget, RedirectRule, Rewrite, RewriteFlag,
    ScgiPass, Server, Step, Upstream, UpstreamServer, UwsgiPass,
};

use std::path::{Path, PathBuf};

pub fn load_full(conf: &Path, prefix: Option<&Path>) -> Result<Config, ConfigError> {
    // nginx resolves a relative `-c` against the prefix, not the cwd.
    let conf_path = match prefix {
        Some(p) if !conf.is_absolute() => absolute(p).join(conf),
        _ => absolute(conf),
    };

    let prefix = resolve_prefix(prefix, &conf_path);

    let src = std::fs::read_to_string(&conf_path).map_err(|e| ConfigError::Io {
        path: conf_path.clone(),
        err: e,
    })?;

    let tree = parser::parse_str(&conf_path, &src)?;
    let tree = parser::expand_includes(tree, &prefix, 0)?;
    typed::build(tree, &prefix, conf_path)
}

/// Load with `-g` global directives prepended and `-e` overriding error_log.
pub fn load_global(
    conf: &Path,
    prefix: Option<&Path>,
    globals: &[String],
    error_log: Option<&Path>,
) -> Result<Config, ConfigError> {
    if globals.is_empty() && error_log.is_none() {
        return load_full(conf, prefix);
    }

    let conf_path = match prefix {
        Some(p) if !conf.is_absolute() => absolute(p).join(conf),
        _ => absolute(conf),
    };
    let prefix_dir = resolve_prefix(prefix, &conf_path);
    let src = std::fs::read_to_string(&conf_path).map_err(|e| ConfigError::Io {
        path: conf_path.clone(),
        err: e,
    })?;

    let mut tree = Vec::new();
    // `-g` directives live in the main context, before the file's own content.
    let joined = globals.join(" ");
    if !joined.trim().is_empty() {
        let extra = format!("{joined}");
        let mut parsed = parser::parse_str(&conf_path, &extra)?;
        tree.append(&mut parsed);
    }
    let mut file_tree = parser::parse_str(&conf_path, &src)?;
    tree.append(&mut file_tree);

    let tree = parser::expand_includes(tree, &prefix_dir, 0)?;
    let mut cfg = typed::build(tree, &prefix_dir, conf_path)?;
    if let Some(p) = error_log {
        // `-e` is also relative to the prefix.
        cfg.error_log = Some(if p.is_absolute() {
            p.to_path_buf()
        } else {
            prefix_dir.join(p)
        });
    }
    Ok(cfg)
}

/// Minimal load used by `-s`: no includes beyond the pid directive's needs.
pub fn load_light(conf: &Path, prefix: Option<&Path>) -> Result<Config, ConfigError> {
    load_full(conf, prefix)
}

/// Render the parsed configuration in nginx.conf syntax (`-T`).
pub fn dump(cfg: &Config) -> String {
    let mut out = String::new();
    out.push_str("# configuration file dump (ngxrs -T)\n");
    out.push_str(&format!("# prefix: {}\n", cfg.prefix.display()));
    out.push_str(&format!(
        "worker_processes {};\n",
        if cfg.worker_processes == 0 {
            "auto".to_string()
        } else {
            cfg.worker_processes.to_string()
        }
    ));
    out.push_str(&format!(
        "daemon {};\n",
        if cfg.daemon { "on" } else { "off" }
    ));
    if let Some(p) = &cfg.pid {
        out.push_str(&format!("pid {};\n", p.display()));
    }

    out.push_str("\nevents {\n}\n\nhttp {\n");
    for up in &cfg.http.upstreams {
        out.push_str(&format!("    upstream {} {{\n", up.name));
        for s in &up.servers {
            out.push_str(&format!("        server {};\n", s.addr));
        }
        if up.keepalive > 0 {
            out.push_str(&format!("        keepalive {};\n", up.keepalive));
        }
        out.push_str("    }\n");
    }
    for srv in &cfg.http.servers {
        out.push_str("    server {\n");
        for g in &cfg.http.groups {
            if g.servers.contains(&srv.idx) {
                out.push_str(&format!(
                    "        listen {}{};\n",
                    g.addr,
                    if srv.ssl { " ssl" } else { "" }
                ));
            }
        }
        if !srv.names.is_empty() {
            out.push_str(&format!("        server_name {};\n", srv.names.join(" ")));
        }
        if let Some(c) = &srv.ssl_certificate {
            out.push_str(&format!("        ssl_certificate {};\n", c.display()));
        }
        out.push_str(&format!(
            "        root {};\n",
            srv.default_loc.root.display()
        ));
        for loc in &srv.locations {
            out.push_str(&format!("        location {} {{\n", loc.pattern()));
            out.push_str("        }\n");
        }
        out.push_str("    }\n");
    }
    for st in &cfg.stream.servers {
        out.push_str(&format!(
            "    # stream listen {}{}\n",
            st.listen,
            if st.udp { " udp" } else { "" }
        ));
    }
    out.push_str("}\n");
    out
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

fn resolve_prefix(prefix: Option<&Path>, conf_path: &Path) -> PathBuf {
    match prefix {
        Some(p) => absolute(p),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

/// `map {}` blocks of the active configuration.
///
/// nginx keeps these per-location-module; a single process-wide table is
/// behaviourally equivalent because only one configuration is live at a time.
static MAPS: std::sync::OnceLock<std::sync::RwLock<std::sync::Arc<Vec<crate::mapping::MapDef>>>> =
    std::sync::OnceLock::new();

fn maps_cell() -> &'static std::sync::RwLock<std::sync::Arc<Vec<crate::mapping::MapDef>>> {
    MAPS.get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(Vec::new())))
}

/// Publish the maps of a freshly built configuration.
pub fn set_maps(m: Vec<crate::mapping::MapDef>) {
    if let Ok(mut w) = maps_cell().write() {
        *w = std::sync::Arc::new(m);
    }
}

/// Snapshot of the live `map` definitions.
pub fn maps() -> std::sync::Arc<Vec<crate::mapping::MapDef>> {
    maps_cell()
        .read()
        .map(|r| r.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// `split_clients` blocks of the active configuration (same rationale as
/// `MAPS`).
static SPLITS: std::sync::OnceLock<
    std::sync::RwLock<std::sync::Arc<Vec<crate::split::SplitClients>>>,
> = std::sync::OnceLock::new();

fn splits_cell() -> &'static std::sync::RwLock<std::sync::Arc<Vec<crate::split::SplitClients>>> {
    SPLITS.get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(Vec::new())))
}

pub fn set_splits(v: Vec<crate::split::SplitClients>) {
    if let Ok(mut w) = splits_cell().write() {
        *w = std::sync::Arc::new(v);
    }
}

pub fn splits() -> std::sync::Arc<Vec<crate::split::SplitClients>> {
    splits_cell()
        .read()
        .map(|r| r.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// `geo {}` blocks of the active configuration.
static GEOS: std::sync::OnceLock<std::sync::RwLock<std::sync::Arc<Vec<crate::geo::GeoDef>>>> =
    std::sync::OnceLock::new();

fn geos_cell() -> &'static std::sync::RwLock<std::sync::Arc<Vec<crate::geo::GeoDef>>> {
    GEOS.get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(Vec::new())))
}

pub fn set_geos(g: Vec<crate::geo::GeoDef>) {
    if let Ok(mut w) = geos_cell().write() {
        *w = std::sync::Arc::new(g);
    }
}

pub fn geos() -> std::sync::Arc<Vec<crate::geo::GeoDef>> {
    geos_cell()
        .read()
        .map(|r| r.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}
