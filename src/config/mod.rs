//! nginx configuration loading.

pub mod lexer;
pub mod parser;
pub mod typed;

pub use parser::{ConfigError, Directive};
pub use typed::{AccessLog, Config, Http, ListenGroup, LocCfg, Match, Server};

use std::path::{Path, PathBuf};

pub fn load_full(conf: &Path, prefix: Option<&Path>) -> Result<Config, ConfigError> {
    let conf_path = if conf.is_absolute() {
        conf.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(conf)
    };

    let prefix = match prefix {
        Some(p) => {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(p)
            }
        }
        // nginx resolves relative paths against its prefix, not the config
        // file's directory; for the dev binary the working directory is the
        // natural analogue.
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let src = std::fs::read_to_string(&conf_path).map_err(|e| ConfigError::Io {
        path: conf_path.clone(),
        err: e,
    })?;

    let tree = parser::parse_str(&conf_path, &src)?;
    let tree = parser::expand_includes(tree, &prefix, 0)?;
    typed::build(tree, &prefix, conf_path)
}
