//! Configuration syntax tree + `include` handling.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::lexer::{lex, Tok, Token};

#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub block: Option<Vec<Directive>>,
    pub file: Arc<PathBuf>,
    pub line: u32,
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        err: std::io::Error,
    },
    Lex(super::lexer::LexError),
    Syntax {
        file: PathBuf,
        line: u32,
        msg: String,
    },
    Semantic {
        file: PathBuf,
        line: u32,
        msg: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, err } => write!(f, "{}: {}", path.display(), err),
            ConfigError::Lex(e) => write!(f, "{e}"),
            ConfigError::Syntax { file, line, msg } | ConfigError::Semantic { file, line, msg } => {
                write!(f, "{}:{}: {}", file.display(), line, msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn syntax(file: &Path, line: u32, msg: impl Into<String>) -> ConfigError {
    ConfigError::Syntax {
        file: file.to_path_buf(),
        line,
        msg: msg.into(),
    }
}

pub fn parse_str(file: &Path, src: &str) -> Result<Vec<Directive>, ConfigError> {
    let tokens = lex(&file.display().to_string(), src).map_err(ConfigError::Lex)?;
    let file = Arc::new(file.to_path_buf());
    let mut i = 0usize;
    parse_block(&tokens, &mut i, &file, true)
}

fn parse_block(
    tokens: &[Token],
    i: &mut usize,
    file: &Arc<PathBuf>,
    top: bool,
) -> Result<Vec<Directive>, ConfigError> {
    let mut out: Vec<Directive> = Vec::new();

    loop {
        if *i >= tokens.len() {
            if top {
                return Ok(out);
            }
            return Err(syntax(
                file,
                tokens.last().map(|t| t.line).unwrap_or(0),
                "unexpected end of file, expecting \"}\"",
            ));
        }

        match &tokens[*i].tok {
            Tok::RBrace => {
                if top {
                    return Err(syntax(file, tokens[*i].line, "unexpected \"}\""));
                }
                *i += 1;
                return Ok(out);
            }
            Tok::Semi => return Err(syntax(file, tokens[*i].line, "unexpected \";\"")),
            Tok::LBrace => return Err(syntax(file, tokens[*i].line, "unexpected \"{\"")),
            Tok::Word(name) => {
                let name = name.clone();
                let line = tokens[*i].line;
                *i += 1;
                let mut args: Vec<String> = Vec::new();

                loop {
                    if *i >= tokens.len() {
                        return Err(syntax(
                            file,
                            line,
                            format!("directive \"{name}\" is not terminated by \";\""),
                        ));
                    }
                    match &tokens[*i].tok {
                        Tok::Word(w) => {
                            args.push(w.clone());
                            *i += 1;
                        }
                        Tok::Semi => {
                            *i += 1;
                            out.push(Directive {
                                name,
                                args,
                                block: None,
                                file: file.clone(),
                                line,
                            });
                            break;
                        }
                        Tok::LBrace => {
                            *i += 1;
                            let inner = parse_block(tokens, i, file, false)?;
                            out.push(Directive {
                                name,
                                args,
                                block: Some(inner),
                                file: file.clone(),
                                line,
                            });
                            break;
                        }
                        Tok::RBrace => {
                            return Err(syntax(
                                file,
                                tokens[*i].line,
                                format!("directive \"{name}\" is not terminated by \";\""),
                            ))
                        }
                    }
                }
            }
        }
    }
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);

    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = si;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Expand a path that may contain shell-style `*` / `?` wildcards.
pub fn expand_path(pattern: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let pat = pattern.to_string_lossy();
    if !pat.contains('*') && !pat.contains('?') {
        if pattern.exists() {
            return Ok(vec![pattern.to_path_buf()]);
        }
        return Err(ConfigError::Io {
            path: pattern.to_path_buf(),
            err: std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory"),
        });
    }

    let parent = pattern.parent().filter(|p| !p.as_os_str().is_empty());
    let name_pat = pattern
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let dir = parent.unwrap_or_else(|| Path::new("."));

    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| ConfigError::Io {
        path: dir.to_path_buf(),
        err: e,
    })?;
    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        if wildcard_match(&name_pat, &fname) {
            out.push(entry.path());
        }
    }
    out.sort();
    if out.is_empty() {
        return Err(ConfigError::Io {
            path: pattern.to_path_buf(),
            err: std::io::Error::new(std::io::ErrorKind::NotFound, "no files matched"),
        });
    }
    Ok(out)
}

const MAX_INCLUDE_DEPTH: usize = 32;

pub fn expand_includes(
    directives: Vec<Directive>,
    prefix: &Path,
    depth: usize,
) -> Result<Vec<Directive>, ConfigError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(ConfigError::Semantic {
            file: PathBuf::from("<config>"),
            line: 0,
            msg: "include nesting is too deep (cycle?)".to_string(),
        });
    }

    let mut out = Vec::with_capacity(directives.len());
    for mut d in directives {
        if d.name == "include" && d.block.is_none() {
            for arg in &d.args {
                let p = Path::new(arg);
                let full = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    prefix.join(p)
                };
                let files = expand_path(&full)?;
                for f in files {
                    let src = std::fs::read_to_string(&f).map_err(|e| ConfigError::Io {
                        path: f.clone(),
                        err: e,
                    })?;
                    let sub = parse_str(&f, &src)?;
                    let sub = expand_includes(sub, prefix, depth + 1)?;
                    out.extend(sub);
                }
            }
            continue;
        }
        // Recurse into blocks (include inside http/server is legal).
        if let Some(block) = d.block.take() {
            d.block = Some(expand_includes(block, prefix, depth + 1)?);
        }
        out.push(d);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_blocks() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    location / {
                        root /srv;
                    }
                }
            }
        "#;
        let tree = parse_str(Path::new("t.conf"), src).unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].name, "http");
        let servers = tree[0].block.as_ref().unwrap();
        assert_eq!(servers[0].name, "server");
        let server_block = servers[0].block.as_ref().unwrap();
        assert_eq!(server_block[0].name, "listen");
        assert_eq!(server_block[0].args, vec!["8080"]);
        let loc = &server_block[1];
        assert_eq!(loc.name, "location");
        assert!(loc.block.is_some());
    }

    #[test]
    fn missing_semicolon_is_error() {
        let e = parse_str(Path::new("t.conf"), "worker_processes auto").unwrap_err();
        assert!(e.to_string().contains("not terminated"));
    }

    #[test]
    fn wildcard() {
        assert!(wildcard_match("*.conf", "mime.types.conf"));
        assert!(!wildcard_match("*.conf", "mime.types"));
        assert!(wildcard_match("mime.type?", "mime.types"));
    }
}
