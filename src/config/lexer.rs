//! nginx configuration tokenizer.
//!
//! Mirrors `ngx_conf_read_token()` semantics for the parts that matter to
//! real-world configs: one directive per `;`, blocks in `{}`, `#` comments,
//! single/double quoted strings with escapes, and `${var}` kept intact.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Word(String),
    Semi,
    LBrace,
    RBrace,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
}

#[derive(Debug)]
pub struct LexError {
    pub file: String,
    pub line: u32,
    pub msg: String,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.msg)
    }
}

impl std::error::Error for LexError {}

fn flush(out: &mut Vec<Token>, word: &mut String, in_word: &mut bool, line: u32) {
    if *in_word {
        out.push(Token {
            tok: Tok::Word(std::mem::take(word)),
            line,
        });
        *in_word = false;
    }
}

pub fn lex(file: &str, src: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<(usize, char)> = src.char_indices().collect();
    let n = chars.len();
    let mut i = 0usize;
    let mut line = 1u32;
    let mut out: Vec<Token> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;

    let err = |line: u32, msg: &str| LexError {
        file: file.to_string(),
        line,
        msg: msg.to_string(),
    };

    while i < n {
        let (_, c) = chars[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
                i += 1;
            } else if c == '\\' && i + 1 < n {
                let e = chars[i + 1].1;
                let decoded = match (q, e) {
                    ('"', 'n') => Some('\n'),
                    ('"', 'r') => Some('\r'),
                    ('"', 't') => Some('\t'),
                    (_, '"') => Some('"'),
                    (_, '\'') => Some('\''),
                    (_, '\\') => Some('\\'),
                    _ => None,
                };
                match decoded {
                    Some(d) => {
                        word.push(d);
                        i += 2;
                    }
                    None => {
                        // Keep unknown escapes verbatim (`"\.php$"` must stay a regex).
                        word.push('\\');
                        word.push(e);
                        i += 2;
                    }
                }
            } else {
                if c == '\n' {
                    line += 1;
                }
                word.push(c);
                i += 1;
            }
            continue;
        }

        match c {
            ' ' | '\t' | '\r' => {
                flush(&mut out, &mut word, &mut in_word, line);
                i += 1;
            }
            '\n' => {
                flush(&mut out, &mut word, &mut in_word, line);
                line += 1;
                i += 1;
            }
            '#' => {
                if in_word {
                    word.push('#');
                    i += 1;
                } else {
                    while i < n && chars[i].1 != '\n' {
                        i += 1;
                    }
                }
            }
            ';' => {
                flush(&mut out, &mut word, &mut in_word, line);
                out.push(Token {
                    tok: Tok::Semi,
                    line,
                });
                i += 1;
            }
            '{' => {
                flush(&mut out, &mut word, &mut in_word, line);
                out.push(Token {
                    tok: Tok::LBrace,
                    line,
                });
                i += 1;
            }
            '}' => {
                flush(&mut out, &mut word, &mut in_word, line);
                out.push(Token {
                    tok: Tok::RBrace,
                    line,
                });
                i += 1;
            }
            '$' if i + 1 < n && chars[i + 1].1 == '{' => {
                word.push('$');
                word.push('{');
                in_word = true;
                i += 2;
                while i < n && chars[i].1 != '}' {
                    if chars[i].1 == '\n' {
                        line += 1;
                    }
                    word.push(chars[i].1);
                    i += 1;
                }
                if i < n {
                    word.push('}');
                    i += 1;
                }
            }
            '"' | '\'' => {
                quote = Some(c);
                in_word = true;
                i += 1;
            }
            _ => {
                word.push(c);
                in_word = true;
                i += 1;
            }
        }
    }

    if quote.is_some() {
        return Err(err(line, "unexpected end of file, expecting closing quote"));
    }
    flush(&mut out, &mut word, &mut in_word, line);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<String> {
        lex("test.conf", src)
            .unwrap()
            .into_iter()
            .map(|t| match t.tok {
                Tok::Word(w) => w,
                Tok::Semi => ";".to_string(),
                Tok::LBrace => "{".to_string(),
                Tok::RBrace => "}".to_string(),
            })
            .collect()
    }

    #[test]
    fn basic_directives() {
        assert_eq!(
            words("worker_processes auto;\n"),
            vec!["worker_processes", "auto", ";"]
        );
    }

    #[test]
    fn comments_and_blocks() {
        let src = "# head\nevents { # inline\n  worker_connections 1024;\n}\n";
        assert_eq!(
            words(src),
            vec!["events", "{", "worker_connections", "1024", ";", "}"]
        );
    }

    #[test]
    fn quoted_strings() {
        assert_eq!(
            words(r#"add_header X "a b; c" always;"#),
            vec!["add_header", "X", "a b; c", "always", ";"]
        );
    }

    #[test]
    fn variables_with_braces() {
        assert_eq!(
            words("return 301 https://$host:${server_port}$request_uri;"),
            vec![
                "return",
                "301",
                "https://$host:${server_port}$request_uri",
                ";"
            ]
        );
    }

    #[test]
    fn regex_braces_are_quoted() {
        assert_eq!(
            words(r#"location ~ "^/a{2}$" { }"#),
            vec!["location", "~", "^/a{2}$", "{", "}"]
        );
    }

    #[test]
    fn unterminated_quote() {
        assert!(lex("t.conf", "add_header X \"oops;").is_err());
    }
}
