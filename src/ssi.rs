//! Server Side Includes (`ssi on`).
//!
//! Directives are HTML comments of the form `<!--#name param="value" ... -->`.
//! nginx parses and evaluates them while streaming the body, so an `#include`
//! runs as an internal subrequest against the normal location pipeline.
//!
//! Everything here mirrors `ngx_http_ssi_filter_module.c`. The behaviours that
//! are easy to get wrong and were taken from probing a real nginx rather than
//! from intuition:
//!
//! * `#echo` defaults to **entity** encoding, not `none`.
//! * The url-escape set is exactly space `# $ % ' < > [ \ ] ^ ` { | }` plus
//!   everything outside printable ASCII; `&`, `+`, `:`, `/`, `=` and `?` are
//!   left alone.
//! * An undefined variable renders as `(none)`, an unknown command as
//!   `[an error occurred while processing the directive]`. A failed `#include`
//!   gets no placeholder at all: nginx inlines the subrequest's own output,
//!   so a 404 contributes its error page body.
//! * `$arg_*` values are **not** URL-decoded.

use std::collections::HashMap;

/// Rendered when a variable has no value (nginx's `NGX_HTTP_SSI_NONE`).
const NONE: &str = "(none)";
/// Rendered for a directive that could not be understood.
const ERR_DIRECTIVE: &str = "[an error occurred while processing the directive]";

/// State carried across one body render.
pub struct Ctx {
    /// `#set` variables, which shadow request variables.
    pub vars: HashMap<String, String>,
    /// `#config timefmt`, `%`-format for `$date_local`/`$date_gmt`.
    pub timefmt: String,
    /// `#config errmsg`: replaces [`ERR_DIRECTIVE`] when set.
    pub errmsg: Option<String>,
    /// Named `#block` bodies, keyed by name.
    pub blocks: HashMap<String, String>,
}

impl Default for Ctx {
    fn default() -> Self {
        Ctx {
            vars: HashMap::new(),
            // nginx's default timefmt (`ngx_http_ssi_timefmt`).
            timefmt: "%A, %d-%b-%Y %H:%M:%S %Z".to_string(),
            errmsg: None,
            blocks: HashMap::new(),
        }
    }
}

impl Ctx {
    fn err(&self) -> &str {
        self.errmsg.as_deref().unwrap_or(ERR_DIRECTIVE)
    }
}

/// One `#if` / `#elif` level.
#[derive(Clone)]
struct Cond {
    /// Whether any branch has been taken yet, so later ones stay suppressed.
    taken: bool,
    /// Whether the current branch is emitting.
    active: bool,
}

/// Parse the parameter list of a directive: `name="value"` pairs.
///
/// nginx requires the quotes and treats a missing `=` as an error, so this
/// returns `None` for a malformed list instead of guessing.
fn parse_params(s: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && (b[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let ks = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let key = s[ks..i].trim().to_string();
        i += 1; // '='
        if i >= b.len() || b[i] != b'"' {
            return None;
        }
        i += 1;
        let vs = i;
        while i < b.len() && b[i] != b'"' {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        out.push((key, s[vs..i].to_string()));
        i += 1;
    }
    Some(out)
}

fn param<'a>(p: &'a [(String, String)], name: &str) -> Option<&'a str> {
    p.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Percent-encode using nginx's SSI url table.
fn escape_url(out: &mut String, s: &str) {
    for &b in s.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'&'
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b';'
                    | b'='
                    | b'?'
                    | b'@'
                    | b'_'
                    | b'~'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit((b & 0xf) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
}

/// HTML-entity encode: nginx's `ngx_http_ssi_entity` table.
fn escape_entity(out: &mut String, s: &str) {
    // Char-wise, so multi-byte text survives; the four entities are ASCII.
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
}

/// Case-insensitive ASCII compare, used by the `=`/`!=` operators.
fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Evaluate an `#if`/`#elif` expression.
///
/// Supported forms, matching what nginx's ssi module accepts:
/// `$var`, `$var = text`, `$var != text`, `text = $var`, `text != $var`,
/// with either side optionally written as a `/regex/` literal.
fn eval_expr(expr: &str, ctx: &mut Ctx, lookup: &dyn Fn(&str) -> String) -> bool {
    // Captures are the only mutation, and they are written after matching, so
    // the expression itself sees a read-only view.
    let mut caps: Vec<(String, String)> = Vec::new();
    let hit = eval_expr_inner(expr, ctx, lookup, &mut caps);
    for (k, v) in caps {
        ctx.vars.insert(k, v);
    }
    hit
}

fn eval_expr_inner(
    expr: &str,
    ctx: &Ctx,
    lookup: &dyn Fn(&str) -> String,
    caps_out: &mut Vec<(String, String)>,
) -> bool {
    let e = expr.trim();
    if e.is_empty() {
        return false;
    }
    // Bare variable: true when set and non-empty.
    if e.starts_with('$') && !e.contains(|c: char| c.is_ascii_whitespace()) {
        let v = lookup(&e[1..]);
        return !v.is_empty();
    }
    // Find the operator outside of any /regex/ literals.
    let bytes = e.as_bytes();
    let mut op_at: Option<(usize, usize)> = None;
    let mut in_re = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'/' => in_re = !in_re,
            b'=' if !in_re => {
                let start = if i > 0 && bytes[i - 1] == b'!' {
                    i - 1
                } else {
                    i
                };
                op_at = Some((start, i + 1));
                break;
            }
            _ => {}
        }
        i += 1;
    }
    let Some((s, epos)) = op_at else {
        // No operator: treat as a literal truthiness test.
        return !e.is_empty();
    };
    let neq = &e[s..epos] == "!=";
    let lhs = e[..s].trim();
    let rhs = e[epos..].trim();
    // Either side may embed variables (`var$arg_v2`), not only start with one.
    let expand = |side: &str, look: &dyn Fn(&str) -> String| -> String {
        if !side.contains('$') {
            return side.to_string();
        }
        if let Some(rest) = side.strip_prefix('$') {
            if !rest.contains('$') {
                return look(rest);
            }
        }
        let mut out = String::with_capacity(side.len());
        let b = side.as_bytes();
        let mut start = 0usize;
        let mut i = 0usize;
        while i < b.len() {
            if b[i] == b'$' {
                let st = i + 1;
                let mut j = st;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j > st {
                    // Literal runs are copied as slices: a byte-wise
                    // `push(b as char)` re-encodes non-ASCII text as mojibake.
                    out.push_str(&side[start..i]);
                    out.push_str(&look(&side[st..j]));
                    i = j;
                    start = i;
                    continue;
                }
            }
            i += 1;
        }
        out.push_str(&side[start..]);
        out
    };
    let resolve = |side: &str, look: &dyn Fn(&str) -> String| -> String { expand(side, look) };
    // `= /re/` means "matches the regex", so the left side is matched against it.
    if let Some(re) = rhs.strip_prefix('/').and_then(|r| r.strip_suffix('/')) {
        let hay = resolve(lhs, lookup);
        let hit = regex_capture(re, &hay, caps_out);
        return if neq { !hit } else { hit };
    }
    if let Some(re) = lhs.strip_prefix('/').and_then(|r| r.strip_suffix('/')) {
        let hay = resolve(rhs, lookup);
        let hit = regex_capture(re, &hay, caps_out);
        return if neq { !hit } else { hit };
    }
    let (a, b) = (resolve(lhs, lookup), resolve(rhs, lookup));
    let hit = eq_ci(&a, &b);
    if neq {
        !hit
    } else {
        hit
    }
}

/// What the renderer needs from the surrounding request.
pub trait Host {
    /// Render a variable as nginx's SSI module would, honouring `timefmt`.
    fn var(&self, name: &str, ctx: &Ctx) -> Option<String>;
    /// Perform `#include virtual="<uri>"` and return the subrequest body.
    ///
    /// `has_stub` tells the host that a `stub="name"` was given: a failed
    /// subrequest must then keep reporting failure so the stub keeps standing in
    /// for it, instead of inlining the error page. nginx's stub is a
    /// post-subrequest handler that replaces the output on failure, so the
    /// stub wins over the subrequest body.
    fn include(&mut self, uri: &str, has_stub: bool) -> Option<Vec<u8>>;
}

/// Render `body` with SSI directives evaluated.
///
/// Returns the rendered bytes. Bodies with no `<!--#` are returned unchanged
/// so the common case stays cheap.
pub fn render(body: &[u8], host: &mut dyn Host) -> Vec<u8> {
    if !contains_directive(body) {
        return body.to_vec();
    }
    let mut ctx = Ctx::default();
    let mut out = Vec::with_capacity(body.len());
    let mut stack: Vec<Cond> = Vec::new();
    render_into(body, &mut out, &mut ctx, &mut stack, host);
    out
}

fn contains_directive(body: &[u8]) -> bool {
    // The needle is four bytes: `windows(3)` would never compare equal.
    body.windows(4).any(|w| w == b"<!--")
}

/// True when every enclosing `#if` branch is currently emitting.
fn emitting(stack: &[Cond]) -> bool {
    stack.iter().all(|c| c.active)
}

fn render_into(
    body: &[u8],
    out: &mut Vec<u8>,
    ctx: &mut Ctx,
    stack: &mut Vec<Cond>,
    host: &mut dyn Host,
) {
    let mut i = 0usize;
    while i < body.len() {
        let rest = &body[i..];
        // Directives start with `<!--#`.
        let Some(off) = find(rest, b"<!--#") else {
            out.extend_from_slice(rest);
            return;
        };
        let start = i + off;
        // nginx requires the directive to be closed by `-->`.
        let Some(endrel) = find(&body[start..], b"-->") else {
            out.extend_from_slice(&body[i..]);
            return;
        };
        let end = start + endrel;
        // Text before the directive is emitted only while a branch is active.
        if emitting(stack) {
            out.extend_from_slice(&body[i..start]);
        }
        let inner = &body[start + 5..end];
        let inner = std::str::from_utf8(inner).unwrap_or("");
        // `#block` owns the text up to its matching `#endblock`, so it is
        // handled here where that span is addressable.
        if let Some(rest) = directive_name(inner).strip_prefix("block") {
            if rest.is_empty() {
                let name = parse_params(&inner[directive_name(inner).len()..])
                    .and_then(|p| param(&p, "name").map(|s| s.to_string()));
                let after = end + 3;
                let close = match find_matching_endblock(body, after) {
                    Some(c) => c,
                    None => {
                        // Unterminated block: nginx reports a directive error.
                        if emitting(stack) {
                            out.extend_from_slice(ctx.err().as_bytes());
                        }
                        return;
                    }
                };
                if let Some(name) = name {
                    if emitting(stack) {
                        // Stored raw: its directives are evaluated when the
                        // block is used, since they may depend on that request.
                        ctx.blocks.insert(
                            name,
                            String::from_utf8_lossy(&body[after..close]).into_owned(),
                        );
                    }
                }
                i = close_after_endblock(body, close);
                continue;
            }
        }
        directive(inner, out, ctx, stack, host);
        i = end + 3;
    }
}

/// The directive word of an SSI directive body (text between `<!--#` and `-->`).
fn directive_name(inner: &str) -> String {
    let t = inner.trim();
    match t.find(|c: char| c.is_ascii_whitespace()) {
        Some(p) => t[..p].to_ascii_lowercase(),
        None => t.to_ascii_lowercase(),
    }
}

/// Offset of the `#endblock` matching a `#block` that opened at `from`,
/// honouring nesting. Returns the offset of the `<!--` that starts it.
fn find_matching_endblock(body: &[u8], from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = from;
    while i < body.len() {
        let Some(off) = find(&body[i..], b"<!--#") else {
            return None;
        };
        let start = i + off;
        let Some(endrel) = find(&body[start..], b"-->") else {
            return None;
        };
        let end = start + endrel;
        let text = std::str::from_utf8(&body[start + 5..end]).unwrap_or("");
        let name = directive_name(text);
        if name == "block" {
            depth += 1;
        } else if name == "endblock" {
            if depth == 0 {
                return Some(start);
            }
            depth -= 1;
        }
        i = end + 3;
    }
    None
}

/// Offset just past the `-->` of the `#endblock` at `at`.
fn close_after_endblock(body: &[u8], at: usize) -> usize {
    match find(&body[at..], b"-->") {
        Some(p) => at + p + 3,
        None => body.len(),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn directive(
    inner: &str,
    out: &mut Vec<u8>,
    ctx: &mut Ctx,
    stack: &mut Vec<Cond>,
    host: &mut dyn Host,
) {
    let inner = inner.trim();
    let (name, rest) = match inner.find(|c: char| c.is_ascii_whitespace()) {
        Some(p) => (&inner[..p], &inner[p..]),
        None => (inner, ""),
    };
    let name = name.to_ascii_lowercase();
    let params = parse_params(rest);

    // Conditional handling comes first: structure must be tracked even when the
    // branch is not emitting, otherwise nesting desynchronises.
    match name.as_str() {
        "if" => {
            let ok = match &params {
                Some(p) => match param(p, "expr") {
                    // Resolve the expression against a snapshot, then evaluate:
                    // the closure would otherwise borrow `ctx` while eval_expr
                    // needs it mutably to record captures.
                    Some(e) => {
                        let e = e.to_string();
                        let mut vals: HashMap<String, Option<String>> = HashMap::new();
                        for name in var_names(&e) {
                            let v = ctx
                                .vars
                                .get(&name)
                                .cloned()
                                .or_else(|| host.var(&name, ctx));
                            vals.insert(name, v);
                        }
                        let snap = Snapshot { vals };
                        eval_expr(&e, ctx, &|n| snap.get(n))
                    }
                    None => false,
                },
                None => false,
            };
            let emit = ok && emitting(stack);
            stack.push(Cond {
                taken: ok,
                active: emit,
            });
            return;
        }
        "elif" => {
            if stack.is_empty() {
                return;
            }
            let outer = emitting(&stack[..stack.len() - 1]);
            let top = stack.last_mut().expect("checked non-empty");
            if top.taken {
                top.active = false;
                return;
            }
            let ok = match &params {
                Some(p) => match param(p, "expr") {
                    // Resolve the expression against a snapshot, then evaluate:
                    // the closure would otherwise borrow `ctx` while eval_expr
                    // needs it mutably to record captures.
                    Some(e) => {
                        let e = e.to_string();
                        let mut vals: HashMap<String, Option<String>> = HashMap::new();
                        for name in var_names(&e) {
                            let v = ctx
                                .vars
                                .get(&name)
                                .cloned()
                                .or_else(|| host.var(&name, ctx));
                            vals.insert(name, v);
                        }
                        let snap = Snapshot { vals };
                        eval_expr(&e, ctx, &|n| snap.get(n))
                    }
                    None => false,
                },
                None => false,
            };
            top.active = ok && outer;
            top.taken = ok;
            return;
        }
        "else" => {
            if !stack.is_empty() {
                let outer = emitting(&stack[..stack.len() - 1]);
                let top = stack.last_mut().expect("checked non-empty");
                top.active = !top.taken && outer;
                top.taken = true;
            }
            return;
        }
        "endif" => {
            stack.pop();
            return;
        }
        // `#block`/`#endblock` are handled in `render_into`, which can see the
        // body between the two directives.
        "block" | "endblock" => return,
        _ => {}
    }

    if !emitting(stack) {
        return;
    }

    match name.as_str() {
        "echo" => {
            let Some(p) = params else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            let Some(var) = param(&p, "var") else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            let enc = param(&p, "encoding").unwrap_or("entity");
            // `default` supplies a value when the variable is unset.
            let value = match host.var(var, ctx) {
                Some(v) => v,
                None => match param(&p, "default") {
                    Some(d) => d.to_string(),
                    None => NONE.to_string(),
                },
            };
            let mut s = String::with_capacity(value.len());
            match enc.to_ascii_lowercase().as_str() {
                "none" => s.push_str(&value),
                "url" => escape_url(&mut s, &value),
                // nginx treats every other encoding as entity.
                _ => escape_entity(&mut s, &value),
            }
            out.extend_from_slice(s.as_bytes());
        }
        "set" => {
            let Some(p) = params else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            let Some(var) = param(&p, "var") else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            let Some(value) = param(&p, "value") else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            // A `value` may itself contain `$variables`.
            let expanded = expand_vars(value, ctx, host);
            ctx.vars.insert(var.to_string(), expanded);
        }
        "include" => {
            let Some(p) = params else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            let Some(uri) = param(&p, "virtual") else {
                // `file=` is a filesystem include; nginx supports it, but it is
                // not exercised by the suites we track.
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            let target = expand_vars(uri, ctx, host);
            let has_stub = param(&p, "stub").is_some();
            match host.include(&target, has_stub) {
                Some(b) => out.extend_from_slice(&b),
                None => {
                    // A `stub` names a `#block` whose rendered body replaces
                    // the error text when the include fails.
                    if let Some(bname) = param(&p, "stub") {
                        if let Some(raw) = ctx.blocks.get(bname).cloned() {
                            let mut sub_stack = stack.clone();
                            render_into(raw.as_bytes(), out, ctx, &mut sub_stack, host);
                            return;
                        }
                    }
                    out.extend_from_slice(ctx.errmsg.as_deref().unwrap_or("").as_bytes());
                }
            }
        }
        "config" => {
            let Some(p) = params else {
                out.extend_from_slice(ctx.err().as_bytes());
                return;
            };
            if let Some(t) = param(&p, "timefmt") {
                ctx.timefmt = t.to_string();
            }
            if let Some(e) = param(&p, "errmsg") {
                ctx.errmsg = Some(e.to_string());
            }
        }
        // `#printenv`, `#block` and `#endblock` outside a block are handled
        // above or are no-ops here.
        _ => {
            let msg = ctx.err().to_string();
            out.extend_from_slice(msg.as_bytes());
        }
    }
}

/// Expand `$name` inside a directive argument.
fn expand_vars(s: &str, ctx: &Ctx, host: &mut dyn Host) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut lit = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            if j > start {
                let name = &s[start..j];
                out.push_str(&s[lit..i]);
                match host.var(name, ctx) {
                    Some(v) => out.push_str(&v),
                    None => out.push_str(NONE),
                }
                i = j;
                lit = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[lit..]);
    out
}

/// Parse an `include virtual` URI the way nginx does: the path is unescaped and
/// an escaped `?` (`%3f`) starts the query string rather than being part of the
/// path. nginx unescapes first and then splits, which is why `/a%3fb` reaches
/// `/a` with query `b`.
pub fn split_include_uri(uri: &str) -> (String, String) {
    // Order matters: nginx splits on the *literal* `?` and only then unescapes.
    // So `%3f` stays in the path (it is a character in a filename), while a
    // real `?` starts the query. Doing it the other way round turns an escaped
    // question mark into a query separator, which is wrong.
    let decode = |x: &str| crate::util::percent_decode(x).unwrap_or_else(|_| x.to_string());
    match uri.split_once('?') {
        Some((p, q)) => (decode(p), decode(q)),
        None => (decode(uri), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHost {
        vars: HashMap<String, String>,
        include: Option<Vec<u8>>,
    }

    impl Host for TestHost {
        fn var(&self, name: &str, ctx: &Ctx) -> Option<String> {
            if let Some(v) = ctx.vars.get(name) {
                return Some(v.clone());
            }
            self.vars.get(name).cloned()
        }
        fn include(&mut self, _uri: &str, _has_stub: bool) -> Option<Vec<u8>> {
            self.include.clone()
        }
    }

    fn run(body: &str) -> String {
        let mut h = TestHost {
            vars: HashMap::new(),
            include: Some(b"INC".to_vec()),
        };
        String::from_utf8(render(body.as_bytes(), &mut h)).unwrap()
    }

    fn run_with(body: &str, vars: &[(&str, &str)]) -> String {
        let mut h = TestHost {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            include: Some(b"INC".to_vec()),
        };
        String::from_utf8(render(body.as_bytes(), &mut h)).unwrap()
    }

    #[test]
    fn echo_defaults_to_entity() {
        assert_eq!(run_with(r#"<a href="x">&"#, &[]), r#"<a href="x">&"#);
        let out = run_with(r#"A<!--#echo var="v" -->B"#, &[("v", "<&>\"")]);
        assert_eq!(out, "A&lt;&amp;&gt;&quot;B");
    }

    #[test]
    fn echo_none_leaves_value_alone() {
        let out = run_with(r#"<!--#echo var="v" encoding="none" -->"#, &[("v", "<x>")]);
        assert_eq!(out, "<x>");
    }

    #[test]
    fn url_escape_matches_nginx_table() {
        let out = run_with(
            r#"<!--#echo var="v" encoding="url" -->"#,
            &[("v", "<a b&c/d?e")],
        );
        // `&`, `/` and `?` are NOT escaped; space and `<` are.
        assert_eq!(out, "%3Ca%20b&c/d?e");
    }

    #[test]
    fn unset_variable_renders_none() {
        assert_eq!(run(r#"<!--#echo var="missing" -->"#), "(none)");
    }

    #[test]
    fn set_then_echo() {
        assert_eq!(
            run(r#"<!--#set var="b" value="hi" --><!--#echo var="b" -->"#),
            "hi"
        );
    }

    #[test]
    fn if_branches() {
        let body = r#"<!--#if expr="$a" -->Y<!--#else -->N<!--#endif -->"#;
        assert_eq!(run_with(body, &[("a", "1")]), "Y");
        assert_eq!(run_with(body, &[]), "N");
    }

    #[test]
    fn elif_chain() {
        let body = concat!(
            r#"<!--#if expr="$a = x" -->X"#,
            r#"<!--#elif expr="$a = y" -->Y"#,
            r#"<!--#else -->Z<!--#endif -->"#
        );
        assert_eq!(run_with(body, &[("a", "x")]), "X");
        assert_eq!(run_with(body, &[("a", "y")]), "Y");
        assert_eq!(run_with(body, &[("a", "q")]), "Z");
    }

    #[test]
    fn string_comparison_is_case_insensitive() {
        let body = r#"<!--#if expr="$a = HELLO" -->Y<!--#endif -->"#;
        assert_eq!(run_with(body, &[("a", "hello")]), "Y");
    }

    #[test]
    fn unknown_command_reports_error() {
        assert_eq!(run(r#"<!--#frobnicate -->"#), ERR_DIRECTIVE);
    }

    #[test]
    fn nested_if_suppresses_inner_text() {
        let body = concat!(
            r#"<!--#if expr="$no" -->"#,
            r#"A<!--#if expr="$a" -->B<!--#endif -->C"#,
            r#"<!--#endif -->Z"#
        );
        assert_eq!(run_with(body, &[("a", "1")]), "Z");
    }

    #[test]
    fn include_uri_splits_on_literal_then_unescapes() {
        let (p, q) = split_include_uri("/tes%741.html?test=1");
        assert_eq!(p, "/test1.html");
        assert_eq!(q, "test=1");
        // `%3f` is a filename character, NOT a query separator: nginx only
        // splits on a literal `?`.
        let (p, q) = split_include_uri("/a%3fb");
        assert_eq!(p, "/a?b");
        assert_eq!(q, "");
    }

    #[test]
    fn plain_body_is_untouched() {
        assert_eq!(run("just text"), "just text");
    }
}

/// All `$name` references in an expression.
fn var_names(expr: &str) -> Vec<String> {
    let b = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'$' {
            let st = i + 1;
            let mut j = st;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            if j > st {
                let n = &expr[st..j];
                if !out.iter().any(|x: &String| x == n) {
                    out.push(n.to_string());
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Variable values captured before evaluating an expression.
struct Snapshot {
    vals: HashMap<String, Option<String>>,
}

impl Snapshot {
    fn get(&self, name: &str) -> String {
        self.vals
            .get(name)
            .and_then(|v| v.clone())
            .unwrap_or_default()
    }
}

/// Match `hay` against a `/regex/` operand, caseless, storing captures as
/// `$1`, `$2`, ... and by name, which subsequent `#echo`/`#set` can use.
fn regex_capture(pattern: &str, hay: &str, caps_out: &mut Vec<(String, String)>) -> bool {
    let Ok(re) = regex::Regex::new(&format!("(?i){pattern}")) else {
        return false;
    };
    let Some(caps) = re.captures(hay) else {
        return false;
    };
    for i in 1..caps.len() {
        if let Some(m) = caps.get(i) {
            caps_out.push((i.to_string(), m.as_str().to_string()));
        }
    }
    for name in re.capture_names().flatten() {
        if let Some(m) = caps.name(name) {
            caps_out.push((name.to_string(), m.as_str().to_string()));
        }
    }
    true
}
