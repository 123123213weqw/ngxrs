//! Typed, nginx-shaped configuration model.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::parser::{ConfigError, Directive};

/// `client_body_in_file_only` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientBodyFileOnly {
    /// Write the body to a file and keep it.
    On,
    /// Write the body to a file and unlink it when the request finishes.
    Clean,
}

pub const DEFAULT_CLIENT_MAX_BODY: u64 = 1024 * 1024;

/// `disable_symlinks`: whether a symlink in the path is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symlinks {
    Off,
    On,
    IfNotOwner,
}

/// `autoindex_format`: which body `autoindex on` produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoindexFormat {
    Html,
    Json,
    Jsonp,
    Xml,
}
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(75);

#[derive(Debug, Clone)]
pub enum Match {
    Exact(String),
    Prefix(String),
    PrefixNoRegex(String),
    Regex {
        re: regex::Regex,
        ci: bool,
        src: String,
    },
    Named(String),
}

#[derive(Debug, Clone)]
pub struct Location {
    pub matcher: Match,
    pub cfg: LocCfg,
    pub nested: Vec<Location>,
}

/// `proxy_next_upstream` flags, nginx's `NGX_HTTP_UPSTREAM_FT_*` bits. The
/// directive *replaces* the default, so `proxy_next_upstream http_500` no
/// longer retries on connect errors.
/// Parse a `*_next_upstream` argument list into flags. The directive *replaces*
/// the default set, so an empty result means "never retry" only when `off` was
/// given -- otherwise the caller keeps its own default.
pub fn next_upstream_flags(args: &[String]) -> u32 {
    let mut flags = 0u32;
    for a in args {
        flags |= match a.as_str() {
            "off" => next_upstream::OFF,
            "error" => next_upstream::ERROR,
            "timeout" => next_upstream::TIMEOUT,
            "invalid_header" => next_upstream::INVALID_HEADER,
            "http_500" => next_upstream::HTTP_500,
            "http_502" => next_upstream::HTTP_502,
            "http_503" => next_upstream::HTTP_503,
            "http_504" => next_upstream::HTTP_504,
            "http_403" => next_upstream::HTTP_403,
            "http_404" => next_upstream::HTTP_404,
            "http_429" => next_upstream::HTTP_429,
            "non_idempotent" => next_upstream::NON_IDEMPOTENT,
            _ => 0,
        };
    }
    flags
}

pub mod next_upstream {
    pub const OFF: u32 = 1 << 0;
    pub const ERROR: u32 = 1 << 1;
    pub const TIMEOUT: u32 = 1 << 2;
    pub const INVALID_HEADER: u32 = 1 << 3;
    pub const HTTP_500: u32 = 1 << 4;
    pub const HTTP_502: u32 = 1 << 5;
    pub const HTTP_503: u32 = 1 << 6;
    pub const HTTP_504: u32 = 1 << 7;
    pub const HTTP_403: u32 = 1 << 8;
    pub const HTTP_404: u32 = 1 << 9;
    pub const HTTP_429: u32 = 1 << 10;
    pub const NON_IDEMPOTENT: u32 = 1 << 11;
    pub const ANY_HTTP: u32 =
        HTTP_500 | HTTP_502 | HTTP_503 | HTTP_504 | HTTP_403 | HTTP_404 | HTTP_429;
    /// nginx's default: `error timeout`.
    pub const DEFAULT: u32 = ERROR | TIMEOUT;
}

#[derive(Debug, Clone)]
pub struct LocCfg {
    /// `access_log` inside this location; `None` inherits the server's.
    pub access_logs: Option<Vec<AccessLog>>,
    pub root: PathBuf,
    pub alias: Option<PathBuf>,
    /// Prefix length that belongs to the alias itself (a nested location
    /// inherits the parent's alias *and* the parent's offset).
    pub alias_prefix_len: usize,
    pub index: Vec<String>,
    pub autoindex: bool,
    /// `autoindex_format html|json|jsonp|xml` (nginx default `html`).
    pub autoindex_format: AutoindexFormat,
    /// `charset utf-8`, which makes autoindex count name lengths in characters
    /// instead of bytes when it truncates a too-long entry.
    pub charset_utf8: bool,
    /// `ssi on`: process Server Side Include directives in the response body.
    pub ssi: bool,
    /// `empty_gif`: a content handler with a fixed 43-byte GIF.
    pub empty_gif: bool,
    /// `stub_status`: the connection counters.
    pub stub_status: bool,
    /// `random_index`: `index` picks a random directory entry instead of
    /// trying the configured names in order.
    pub random_index: bool,
    /// `valid_referers` arguments as written. They are resolved into rules once
    /// the server's `server_name` list is final, because `server_names` refers
    /// to it and nginx allows `server_name` after the location.
    pub valid_referers_args: Option<Vec<String>>,
    /// Resolved `valid_referers`. `None` means the module is not configured and
    /// `$invalid_referer` is always empty.
    pub valid_referers: Option<crate::referer::ValidReferers>,
    /// `limit_rate` as written (a complex value: `$limit_rate` is settable).
    pub limit_rate: Option<String>,
    /// `limit_rate_after`: leading bytes that escape the limit.
    pub limit_rate_after: u64,
    /// `sub_filter` replacements declared **in this scope**. nginx appends the
    /// inherited entries *after* these (`ngx_http_sub_filter_merge_conf`), and
    /// the order matters because each rule sees the previous one's output.
    pub sub_filters: Vec<(String, String)>,
    /// `sub_filter` entries inherited from the enclosing scope.
    pub sub_filter_inherited: Vec<(String, String)>,
    /// `sub_filter_once on` (nginx's default): replace only the first match.
    pub sub_filter_once: bool,
    /// `sub_filter_types`: MIME types eligible for substitution.
    pub sub_filter_types: Vec<String>,
    /// `sub_filter_buffering off`: emit output as it is produced, holding back
    /// only the tail that could still become a match. With `on` (the default)
    /// the whole body is collected first.
    pub sub_filter_buffering: bool,
    /// `sub_filter_last_modified` (nginx default: off, which drops the header
    /// because the body no longer matches the file).
    pub sub_filter_last_modified: bool,
    pub gzip: bool,
    pub client_max_body_size: u64,
    /// `client_body_in_file_only on|clean|off`: write the request body to a
    /// temp file and expose the path as `$request_body_file`. `clean` also
    /// unlinks it once the request finishes.
    pub client_body_in_file_only: Option<ClientBodyFileOnly>,
    /// `client_body_buffer_size`: bodies up to this size stay in memory unless
    /// `client_body_in_file_only` forces a file.
    pub client_body_buffer_size: u64,
    pub headers: Vec<(String, String)>,
    pub error_pages: BTreeMap<u16, String>,
    pub ret: Option<(u16, String)>,
    pub try_files: Vec<String>,
    pub internal: bool,
    pub expires: Option<String>,
    // ---- keepalive ----
    /// `keepalive_requests N` at this level (None = inherit).
    pub keepalive_requests: Option<u64>,
    /// `keepalive_timeout T [header_time]`; `0` disables keepalive.
    pub keepalive_timeout: Option<(Duration, Option<u32>)>,
    /// `keepalive_time T` — maximum lifetime of a keepalive connection.
    pub keepalive_time: Option<Duration>,
    pub keepalive_disable: KeepaliveDisable,
    /// `absolute_redirect on|off` (nginx default: on).
    pub absolute_redirect: bool,
    /// `server_name_in_redirect on|off` (default: off).
    pub server_name_in_redirect: bool,
    /// `port_in_redirect on|off` (default: on).
    pub port_in_redirect: bool,
    /// The server's primary name, used by `server_name_in_redirect`.
    pub server_name: String,
    /// `allow` / `deny` rules, evaluated in order (first match wins).
    pub access: Vec<AccessRule>,
    /// `limit_except METHOD... { allow/deny ... }` blocks.
    pub limit_except: Vec<LimitExcept>,
    /// `auth_basic` realm plus `auth_basic_user_file`.
    pub auth_basic: crate::auth::BasicAuth,
    /// `auth_request URI` / `off`; `None` when not configured.
    pub auth_request: Option<String>,
    /// `auth_request_set $var <complex value>`, applied after a successful
    /// auth subrequest. Ordered, because later assignments may read earlier.
    pub auth_request_set: Vec<(String, String)>,
    /// `satisfy all|any`: how `auth_basic` and `auth_request` combine.
    pub satisfy_any: bool,
    /// `proxy_bind ADDR[:PORT]` / `off`; empty means "not configured".
    pub proxy_bind: Option<String>,
    /// `set_real_ip_from` networks (address, prefix bits). A scope-local list
    /// replaces the inherited one.
    pub realip_from: Vec<(std::net::IpAddr, u8)>,
    pub realip_from_set: bool,
    /// `set_real_ip_from unix:`: a peer on a unix socket is trusted. nginx
    /// keeps this apart from the address list because a unix peer has no
    /// address to match against (`$remote_addr` reads `unix:`).
    pub realip_from_unix: bool,
    /// `real_ip_header` (nginx default `X-Real-IP`).
    pub real_ip_header: String,
    /// `real_ip_recursive` (default off).
    pub real_ip_recursive: bool,
    pub limit_reqs: Vec<LimitReq>,
    pub limit_conns: Vec<LimitConn>,
    /// `error_log` directives that apply to this location, in order.
    pub error_logs: Vec<LogSpec>,
    /// `slice <size>`: fetch the entity in fixed-size slices, each its own
    /// upstream request carrying `Range: $slice_range`
    /// (`ngx_http_slice_filter_module`).
    pub slice: Option<u64>,
    /// `server_tokens on|off|build` at location scope. `None` inherits, which is
    /// what nginx's `clcf` merge does -- a location-level `off` affects only that
    /// location (`h2_server_tokens.t` sets it inside `/off`).
    pub server_tokens: Option<bool>,
    /// `gzip_static on|off|always`: serve a sibling `.gz` when the client
    /// accepts gzip (`ngx_http_gzip_static_module`).
    pub gzip_static: bool,
    /// `charset <name|off|$var>`: the charset to declare and convert to.
    pub charset: CharsetSpec,
    /// `source_charset <name|$var>`: what the response is assumed to be in.
    pub source_charset: CharsetSpec,
    /// `charset_types`: content types the filter applies to. `None` means the
    /// nginx default list.
    pub charset_types: Option<Vec<String>>,
    /// `override_charset on`: replace a charset the response already declares.
    pub override_charset: bool,
    /// `open_log_file_cache`, which governs the `access_log` files declared at
    /// this level.
    pub open_log_file_cache: OpenFileCache,
    /// `log_not_found on|off`: whether a missing file is written to the error
    /// log as `open() ... failed (2: No such file or directory)` (nginx default
    /// on).
    pub log_not_found: bool,
    /// `limit_req_log_level`: severity of the "limiting requests" message.
    pub limit_req_log_level: crate::log::Level,
    /// `limit_conn_log_level`: severity of "limiting connections".
    pub limit_conn_log_level: crate::log::Level,
    /// `limit_req_dry_run`: count and log the excess, but never delay or
    /// reject. `$limit_req_status` then reports `*_DRY_RUN`.
    pub limit_req_dry_run: bool,
    /// `limit_conn_dry_run`, same idea for `limit_conn`.
    pub limit_conn_dry_run: bool,
    /// Status returned when a limit is exceeded (`limit_req_status`).
    pub limit_req_status: u16,
    pub limit_conn_status: u16,
    /// Length of the location prefix, used to strip it for `alias`.
    pub prefix_len: usize,
    // ---- gzip ----
    pub gzip_min_length: u64,
    pub gzip_comp_level: u32,
    pub gzip_types: Vec<String>,
    pub gzip_vary: bool,
    // ---- reverse proxy ----
    /// `rewrite <regex> <replacement> [flag]` entries, in config order.
    pub rewrites: Vec<Rewrite>,
    /// `if (<cond>) { ... }` blocks, evaluated in config order with rewrites.
    pub ifs: Vec<IfBlock>,
    /// `set $var value;`
    pub sets: Vec<(String, String)>,
    /// `set`/`if` in source order; indices into `sets` / `ifs`.
    pub steps: Vec<Step>,
    pub proxy_pass: Option<ProxyPass>,
    /// `grpc_pass <target>`: kept raw; nginx strips the scheme and looks the
    /// remainder up in the upstream table, then resolves at request time.
    pub grpc_pass: Option<String>,
    /// Set while parsing `proxy_pass http://<name>` so the http level can
    /// resolve the name to an `upstream` index after all blocks are read.
    pub proxy_upstream_name: Option<String>,
    pub proxy_set_headers: Vec<(String, String)>,
    pub proxy_http_version: u8,
    pub proxy_connect_timeout: Duration,
    pub proxy_read_timeout: Duration,
    pub proxy_send_timeout: Duration,
    /// `proxy_next_upstream` flags (`next_upstream::*`); nginx default is
    /// `error timeout`.
    pub proxy_next_upstream: u32,
    /// `proxy_next_upstream_tries N`; 0 = unlimited.
    pub proxy_next_upstream_tries: u32,
    /// `proxy_next_upstream_timeout T`; zero = unlimited.
    pub proxy_next_upstream_timeout: Duration,
    /// `grpc_next_upstream` flags. nginx keeps these in the grpc module's own
    /// location conf, so a `proxy_next_upstream` in the same location does not
    /// apply to `grpc_pass` and vice versa.
    pub grpc_next_upstream: u32,
    /// `grpc_next_upstream_tries N`; 0 = unlimited.
    pub grpc_next_upstream_tries: u32,
    /// `grpc_next_upstream_timeout T`; zero = unlimited.
    pub grpc_next_upstream_timeout: Duration,
    pub proxy_buffering: bool,
    pub proxy_hide_headers: Vec<String>,
    // ---- fastcgi ----
    pub fastcgi_pass: Option<FastcgiPass>,
    pub fastcgi_params: Vec<FastcgiParam>,
    /// `fastcgi_cache <zone>` and its companions. nginx keeps these on their own
    /// location conf (`ngx_http_fastcgi_loc_conf_t.cache`), independent of
    /// `proxy_cache`, so a location can cache one upstream module and not another.
    /// `proxy_request_buffering` / `fastcgi_request_buffering` (nginx default
    /// on). Off means the body is streamed to the upstream as it arrives from
    /// the client, so the upstream connection is made before the body is read.
    pub proxy_request_buffering: bool,
    pub fastcgi_request_buffering: bool,
    pub fastcgi_cache: Option<String>,
    pub fastcgi_cache_key: Option<String>,
    pub fastcgi_cache_valid: Vec<(Vec<u16>, Duration)>,
    pub fastcgi_index: Option<String>,
    pub fastcgi_split_path_info: Option<regex::Regex>,
    /// `dav_methods`: bitmask of the WebDAV methods this location serves
    /// (`crate::dav::flags`). Zero -- the default, and what `off` means -- makes
    /// the DAV module decline entirely.
    pub dav_methods: u32,
    /// `dav_access`: mode for entries the DAV module creates (default 0600).
    pub dav_access: u32,
    /// `create_full_put_path on`: create the missing parent directories of a
    /// PUT target.
    pub dav_create_full_put_path: bool,
    /// `min_delete_depth`: how many path segments a DELETE URI needs before it
    /// is allowed (nginx default 0 = no check).
    pub dav_min_delete_depth: u32,
    /// `disable_symlinks on|if_not_owner [from=part]`.
    pub disable_symlinks: Symlinks,
    /// The `from=` part of `disable_symlinks`, kept as written so
    /// `$document_root` still expands per request.
    pub disable_symlinks_from: Option<String>,
    /// `resolver <addr>`: consulted for hosts that only appear at request time.
    /// nginx allows this in http, server and location, with the innermost
    /// winning; each directive instance has its own cache.
    pub resolver: Option<crate::resolver::Resolver>,
    /// `resolver_timeout`: how long one name may take. Kept beside `resolver`
    /// because the two directives may appear in either order.
    pub resolver_timeout: Option<Duration>,
    /// `secure_link` (new style): a complex value holding `hash[,expires]`.
    ///
    /// The three `secure_link*` fields follow `ngx_http_secure_link_merge_conf`:
    /// a scope that sets `secure_link_secret` forces the other two to nothing
    /// (nginx rejects a config that sets both in one scope), and a scope that
    /// sets either new-style directive stops inheriting the secret. The `*_set`
    /// flags are how "set in this scope" is tracked; they are cleared for every
    /// location block and consumed by `merge_secure_link`.
    pub secure_link_set: bool,
    pub secure_link_md5_set: bool,
    pub secure_link_secret_set: bool,
    pub secure_link: Option<String>,
    /// `secure_link_md5`: the text whose MD5 the hash must equal.
    pub secure_link_md5: Option<String>,
    /// `secure_link_secret` (old style): the shared secret in the path.
    pub secure_link_secret: Option<String>,
    /// `fastcgi_catch_stderr`: a STDERR substring that turns the reply into 502.
    pub fastcgi_catch_stderr: Vec<String>,
    pub fastcgi_connect_timeout: Duration,
    pub fastcgi_read_timeout: Duration,
    // ---- uwsgi / scgi ----
    pub uwsgi_pass: Option<UwsgiPass>,
    /// `proxy_ssl_certificate` / `uwsgi_ssl_certificate`: client certificate
    /// presented to the upstream.
    pub proxy_ssl_certificate: Option<PathBuf>,
    pub proxy_ssl_certificate_key: Option<PathBuf>,
    pub uwsgi_ssl_certificate: Option<PathBuf>,
    pub uwsgi_ssl_certificate_key: Option<PathBuf>,
    /// `*_ssl_password_file`: passwords tried in order for an encrypted
    /// upstream client key.
    pub proxy_ssl_password_file: Option<PathBuf>,
    pub uwsgi_ssl_password_file: Option<PathBuf>,
    pub uwsgi_params: Vec<FastcgiParam>,
    pub scgi_pass: Option<ScgiPass>,
    pub scgi_params: Vec<FastcgiParam>,
    // ---- proxy_cache ----
    pub proxy_cache: Option<String>,
    pub proxy_cache_valid: Vec<(Vec<u16>, Duration)>,
    /// `proxy_cache_lock on|off`, `proxy_cache_lock_timeout`, `_age`.
    /// `proxy_ssl_session_reuse` (nginx default on).
    pub proxy_ssl_session_reuse: bool,
    /// `proxy_ssl_name`: the SNI name sent to an `https://` upstream. `None`
    /// means "use the proxy_pass authority".
    pub proxy_ssl_name: Option<String>,
    /// `proxy_redirect` rules as written; resolved in `parse_location` once the
    /// location prefix is known (`default` needs it).
    pub proxy_redirect_src: Option<Vec<Vec<String>>>,
    /// Resolved rules. Empty means "do not touch Location/Refresh".
    pub proxy_redirects: Vec<RedirectRule>,
    /// `proxy_cookie_domain` entries. `Some(vec![])` means `off`.
    pub proxy_cookie_domains: Option<Vec<crate::cookie::CookieRewrite>>,
    pub proxy_cookie_paths: Option<Vec<crate::cookie::CookieRewrite>>,
    /// Set once this location declares its own cookie rewrites (nginx replaces,
    /// not extends, the inherited list).
    pub cookie_domains_set: bool,
    pub cookie_paths_set: bool,
    /// `proxy_cookie_flags` entries. `Some(vec![])` means `off`.
    pub proxy_cookie_flags: Option<Vec<crate::cookie::CookieFlags>>,
    pub cookie_flags_set: bool,
    pub proxy_cache_ignore: crate::cache::Ignore,
    /// `proxy_cache_convert_head`, on by default like nginx.
    pub proxy_cache_convert_head: bool,
    /// `proxy_cache_use_stale` events. Only `updating` changes what a client
    /// sees today (it turns a concurrent background refresh into `UPDATING`).
    pub proxy_cache_use_stale_updating: bool,
    /// `proxy_cache_use_stale ... http_404 http_500`: upstream statuses for
    /// which an expired entry may be served instead of the upstream reply.
    pub proxy_cache_use_stale_codes: Vec<u16>,
    /// `proxy_cache_revalidate`: send conditional headers upstream for an
    /// expired entry and reuse the cached body on `304`.
    pub proxy_cache_revalidate: bool,
    /// `proxy_cache_background_update`: serve a stale entry while refreshing.
    pub proxy_cache_background_update: bool,
    /// `proxy_cache_max_range_offset`: a `Range` request whose start offset is
    /// at or beyond this bypasses the cache. `None` = unlimited (never bypass),
    /// which is nginx's default.
    pub proxy_cache_max_range_offset: Option<u64>,
    /// `proxy_limit_rate`: pace the upstream→client transfer, bytes/second
    /// (0 = unlimited). nginx stores this on the upstream conf.
    pub proxy_limit_rate: u64,
    /// `proxy_intercept_errors`: let `error_page` handle proxy error statuses.
    pub proxy_intercept_errors: bool,
    /// `add_trailer` entries, same shape as `headers`.
    pub trailers: Vec<(String, String)>,
    /// `max_ranges N`: at most N ranges are honoured; `0` disables ranges.
    /// `None` means the directive was not set (unlimited).
    pub max_ranges: Option<u32>,
    /// `proxy_force_ranges`: honour `Range` even if the upstream never
    /// advertised `Accept-Ranges`.
    pub proxy_force_ranges: bool,
    /// `proxy_cache_min_uses`: requests needed before a response is cached.
    pub proxy_cache_min_uses: u32,
    pub proxy_cache_lock: bool,
    pub proxy_cache_lock_timeout: Duration,
    pub proxy_cache_lock_age: Duration,
    pub proxy_cache_key: Option<String>,
    pub proxy_no_cache: Vec<String>,
    pub proxy_cache_bypass: Vec<String>,
}

impl LocCfg {
    fn new(root: PathBuf) -> Self {
        LocCfg {
            access_logs: None,
            charset_utf8: false,
            error_logs: Vec::new(),
            slice: None,
            server_tokens: None,
            gzip_static: false,
            charset: CharsetSpec::default(),
            source_charset: CharsetSpec::default(),
            charset_types: None,
            override_charset: false,
            open_log_file_cache: OpenFileCache::default(),
            log_not_found: true,
            limit_req_log_level: crate::log::Level::Error,
            limit_conn_log_level: crate::log::Level::Error,
            limit_req_dry_run: false,
            limit_conn_dry_run: false,
            root,
            steps: Vec::new(),
            alias: None,
            alias_prefix_len: 0,
            index: vec!["index.html".to_string()],
            autoindex: false,
            autoindex_format: AutoindexFormat::Html,
            ssi: false,
            empty_gif: false,
            stub_status: false,
            random_index: false,
            valid_referers_args: None,
            valid_referers: None,
            limit_rate: None,
            limit_rate_after: 0,
            sub_filters: Vec::new(),
            sub_filter_inherited: Vec::new(),
            sub_filter_once: true,
            sub_filter_types: vec!["text/html".to_string()],
            sub_filter_buffering: true,
            sub_filter_last_modified: false,
            gzip: false,
            client_max_body_size: DEFAULT_CLIENT_MAX_BODY,
            client_body_in_file_only: None,
            client_body_buffer_size: 8 * 1024,
            headers: Vec::new(),
            error_pages: BTreeMap::new(),
            ret: None,
            try_files: Vec::new(),
            internal: false,
            expires: None,
            keepalive_requests: None,
            keepalive_timeout: None,
            keepalive_time: None,
            keepalive_disable: KeepaliveDisable::Msie6,
            absolute_redirect: true,
            server_name_in_redirect: false,
            port_in_redirect: true,
            server_name: String::new(),
            access: Vec::new(),
            limit_except: Vec::new(),
            auth_basic: crate::auth::BasicAuth::default(),
            auth_request: None,
            auth_request_set: Vec::new(),
            satisfy_any: false,
            proxy_bind: None,
            realip_from: Vec::new(),
            realip_from_set: false,
            realip_from_unix: false,
            real_ip_header: "X-Real-IP".to_string(),
            real_ip_recursive: false,
            limit_reqs: Vec::new(),
            limit_conns: Vec::new(),
            limit_req_status: 503,
            limit_conn_status: 503,
            prefix_len: 0,
            gzip_min_length: 20,
            gzip_comp_level: 1,
            gzip_types: Vec::new(),
            gzip_vary: false,
            rewrites: Vec::new(),
            ifs: Vec::new(),
            sets: Vec::new(),
            proxy_pass: None,
            grpc_pass: None,
            proxy_upstream_name: None,
            proxy_set_headers: Vec::new(),
            proxy_http_version: 1,
            proxy_connect_timeout: Duration::from_secs(60),
            proxy_read_timeout: Duration::from_secs(60),
            proxy_send_timeout: Duration::from_secs(60),
            proxy_next_upstream: next_upstream::DEFAULT,
            proxy_next_upstream_tries: 0,
            proxy_next_upstream_timeout: Duration::ZERO,
            grpc_next_upstream: next_upstream::DEFAULT,
            grpc_next_upstream_tries: 0,
            grpc_next_upstream_timeout: Duration::ZERO,
            proxy_buffering: true,
            proxy_hide_headers: Vec::new(),
            fastcgi_pass: None,
            fastcgi_params: Vec::new(),
            proxy_request_buffering: true,
            fastcgi_request_buffering: true,
            fastcgi_cache: None,
            fastcgi_cache_key: None,
            fastcgi_cache_valid: Vec::new(),
            fastcgi_index: None,
            fastcgi_split_path_info: None,
            dav_methods: 0,
            dav_access: 0o600,
            dav_create_full_put_path: false,
            dav_min_delete_depth: 0,
            disable_symlinks: Symlinks::Off,
            disable_symlinks_from: None,
            resolver: None,
            resolver_timeout: None,
            secure_link_set: false,
            secure_link_md5_set: false,
            secure_link_secret_set: false,
            secure_link: None,
            secure_link_md5: None,
            secure_link_secret: None,
            fastcgi_catch_stderr: Vec::new(),
            fastcgi_connect_timeout: Duration::from_secs(60),
            fastcgi_read_timeout: Duration::from_secs(60),
            uwsgi_pass: None,
            proxy_ssl_certificate: None,
            proxy_ssl_certificate_key: None,
            uwsgi_ssl_certificate: None,
            uwsgi_ssl_certificate_key: None,
            proxy_ssl_password_file: None,
            uwsgi_ssl_password_file: None,
            uwsgi_params: Vec::new(),
            scgi_pass: None,
            scgi_params: Vec::new(),
            proxy_cache: None,
            proxy_cache_valid: Vec::new(),
            proxy_ssl_session_reuse: true,
            proxy_ssl_name: None,
            proxy_redirect_src: None,
            proxy_redirects: Vec::new(),
            proxy_cookie_domains: None,
            proxy_cookie_paths: None,
            cookie_domains_set: false,
            cookie_paths_set: false,
            proxy_cookie_flags: None,
            cookie_flags_set: false,
            proxy_cache_ignore: crate::cache::Ignore::default(),
            proxy_cache_convert_head: true,
            proxy_cache_use_stale_updating: false,
            proxy_cache_use_stale_codes: Vec::new(),
            proxy_cache_revalidate: false,
            proxy_cache_background_update: false,
            trailers: Vec::new(),
            max_ranges: None,
            proxy_cache_max_range_offset: None,
            proxy_limit_rate: 0,
            proxy_intercept_errors: false,
            proxy_force_ranges: false,
            proxy_cache_min_uses: 1,
            proxy_cache_lock: false,
            proxy_cache_lock_timeout: Duration::from_secs(5),
            proxy_cache_lock_age: Duration::from_secs(5),
            proxy_cache_key: None,
            proxy_no_cache: Vec::new(),
            proxy_cache_bypass: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IfBlock {
    pub cond: IfCond,
    /// Rewrites, `return`, and nested `set` inside the block.
    pub rewrites: Vec<Rewrite>,
    pub ret: Option<(u16, String)>,
    pub sets: Vec<(String, String)>,
    /// `proxy_pass` inside `if` — nginx allows it and it replaces the
    /// location's target while the condition holds.
    pub proxy_pass: Option<ProxyPass>,
    /// Upstream name, as `LocCfg::proxy_upstream_name` records it.
    pub proxy_upstream_name: Option<String>,
}

/// One entry of the rewrite-phase script, in source order.
///
/// nginx evaluates `set` and `if` **interleaved** as written; keeping them in
/// separate lists (all sets, then all ifs) gives the wrong answer whenever a
/// config re-assigns a variable between two `if`s — which is the standard
/// idiom for `auth_http` handlers.
#[derive(Debug, Clone, Copy)]
pub enum Step {
    Set(usize),
    If(usize),
}

#[derive(Debug, Clone)]
pub enum IfCond {
    /// `if ($var)`
    Truthy(String),
    /// `if ($var = value)` / `!=`
    Equals(String, String, bool),
    /// `if ($var ~ regex)` / `~*` / `!~` / `!~*`
    Match(String, regex::Regex, bool),
    /// `if (-f $request_filename)` etc. The `bool` is the `!` prefix, which
    /// nginx spells as part of the operator (`!-f`), not as a separate token.
    FileTest(char, String, bool),
}

#[derive(Debug, Clone)]
pub struct LimitExcept {
    pub methods: Vec<String>,
    pub rules: Vec<AccessRule>,
    /// `limit_except GET { proxy_pass ...; }` replaces the location's target
    /// for every method *not* listed.
    pub proxy_pass: Option<ProxyPass>,
    pub proxy_upstream_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccessRule {
    pub deny: bool,
    /// `None` means `all`.
    pub net: Option<Cidr>,
    /// `allow unix:` / `deny unix:` matches only clients on a unix socket.
    pub unix: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    pub addr: std::net::IpAddr,
    pub bits: u8,
}

impl Cidr {
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        match (self.addr, ip) {
            (std::net::IpAddr::V4(net), std::net::IpAddr::V4(ip)) => {
                let bits = self.bits.min(32);
                if bits == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - bits as u32);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (std::net::IpAddr::V6(net), std::net::IpAddr::V6(ip)) => {
                let bits = self.bits.min(128);
                if bits == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - bits as u32);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

pub fn parse_cidr(s: &str) -> Option<Option<Cidr>> {
    if s == "all" {
        return Some(None);
    }
    let (addr, bits) = match s.rsplit_once('/') {
        Some((a, b)) => (a, b.parse::<u8>().ok()?),
        None => (s, u8::MAX),
    };
    let ip: std::net::IpAddr = addr.parse().ok()?;
    let bits = match ip {
        std::net::IpAddr::V4(_) if bits == u8::MAX => 32,
        std::net::IpAddr::V6(_) if bits == u8::MAX => 128,
        _ => bits,
    };
    Some(Some(Cidr { addr: ip, bits }))
}

/// `rate=2r/s`, `rate=1r/m`, `rate=10r/s`.
fn parse_rate_spec(spec: &str) -> Option<f64> {
    let rest = spec
        .strip_suffix("r/s")
        .or_else(|| spec.strip_suffix("r/m"))?;
    let per_minute = spec.ends_with("r/m");
    let n: f64 = rest.parse().ok()?;
    Some(if per_minute { n / 60.0 } else { n })
}

/// `ngx_http_access_module`: first matching rule wins, default is allow.
pub fn access_denied(rules: &[AccessRule], ip: std::net::IpAddr) -> bool {
    access_denied_for(rules, ip, false)
}

/// `is_unix` is true for a connection accepted on `listen unix:`; nginx allows
/// `allow unix:` / `deny unix:` to target exactly those.
pub fn access_denied_for(rules: &[AccessRule], ip: std::net::IpAddr, is_unix: bool) -> bool {
    for r in rules {
        let matches = if r.unix {
            is_unix
        } else {
            match &r.net {
                None => true,
                Some(c) => c.contains(ip),
            }
        };
        if matches {
            return r.deny;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveDisable {
    /// nginx's default: keepalive is off for MSIE 6 and older.
    Msie6,
    Safari,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteFlag {
    None,
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug, Clone)]
pub struct Rewrite {
    pub re: regex::Regex,
    pub replacement: String,
    pub flag: RewriteFlag,
}

/// Parse `if (<expr>)`. nginx strips the parentheses, so the tokens arrive as
/// e.g. `["($http_user_agent", "~", "curl)"]`.
fn parse_if_cond(args: &[String]) -> Option<IfCond> {
    if args.is_empty() {
        return None;
    }
    let mut toks: Vec<String> = args.to_vec();
    if let Some(first) = toks.first_mut() {
        *first = first.trim_start_matches('(').to_string();
    }
    if let Some(last) = toks.last_mut() {
        *last = last.trim_end_matches(')').to_string();
    }
    toks.retain(|t| !t.is_empty());
    if toks.is_empty() {
        return None;
    }
    if toks.len() == 1 {
        return Some(IfCond::Truthy(toks[0].clone()));
    }
    // File tests have no left operand: the grammar is `-f <path>` / `!-e <path>`.
    // Reading them as `<var> <op> <rhs>` consumed the operator as the variable
    // and the path as the operator, which is why every `-f` config failed to
    // start before this.
    if let Some(op) = toks.first().filter(|t| {
        matches!(
            t.as_str(),
            "-f" | "-d" | "-e" | "-x" | "!-f" | "!-d" | "!-e" | "!-x"
        )
    }) {
        let negated = op.starts_with('!');
        let kind = op.chars().nth(if negated { 2 } else { 1 })?;
        return Some(IfCond::FileTest(kind, toks[1..].join(" "), negated));
    }
    let var = toks[0].clone();
    let op = toks[1].clone();
    let rhs = toks.get(2).cloned().unwrap_or_default();
    match op.as_str() {
        "=" => Some(IfCond::Equals(var, rhs, true)),
        "!=" => Some(IfCond::Equals(var, rhs, false)),
        "~" | "~*" | "!~" | "!~*" => {
            let ci = op.ends_with('*');
            let negate = op.starts_with('!');
            let pattern = if ci { format!("(?i:{rhs})") } else { rhs };
            let re = regex::Regex::new(&pattern).ok()?;
            Some(IfCond::Match(var, re, negate))
        }
        "-f" | "-d" | "-e" | "-x" => Some(IfCond::FileTest(op.chars().nth(1)?, rhs, false)),
        "!-f" | "!-d" | "!-e" | "!-x" => {
            Some(IfCond::FileTest(op.chars().nth(2)?, rhs, true))
        }
        _ => None,
    }
}

/// Compile nginx's `$1..$9` replacement syntax into a format we can expand.
pub fn compile_rewrite(re_src: &str, replacement: &str, flag: RewriteFlag) -> Option<Rewrite> {
    let re = regex::Regex::new(re_src).ok()?;
    Some(Rewrite {
        re,
        replacement: replacement.to_string(),
        flag,
    })
}

#[derive(Debug, Clone)]
pub struct FastcgiPass {
    /// The literal address. Only meaningful when `dynamic` is false.
    pub addr: SocketAddr,
    /// The configured value as written. Kept because `fastcgi_pass` accepts a
    /// complex value (`fastcgi_pass $arg_b`) that nginx resolves per request,
    /// against either an `upstream` name or `host:port`.
    pub spec: String,
    pub dynamic: bool,
}

#[derive(Debug, Clone)]
pub struct UwsgiPass {
    pub addr: SocketAddr,
    /// `uwsgi_pass suwsgi://` -- the connection is TLS.
    pub tls: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ScgiPass {
    pub addr: SocketAddr,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct FastcgiParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct CacheZone {
    pub name: String,
    /// Directory that holds the cache files.
    pub path: PathBuf,
    pub max_size: u64,
    pub inactive: Duration,
    pub levels: Option<String>,
    /// `proxy_cache_lock`: only one request may populate a key at a time.
    /// `proxy_cache_lock` ownership per cache key: the instant the current
    /// holder's `lock_age` runs out (`node->lock_time` in nginx). A waiter may
    /// take over once that passes.
    pub lock:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    /// `proxy_cache_min_uses` support: how many times each key has been asked
    /// for (`ngx_http_file_cache_node_t.uses`). The first `min_uses - 1`
    /// requests are served but never stored.
    pub uses: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
}

/// One protocol's authentication bitmask. nginx keeps `pop3_auth`,
/// `imap_auth` and `smtp_auth` in *separate* server configs, so setting one
/// must not affect the others.
#[derive(Clone, Copy)]
pub struct AuthSet {
    pub plain: bool,
    pub apop: bool,
    pub none: bool,
    pub login: bool,
    pub cram_md5: bool,
    pub external: bool,
}

impl Default for AuthSet {
    fn default() -> Self {
        // nginx's default is `*_auth plain`; LOGIN is unconditional on top.
        AuthSet {
            plain: true,
            apop: false,
            none: false,
            login: true,
            cram_md5: false,
            external: false,
        }
    }
}

impl AuthSet {
    fn from_args(args: &[String]) -> Self {
        let mut set = AuthSet {
            plain: false,
            apop: false,
            none: false,
            login: true,
            cram_md5: false,
            external: false,
        };
        for a in args {
            match a.as_str() {
                "plain" => set.plain = true,
                "apop" => set.apop = true,
                "none" => set.none = true,
                "cram-md5" => set.cram_md5 = true,
                "external" => set.external = true,
                _ => {}
            }
        }
        set
    }
}

/// One `error_log <dest> [level]` directive, kept unresolved so that the file
/// is only opened when the server actually starts (`-t` must not create logs).
#[derive(Clone, Debug)]
pub struct LogSpec {
    pub dest: String,
    pub level: crate::log::Level,
}

/// Split `error_log <dest> [level]` into its parts. Unknown levels are ignored
/// by nginx with a warning, and the default level is `error`.
pub fn parse_log_spec(prefix: &Path, args: &[String]) -> Option<LogSpec> {
    let dest = args.first()?;
    let level = args
        .get(1)
        .and_then(|l| crate::log::Level::parse(l))
        .unwrap_or(crate::log::Level::Error);
    let dest = if dest == "stderr" || dest.starts_with("syslog:") {
        dest.clone()
    } else {
        let p = Path::new(dest);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            prefix.join(p)
        };
        full.to_string_lossy().to_string()
    };
    Some(LogSpec { dest, level })
}

/// Turn specs into live sinks.
/// Open every `error_log` a location declares, so the file exists even when
/// nothing is ever written to it.
///
/// nginx opens all configured logs while loading the configuration; a test that
/// reads an empty log then gets `""` rather than a missing file
/// (`index.t`, `log_not_found off`).
/// Create the directory and file for every *static* `access_log` path, the way
/// nginx opens them while loading the configuration.
///
/// A path containing `$` is deliberately skipped: those are opened per request,
/// and nginx would not create their directory either.
/// Turn the parsed `charset_map` blocks into the runtime registry.
///
/// nginx registers both names of every `charset_map`, and that registration is
/// what makes `charset A; source_charset B;` resolvable at all -- the names are
/// not built in.
pub fn build_charsets(http: &mut Http) {
    let defs: Vec<_> = http.charset_maps.clone();
    let mut set = crate::charset::Charsets::default();
    for ((src_name, dst_name), pairs) in defs {
        let src = set.get_or_add(&src_name);
        let dst = set.get_or_add(&dst_name);
        let src_utf8 = set.names[src].utf8;
        let dst_utf8 = set.names[dst].utf8;
        let mut map = crate::charset::build_map(src, dst, src_utf8, dst_utf8);
        let mut len = 0usize;
        for (from, to) in pairs {
            crate::charset::add_pair(&mut map, dst_utf8, from, &to, &mut len);
        }
        if dst_utf8 && len > 0 {
            // nginx averages the encoded width over the declared characters.
            let n = set.names[dst].length.max(1);
            set.names[dst].length = (n + len / 2).max(1);
        }
        set.maps.push(map);
    }
    http.charsets = set;
}

pub fn preopen_access_logs(http: &Http) {
    fn one(log: &AccessLog) {
        if log.path_template.is_some() {
            return;
        }
        if let Some(parent) = log.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log.path);
    }
    fn walk(locs: &[Location]) {
        for l in locs {
            if let Some(logs) = &l.cfg.access_logs {
                logs.iter().for_each(one);
            }
            walk(&l.nested);
        }
    }
    http.default_access_logs.iter().for_each(one);
    for srv in &http.servers {
        srv.access_logs.iter().for_each(one);
        walk(&srv.locations);
    }
}

pub fn preopen_location_error_logs(http: &Http) {
    fn walk(locs: &[Location]) {
        for l in locs {
            open_sinks(&l.cfg.error_logs);
            walk(&l.nested);
        }
    }
    for srv in &http.servers {
        open_sinks(&srv.default_loc.error_logs);
        walk(&srv.locations);
    }
    open_sinks(&http.default_loc.error_logs);
}

pub fn open_sinks(specs: &[LogSpec]) -> Vec<std::sync::Arc<crate::log::Sink>> {
    let mut out = Vec::new();
    for spec in specs {
        if spec.dest == "stderr" {
            out.push(crate::log::Sink::stderr(spec.level));
        } else if let Some(rest) = spec.dest.strip_prefix("syslog:") {
            if let Some(sink) = open_syslog(rest, spec.level) {
                out.push(sink);
            }
        } else if let Ok(s) = crate::log::Sink::file(Path::new(&spec.dest), spec.level) {
            out.push(s);
        }
    }
    out
}

/// `server=host:port[,facility=local7][,tag=nginx]`
pub fn open_syslog_pub(
    rest: &str,
    level: crate::log::Level,
) -> Option<std::sync::Arc<crate::log::Sink>> {
    open_syslog(rest, level)
}

fn open_syslog(rest: &str, level: crate::log::Level) -> Option<std::sync::Arc<crate::log::Sink>> {
    let mut server = None;
    let mut facility = 23u8; // local7, nginx's default
    let mut tag = "nginx".to_string();
    for part in rest.split(',') {
        let (k, v) = part.split_once('=')?;
        match k {
            "server" => server = Some(v.to_string()),
            "facility" => {
                facility = match v {
                    "kern" => 0,
                    "user" => 1,
                    "mail" => 2,
                    "daemon" => 3,
                    "auth" => 4,
                    "syslog" => 5,
                    "lpr" => 6,
                    "news" => 7,
                    "uucp" => 8,
                    "cron" => 9,
                    "authpriv" => 10,
                    "ftp" => 11,
                    "local0" => 16,
                    "local1" => 17,
                    "local2" => 18,
                    "local3" => 19,
                    "local4" => 20,
                    "local5" => 21,
                    "local6" => 22,
                    "local7" => 23,
                    _ => 23,
                }
            }
            "tag" => tag = v.to_string(),
            _ => {}
        }
    }
    let addr = server.and_then(|s| {
        s.parse::<std::net::SocketAddr>().ok().or_else(|| {
            s.rsplit_once(':').and_then(|(h, p)| {
                p.parse::<u16>().ok().and_then(|port| {
                    h.parse::<std::net::IpAddr>()
                        .ok()
                        .map(|ip| std::net::SocketAddr::new(ip, port))
                })
            })
        })
    })?;
    crate::log::Sink::syslog(addr, facility, tag, level).ok()
}

/// One `mail { server { ... } }` listener.
#[derive(Debug, Clone)]
pub struct MailServer {
    pub listen: SocketAddr,
    /// `server_name` in a mail block; nginx defaults it to the hostname and
    /// uses it for the banner and the EHLO we send upstream.
    pub name: String,
    pub protocol: crate::mail::Protocol,
    pub auth_http: Option<crate::mail::AuthHttp>,
    pub auth_http_timeout: std::time::Duration,
    /// `proxy_pass_error_message`: show the authenticator's text verbatim.
    pub pass_error_message: bool,
    pub proxy_timeout: std::time::Duration,
    /// Mechanisms enabled by `pop3_auth` / `imap_auth` / `smtp_auth`.
    pub auth_plain: bool,
    /// APOP (POP3 only). nginx has a flag for this; LOGIN never does.
    pub auth_apop: bool,
    /// `smtp_auth none`: no authentication, proxy the session straight away.
    pub auth_none: bool,
    pub auth_login: bool,
    pub auth_cram_md5: bool,
    pub auth_external: bool,
    /// `smtp_greeting_delay`: hold the `220` back so a client that speaks
    /// first can be rejected (anti-probe measure).
    pub greeting_delay: std::time::Duration,
    /// `starttls off|on|only`.
    pub starttls: StarttlsCfg,
    /// `{imap,pop3,smtp}_capabilities`: replaces the protocol's default list.
    pub capabilities: Option<Vec<String>>,
    /// Certificates for this listener, used by `STLS` / `STARTTLS` and by
    /// implicit TLS.
    pub tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    /// `ssl_password_file` effective for this listener.
    pub ssl_password_file: Option<PathBuf>,
    /// `listen ... ssl`: the connection is TLS from the first byte.
    pub ssl: bool,
    /// `error_log` directives of this mail server. nginx *adds* these to the
    /// main-context ones rather than replacing them.
    pub error_logs: Vec<LogSpec>,
    /// Live sinks built from `error_logs` at startup.
    pub sinks: Vec<std::sync::Arc<crate::log::Sink>>,
}

/// `starttls` in a mail server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StarttlsCfg {
    Off,
    /// Advertise TLS but still allow plaintext authentication.
    On,
    /// Advertise TLS and refuse every authentication command until it is used.
    Only,
}

impl StarttlsCfg {
    fn parse(v: &str) -> Option<Self> {
        match v {
            "off" => Some(StarttlsCfg::Off),
            "on" => Some(StarttlsCfg::On),
            "only" => Some(StarttlsCfg::Only),
            _ => None,
        }
    }
}

impl Default for MailServer {
    fn default() -> Self {
        MailServer {
            listen: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 110)),
            name: hostname(),
            protocol: crate::mail::Protocol::Pop3,
            auth_http: None,
            auth_http_timeout: std::time::Duration::from_secs(60),
            pass_error_message: false,
            proxy_timeout: std::time::Duration::from_secs(24 * 3600),
            // nginx's default is `*_auth plain`; LOGIN is unconditional on top.
            auth_plain: true,
            auth_apop: false,
            auth_none: false,
            auth_login: true,
            auth_cram_md5: false,
            auth_external: false,
            greeting_delay: std::time::Duration::ZERO,
            starttls: StarttlsCfg::Off,
            capabilities: None,
            tls: None,
            ssl_password_file: None,
            ssl: false,
            error_logs: Vec::new(),
            sinks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProxyTarget {
    /// `proxy_pass http://127.0.0.1:8080` or with an explicit host name.
    Addr(SocketAddr),
    /// Reference to an `upstream {}` block.
    Upstream(usize),
    /// `proxy_pass http://unix:/path:...`: a unix-domain socket.
    Unix(std::sync::Arc<std::path::PathBuf>),
}

#[derive(Debug, Clone)]
pub struct ProxyPass {
    pub target: ProxyTarget,
    /// URI prefix to substitute for the matched location prefix (may be empty).
    pub uri: Option<String>,
    pub host_header: String,
    pub https: bool,
}

#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub addr: SocketAddr,
    pub weight: u32,
    pub backup: bool,
    pub down: bool,
    pub name: String,
    /// `max_fails=N` (nginx default 1; 0 = never mark down).
    pub max_fails: u32,
    /// `fail_timeout=T` (nginx default 10s): how long a peer with
    /// `fails >= max_fails` stays out of rotation.
    pub fail_timeout: Duration,
    /// `max_conns=N`: cap on simultaneous connections to this peer, 0 meaning
    /// unlimited (nginx's default). Reached the cap, the peer is skipped for
    /// this connection and the balancer moves on -- to a backup if there is one,
    /// otherwise the connection is refused.
    pub max_conns: u32,
}

/// One resolved `proxy_redirect` rule.
///
/// `from`/`to` stay as complex values until request time because nginx expands
/// variables in both arguments (`proxy_redirect http://$host/ /$some_var/`).
#[derive(Debug, Clone)]
pub enum RedirectRule {
    /// `proxy_redirect off`: leave `Location`/`Refresh` untouched.
    Off,
    /// Literal prefix: the matched prefix is replaced and the remainder kept.
    Prefix { from: String, to: String },
    /// `~`/`~*`: the **whole** URL after the header prefix is replaced by the
    /// expansion of `to`, with `$1..$n` taken from the match. Verified against
    /// nginx by `proxy_redirect.t`: `regexp w/captures` expects the suffix
    /// `/test.html` to be dropped, not appended.
    Regex { re: regex::Regex, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LbMethod {
    RoundRobin,
    LeastConn,
    IpHash,
    /// `hash <key> [consistent]` — the key is a complex value expanded per
    /// request.
    Hash {
        key: String,
        consistent: bool,
    },
    /// `random [two [least_conn]]`. `two` picks two peers and takes the better
    /// of them; `least_conn` makes that comparison least-connections instead of
    /// the default (fewest requests in flight, then random).
    Random {
        two: bool,
        least_conn: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub method: LbMethod,
    pub keepalive: usize,
    /// `keepalive_requests N`: nginx closes an idle pooled connection after it
    /// has carried N requests (default 1000).
    pub keepalive_requests: u64,
    /// `keepalive_time T`: maximum age of a pooled connection (default 1h).
    pub keepalive_time: Duration,
    /// `keepalive_timeout T`: how long an idle pooled connection is kept
    /// (nginx upstream default 60s).
    pub keepalive_timeout: Duration,
    /// `hash ... consistent` ring, built once at config time:
    /// `(crc32 point hash, server index)`, sorted by hash with duplicates
    /// removed — nginx's `ngx_http_upstream_update_chash`.
    pub chash_points: Vec<(u32, usize)>,
}

/// `log_format` definitions, split by the escape mode they were declared with.
///
/// `log_format json escape=json '...'` binds the escaping to the *format*, not
/// to the `access_log` that uses it (`access_log.t` has three formats over the
/// same text differing only in `escape=`).
#[derive(Debug, Clone, Default)]
pub struct LogFormats {
    pub text: std::collections::HashMap<String, String>,
    pub escape: std::collections::HashMap<String, Escape>,
}

impl LogFormats {
    pub fn get(&self, name: &str) -> Option<&String> {
        self.text.get(name)
    }
    pub fn insert(&mut self, name: String, text: String, escape: Escape) {
        self.text.insert(name.clone(), text);
        self.escape.insert(name, escape);
    }
}

#[derive(Debug, Clone)]
pub struct AccessLog {
    pub path: PathBuf,
    /// The path as written when it contains `$`: `access_log .../varlog_${arg_logname}`
    /// picks a file per request (`access_log.t`, "varlog").
    pub path_template: Option<String>,
    pub format: String,
    /// `if=<value>`: log only when the expanded value is neither empty nor "0".
    pub if_cond: Option<String>,
    /// `escape=default|json|none`; `None` means "take the format's own mode".
    pub escape: Option<Escape>,
    /// Always `None`. The policy in force comes from the *current location's*
    /// core conf at write time (`ngx_http_log_handler` reads
    /// `clcf->open_file_cache`), so directive order inside a block cannot
    /// matter -- and in `access_log.t` the `access_log` line comes before
    /// `open_log_file_cache`.
    pub cache: Option<OpenFileCache>,
}

/// A `charset` / `source_charset` value: `off`, a literal name, or a variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CharsetSpec {
    #[default]
    Off,
    Name(String),
    /// `charset $arg_c`: resolved per request.
    Var(String),
}

/// `open_log_file_cache max=N [inactive=T] [min_uses=N] [valid=T]`.
///
/// nginx caches the *file handle*, so a log file that is renamed keeps receiving
/// lines while its handle is held, and one that falls out of the cache has to be
/// reopened by path (`access_log.t` proves both by renaming a directory).
#[derive(Debug, Clone, Copy)]
pub struct OpenFileCache {
    pub max: usize,
    pub inactive: Duration,
    pub min_uses: u32,
    pub valid: Duration,
    /// `open_file_cache_errors`: remember a failed open so it is not retried.
    pub errors: bool,
}

impl Default for OpenFileCache {
    fn default() -> Self {
        OpenFileCache {
            max: 0,
            inactive: Duration::from_secs(60),
            min_uses: 1,
            valid: Duration::from_secs(60),
            errors: false,
        }
    }
}

/// `access_log ... escape=` modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Escape {
    /// Escape `"`, `\` and control characters as `\xXX` (nginx's default).
    #[default]
    Default,
    Json,
    None,
}

/// `log_format` name -> (text, escape). `combined` is built in.
fn resolve_format(formats: &LogFormats, name: &str) -> (String, Escape) {
    if name == "combined" {
        return ("combined".to_string(), Escape::Default);
    }
    match formats.text.get(name) {
        Some(t) => (
            t.clone(),
            formats.escape.get(name).copied().unwrap_or_default(),
        ),
        None => ("combined".to_string(), Escape::Default),
    }
}

/// Build an `AccessLog` from an `access_log` directive's arguments.
///
/// `buffer=`, `gzip` and `flush=` are accepted and ignored: our writer is
/// unbuffered, which is observably equivalent for the suites (nginx's own
/// buffering only delays the write).
pub fn parse_access_log(args: &[String], prefix: &std::path::Path) -> Option<AccessLog> {
    let raw = args.first()?;
    let mut format = "combined".to_string();
    let mut if_cond = None;
    let mut escape: Option<Escape> = None;
    for (i, a) in args.iter().enumerate().skip(1) {
        if let Some(v) = a.strip_prefix("if=") {
            if_cond = Some(v.to_string());
        } else if let Some(v) = a.strip_prefix("escape=") {
            escape = Some(match v {
                "json" => Escape::Json,
                "none" => Escape::None,
                _ => Escape::Default,
            });
        } else if a.starts_with("buffer=") || a.starts_with("flush=") || a == "gzip" {
            continue;
        } else if i == 1 {
            format = a.clone();
        }
    }
    let (path, path_template) = if raw.contains('$') {
        // Keep the template for per-request expansion; resolve the static prefix
        // so a relative path still lands under the prefix directory.
        let expanded_for_dir = match raw.rfind('/') {
            Some(slash) => format!("{}/", &raw[..slash]),
            None => String::new(),
        };
        let dir = resolve_path(prefix, &expanded_for_dir);
        (
            dir.join(raw.rsplit('/').next().unwrap_or(raw)),
            Some(raw.clone()),
        )
    } else {
        (resolve_path(prefix, raw), None)
    };
    Some(AccessLog {
        path,
        path_template,
        format,
        if_cond,
        escape,
        cache: None,
    })
}

#[derive(Debug, Clone)]
pub struct Server {
    pub idx: usize,
    pub names: Vec<String>,
    pub default_loc: LocCfg,
    pub locations: Vec<Location>,
    pub access_logs: Vec<AccessLog>,
    pub keepalive_timeout: Duration,
    pub server_tokens: bool,
    /// `large_client_header_buffers <num> <size>`: one header field may not
    /// exceed `size`, and the whole header block may not exceed `num * size`.
    /// HTTP/2 derives its limits from the same directive
    /// (`ngx_http_v2.c` uses `cscf->large_client_header_buffers`).
    pub header_field_limit: usize,
    pub header_block_limit: usize,
    pub error_pages: BTreeMap<u16, String>,
    pub access_log_off: bool,
    /// Server-level `if` blocks, evaluated before location matching.
    pub ifs: Vec<IfBlock>,
    pub sets: Vec<(String, String)>,
    /// `set`/`if` in source order; indices into `sets` / `ifs`.
    pub steps: Vec<Step>,
    pub regex_names: Vec<regex::Regex>,
    /// Regex server names paired with their source text (for diagnostics and
    /// for named-capture handling).
    pub regex_names_src: Vec<(regex::Regex, String)>,
    // ---- TLS ----
    pub ssl: bool,
    pub ssl_certificate: Option<PathBuf>,
    pub ssl_certificate_key: Option<PathBuf>,
    /// `ssl_password_file`: passwords tried in order for an encrypted key.
    pub ssl_password_file: Option<PathBuf>,
    pub ssl_certificate_cache: CertCacheCfg,
    /// `ssl_verify_client`: 0 = off, 1 = on, 2 = optional, 3 = optional_no_ca.
    /// Same encoding as nginx's `sscf->verify`.
    pub ssl_verify_client: u8,
    /// `ssl_client_certificate`: the CA bundle client certs are checked against.
    pub ssl_client_certificate: Option<PathBuf>,
    /// `ssl_trusted_certificate` (http/server): trust anchors for client
    /// certificate verification. nginx adds this bundle to the verify store
    /// alongside `ssl_client_certificate`.
    pub ssl_trusted_certificate: Option<PathBuf>,
    pub http2: bool,
}

/// Stand-in `SocketAddr` for a unix listener, which has no address or port.
/// `ListenGroup::unix` is what callers must consult.
pub const UNIX_PLACEHOLDER: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

/// A `listen` target: a TCP/UDP socket or a unix-domain path.
///
/// nginx treats them as separate namespaces; a unix listener has no address or
/// port, which is why `ListenGroup` keeps the path alongside a synthetic
/// `SocketAddr`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ListenAddr {
    Tcp(SocketAddr),
    Unix(std::sync::Arc<std::path::PathBuf>),
}

impl ListenAddr {
    /// `None` for a unix socket: nginx has no port to report.
    pub fn port(&self) -> Option<u16> {
        match self {
            ListenAddr::Tcp(a) => Some(a.port()),
            ListenAddr::Unix(_) => None,
        }
    }

    pub fn syslog_form(&self) -> String {
        match self {
            ListenAddr::Tcp(a) => a.to_string(),
            ListenAddr::Unix(p) => format!("unix:{}", p.display()),
        }
    }
}

#[derive(Debug)]
pub struct ListenGroup {
    pub addr: SocketAddr,
    /// Set for `listen unix:`. `addr` is then a placeholder.
    pub unix: Option<std::sync::Arc<std::path::PathBuf>>,
    pub servers: Vec<usize>,
    pub default_server: usize,
    /// True when any server on this socket enabled TLS.
    pub ssl: bool,
    /// `listen ... quic`: this socket also serves HTTP/3 over UDP.
    pub quic: bool,
    /// `listen ... proxy_protocol`: every connection on this socket starts with
    /// a HAProxy PROXY header that has to be consumed before HTTP parsing.
    pub proxy_protocol: bool,
}

#[derive(Debug)]
pub struct MimeMap {
    map: HashMap<String, String>,
}

impl MimeMap {
    fn new() -> Self {
        let mut map = HashMap::new();
        for (ty, exts) in BUILTIN_TYPES {
            for e in exts.split_whitespace() {
                map.insert(e.to_string(), ty.to_string());
            }
        }
        MimeMap { map }
    }

    pub fn insert(&mut self, ty: &str, ext: &str) {
        self.map.insert(ext.to_ascii_lowercase(), ty.to_string());
    }

    pub fn get(&self, ext: &str) -> Option<&str> {
        self.map.get(ext).map(|s| s.as_str())
    }
}

const BUILTIN_TYPES: &[(&str, &str)] = &[
    ("text/html", "html htm shtml"),
    ("text/css", "css"),
    ("text/xml", "xml"),
    ("text/plain", "txt text conf"),
    ("application/javascript", "js mjs"),
    ("application/json", "json"),
    ("application/pdf", "pdf"),
    ("application/wasm", "wasm"),
    ("application/zip", "zip"),
    ("application/gzip", "gz"),
    ("image/gif", "gif"),
    ("image/jpeg", "jpeg jpg"),
    ("image/png", "png"),
    ("image/svg+xml", "svg svgz"),
    ("image/webp", "webp"),
    ("image/avif", "avif"),
    ("image/x-icon", "ico"),
    ("font/woff", "woff"),
    ("font/woff2", "woff2"),
    ("font/ttf", "ttf"),
    ("font/otf", "otf"),
    ("application/vnd.ms-fontobject", "eot"),
    ("audio/mpeg", "mp3"),
    ("audio/ogg", "ogg"),
    ("video/mp4", "mp4"),
    ("video/webm", "webm"),
    ("application/octet-stream", "bin exe dll"),
];

/// `ssl_certificate_cache` — caches the *parsed* certificate objects so a
/// variable path is not re-read and re-parsed on every handshake.
///
/// nginx: `ssl_certificate_cache off | max=N [inactive=time] [valid=time]`.
/// Default is `off` (no caching): every handshake re-reads the files.
#[derive(Debug, Clone, PartialEq)]
pub struct CertCacheCfg {
    pub max: usize,
    pub inactive: Option<std::time::Duration>,
    pub valid: Option<std::time::Duration>,
}

impl Default for CertCacheCfg {
    fn default() -> Self {
        CertCacheCfg {
            max: 0,
            inactive: None,
            valid: None,
        }
    }
}

impl CertCacheCfg {
    pub fn is_off(&self) -> bool {
        self.max == 0
    }
}

#[derive(Debug)]
pub struct Http {
    /// `charset_map` blocks, in declaration order: `((src, dst), pairs)`.
    pub charset_maps: Vec<((String, String), Vec<(u8, Vec<u8>)>)>,
    /// The resolved charset registry and mapping tables, built from
    /// `charset_maps` once the configuration is complete.
    pub charsets: crate::charset::Charsets,
    pub servers: Vec<Server>,
    pub groups: Vec<ListenGroup>,
    /// `listen ... quic` sockets (UDP), kept apart from the TCP groups.
    pub quic_groups: Vec<ListenGroup>,
    pub mime: MimeMap,
    pub default_type: String,
    pub keepalive_timeout: Duration,
    pub keepalive_requests: u64,
    pub sendfile: bool,
    pub tcp_nopush: bool,
    /// `http2 on|off` at http level: the inherited default for every server
    /// (nginx 1.25.1+; `listen ... http2` is the older spelling).
    pub http2: bool,
    /// `resolver <addr>`: consulted for hosts that only appear at request time.
    pub resolver: Option<crate::resolver::Resolver>,
    /// `resolver_timeout` at http scope: the fallback for locations.
    pub resolver_timeout: Option<Duration>,
    /// `large_client_header_buffers <num> <size>` as (num, size).
    /// nginx defaults to `4 8k`.
    pub large_client_header_buffers: (usize, usize),
    pub tcp_nodelay: bool,
    pub gzip: bool,
    pub server_tokens: bool,
    pub client_max_body_size: u64,
    /// `client_body_temp_path <path> [level1 [level2 [level3]]]`: where
    /// `client_body_in_file_only` writes. Defaults to `<prefix>/client_body_temp`,
    /// which is what nginx reports with an empty prefix-relative name.
    pub client_body_temp_path: PathBuf,
    pub default_loc: LocCfg,
    /// `ssl_certificate` / `ssl_certificate_key` / `ssl_password_file` from the
    /// `http` block, inherited by any server that does not set its own.
    pub ssl_certificate: Option<PathBuf>,
    pub ssl_certificate_key: Option<PathBuf>,
    pub ssl_password_file: Option<PathBuf>,
    pub ssl_certificate_cache: CertCacheCfg,
    pub default_access_logs: Vec<AccessLog>,
    pub upstreams: Vec<Upstream>,
    pub cache_zones: Vec<CacheZone>,
    pub maps: Vec<crate::mapping::MapDef>,
    /// `split_clients` buckets, resolved as variables.
    pub split_clients: Vec<crate::split::SplitClients>,
    pub geos: Vec<crate::geo::GeoDef>,
    pub limit_req_zones: Vec<LimitReqZone>,
    pub limit_conn_zones: Vec<LimitConnZone>,
    pub log_formats: LogFormats,
}

/// A declared `limit_req_zone`.
pub struct LimitReqZone {
    pub name: String,
    pub key: String,
    pub rate: f64,
    /// Shared state, created at config time so a reload keeps the same table.
    pub state: Arc<crate::limit::ReqZone>,
}

impl std::fmt::Debug for LimitReqZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimitReqZone")
            .field("name", &self.name)
            .field("rate", &self.rate)
            .finish()
    }
}

impl std::fmt::Debug for LimitConnZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimitConnZone")
            .field("name", &self.name)
            .finish()
    }
}

/// A declared `limit_conn_zone`.
pub struct LimitConnZone {
    pub name: String,
    pub key: String,
    pub state: Arc<crate::limit::ConnZone>,
}

/// One `limit_req` directive inside a location.
#[derive(Debug, Clone)]
pub struct LimitReq {
    pub zone: String,
    pub burst: u32,
    pub nodelay: bool,
    pub delay: Option<u32>,
}

/// One `limit_conn` directive inside a location.
#[derive(Debug, Clone)]
pub struct LimitConn {
    pub zone: String,
    pub limit: u32,
}

#[derive(Debug)]
pub struct Config {
    pub prefix: PathBuf,
    pub conf_path: PathBuf,
    pub worker_processes: usize,
    pub daemon: bool,
    pub pid: Option<PathBuf>,
    pub error_log: Option<PathBuf>,
    /// `error_log` directives of the main context, in order.
    pub error_logs: Vec<LogSpec>,
    pub http: Http,
    pub stream: StreamSection,
    /// `mail {}` listeners (a top-level section, like stream, not part of http).
    pub mail_servers: Vec<MailServer>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct StreamSection {
    pub servers: Vec<StreamServerCfg>,
    pub upstreams: Vec<StreamUpstream>,
    /// `geo` blocks in `stream {}` context. They are a separate namespace from
    /// the http ones: `ngx_stream_geo_module` registers its own variables, and
    /// a name may exist in both sections with different meanings.
    pub geos: Vec<crate::geo::GeoDef>,
    /// `map` blocks in `stream {}` context, likewise separate from http.
    pub maps: Vec<crate::mapping::MapDef>,
    /// `split_clients` blocks in `stream {}` context.
    pub splits: Vec<crate::split::SplitClients>,
}

#[derive(Debug, Clone)]
pub struct StreamUpstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub method: LbMethod,
    /// `hash <key>` template, expanded per connection.
    pub hash_key: String,
}

#[derive(Debug, Clone)]
pub struct StreamServerCfg {
    pub listen: SocketAddr,
    pub udp: bool,
    pub proxy_pass: Option<String>,
    pub proxy_timeout: Duration,
    pub proxy_connect_timeout: Duration,
    /// `error_log` directives of this stream server.
    pub error_logs: Vec<LogSpec>,
    /// `listen ... ssl`: terminate TLS before proxying.
    pub ssl: bool,
    pub ssl_certificate: Option<PathBuf>,
    pub ssl_certificate_key: Option<PathBuf>,
    pub ssl_password_file: Option<PathBuf>,
    /// `proxy_ssl`: speak TLS to the upstream.
    pub proxy_ssl: bool,
    /// `proxy_ssl_session_reuse`.
    pub proxy_ssl_session_reuse: bool,
    /// `proxy_ssl_name`: upstream SNI.
    pub proxy_ssl_name: Option<String>,
    /// `return <text>` in a stream server.
    pub return_text: Option<String>,
    /// `ssl_verify_client`: 0 off, 1 on, 2 optional, 3 optional_no_ca.
    pub ssl_verify_client: u8,
    /// `ssl_client_certificate`: trust anchors for the client chain.
    pub ssl_client_certificate: Option<PathBuf>,
    /// `ssl_trusted_certificate`: extra chain-building certificates.
    pub ssl_trusted_certificate: Option<PathBuf>,
    /// `set $name value` in a stream server, applied in order before `return`.
    pub sets: Vec<(String, String)>,
    /// `access_log` of this stream server; empty means none.
    pub access_logs: Vec<AccessLog>,
    /// `proxy_protocol on|off`: prefix the upstream connection with a HAProxy
    /// PROXY header (`ngx_proxy_protocol_write`).
    ///
    /// `None` means "not set here", so the `stream {}`-level value applies --
    /// `stream_proxy_protocol.t` declares `proxy_protocol on` at stream level
    /// and turns it off for one server.
    pub proxy_protocol: Option<bool>,
    /// `listen ... proxy_protocol` in stream: consume such a header from the
    /// client before proxying.
    pub listen_proxy_protocol: bool,
}

impl Http {
    pub fn server(&self, idx: usize) -> &Server {
        &self.servers[idx]
    }

    pub fn group_for(&self, addr: &SocketAddr) -> Option<&ListenGroup> {
        self.groups.iter().find(|g| &g.addr == addr)
    }
}

fn sem(file: &Path, line: u32, msg: impl Into<String>) -> ConfigError {
    ConfigError::Semantic {
        file: file.to_path_buf(),
        line,
        msg: msg.into(),
    }
}

fn parse_on_off(s: &str) -> Option<bool> {
    match s {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

pub fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1024u64),
        b'm' | b'M' => (&s[..s.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.parse::<u64>().ok().map(|v| v * mult)
}

/// nginx time value: `ms`, `s`, `m`, `h`, `d`, `w`, `M`, `y`, or a bare
/// number meaning seconds.
///
/// The `ms` suffix *must* be checked before the single-letter units: otherwise
/// `200ms` is read as `200m` + `s`, fails to parse, and the caller silently
/// keeps the directive's default. That bug made `proxy_cache_lock_timeout
/// 200ms` behave like its 5 s default.
/// The machine's host name, nginx's default for `server_name`.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".to_string())
}

/// `pop3` / `imap` / `smtp`, case-insensitively.
fn mail_protocol(v: &str) -> Option<crate::mail::Protocol> {
    match v.to_ascii_lowercase().as_str() {
        "pop3" => Some(crate::mail::Protocol::Pop3),
        "imap" => Some(crate::mail::Protocol::Imap),
        "smtp" => Some(crate::mail::Protocol::Smtp),
        _ => None,
    }
}

/// `a.b.c.d[/nn]` (bare address = /32 or /128).
pub fn parse_realip_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    match s.split_once('/') {
        Some((ip, bits)) => Some((ip.parse().ok()?, bits.parse().ok()?)),
        None => {
            let ip: std::net::IpAddr = s.parse().ok()?;
            let bits = if ip.is_ipv4() { 32 } else { 128 };
            Some((ip, bits))
        }
    }
}

/// `set_real_ip_from` value → the networks it trusts.
///
/// nginx accepts three shapes: a literal address or CIDR, a hostname (resolved
/// with getaddrinfo at configuration time, which is why `set_real_ip_from
/// localhost` works), and `unix:` (handled by the caller — it produces no
/// address at all). A name that fails to resolve is a configuration error in
/// nginx; here it is reported as a warning and contributes nothing.
pub fn resolve_realip_from(s: &str) -> Result<Vec<(std::net::IpAddr, u8)>, String> {
    if let Some(cidr) = parse_realip_cidr(s) {
        return Ok(vec![cidr]);
    }
    if s.contains('/') || s.is_empty() {
        return Err(format!("invalid parameter \"{s}\""));
    }
    // `to_socket_addrs` is getaddrinfo(3) with the port stripped, which is
    // exactly what `ngx_inet_resolve_host` does for this directive.
    let addrs: Vec<(std::net::IpAddr, u8)> = (s, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("host not found in \"{s}\" ({e})"))?
        .map(|a| {
            let ip = a.ip();
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        })
        .collect();
    if addrs.is_empty() {
        return Err(format!("host not found in \"{s}\""));
    }
    Ok(addrs)
}

/// `ngx_http_secure_link_merge_conf`: the two styles do not mix.
///
/// A scope that set `secure_link_secret` has already cleared the new-style
/// fields (the caller does that), and a scope that set either new-style
/// directive must stop inheriting the parent's secret -- otherwise a nested
/// `location` with `secure_link`/`secure_link_md5` would be evaluated with the
/// parent's `secure_link_secret`, which is the old style.
fn merge_secure_link(cfg: &mut LocCfg) {
    if cfg.secure_link_secret_set {
        cfg.secure_link = None;
        cfg.secure_link_md5 = None;
        return;
    }
    if cfg.secure_link_set || cfg.secure_link_md5_set {
        cfg.secure_link_secret = None;
    }
}

pub fn parse_time(s: &str) -> Option<Duration> {
    // nginx's time grammar sums unit tokens in any order: `1h30m`, `1d 12h`,
    // `500` (bare seconds). A bare number must end the value.
    // An empty value is not zero: `ngx_parse_time` reports NGX_ERROR when there
    // is not a single digit, which is what makes `expires ""` emit no headers at
    // all (`headers.t`, "expires var empty"). Returning `Some(0)` here silently
    // turned every missing value into a zero duration.
    if s.is_empty() {
        return None;
    }
    let mut total_ms: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        let (n, tail) = rest.split_at(digits);
        let n: u64 = n.parse().ok()?;
        if tail.is_empty() {
            total_ms = total_ms.saturating_add(n.saturating_mul(1000));
            break;
        }
        let (mult, consumed) = if let Some(t) = tail.strip_prefix("ms") {
            (1u64, t)
        } else {
            let mut ch = tail.chars();
            let c = ch.next()?;
            let m = match c {
                's' => 1000,
                'm' => 60 * 1000,
                'h' => 3600 * 1000,
                'd' => 86400 * 1000,
                'w' => 7 * 86400 * 1000,
                'M' => 30 * 86400 * 1000,
                'y' => 365 * 86400 * 1000,
                _ => return None,
            };
            (m, ch.as_str())
        };
        total_ms = total_ms.saturating_add(n.saturating_mul(mult));
        rest = consumed;
    }
    Some(Duration::from_millis(total_ms))
}

fn resolve_path(prefix: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        prefix.join(pb)
    }
}

/// `http://host[:port][/uri]` -> ProxyPass. Upstream names are resolved later.
pub fn parse_proxy_pass(url: &str) -> Option<ProxyPass> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return None;
    };
    // `unix:/path/to.sock[:uri]`. nginx takes the first `:` after the path
    // prefix as the URI separator, so `unix:/tmp/a.sock:/x` -> path + `/x`.
    if let Some(rest_unix) = rest.strip_prefix("unix:") {
        let (path, uri) = match rest_unix.find(':') {
            Some(i) => (&rest_unix[..i], Some(rest_unix[i + 1..].to_string())),
            None => (rest_unix, None),
        };
        if path.is_empty() {
            return None;
        }
        return Some(ProxyPass {
            target: ProxyTarget::Unix(std::sync::Arc::new(std::path::PathBuf::from(path))),
            uri,
            host_header: "localhost".to_string(),
            https: false,
        });
    }
    let (authority, uri) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_string())),
        None => (rest, None),
    };
    if authority.is_empty() {
        return None;
    }

    let target = match parse_listen(authority) {
        Some(addr) => ProxyTarget::Addr(addr),
        None => ProxyTarget::Upstream(usize::MAX),
    };
    // A bare port or host:port defaults to port 80 when only a host is given.
    let target = match target {
        ProxyTarget::Addr(a) if !authority.contains(':') => {
            ProxyTarget::Addr(SocketAddr::new(a.ip(), 80))
        }
        other => other,
    };
    // nginx's $proxy_host is the authority exactly as written in proxy_pass.
    let host_header = authority.to_string();

    Some(ProxyPass {
        target,
        uri,
        host_header,
        https: scheme,
    })
}

pub fn proxy_upstream_name(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    // `unix:/path` is a socket path, never an `upstream {}` name.
    if rest.starts_with("unix:") {
        return None;
    }
    let authority = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    if authority.is_empty() || parse_listen(authority).is_some() {
        return None;
    }
    // A variable names an upstream only at request time (`proxy_pass http://$b`),
    // so there is nothing to resolve here -- nginx only looks the name up when
    // the request is built. A `$` also covers `host:port` forms.
    if authority.contains('$') {
        return None;
    }
    Some(authority.to_string())
}

fn parse_upstream(d: &Directive) -> Result<Upstream, ConfigError> {
    let name = d
        .args
        .first()
        .ok_or_else(|| sem(&d.file, d.line, "upstream requires a name"))?
        .clone();
    let mut up = Upstream {
        name,
        servers: Vec::new(),
        method: LbMethod::RoundRobin,
        keepalive: 0,
        keepalive_requests: 1000,
        keepalive_time: Duration::from_secs(3600),
        keepalive_timeout: Duration::from_secs(60),
        chash_points: Vec::new(),
    };

    for child in d.block.as_ref().map(|b| b.as_slice()).unwrap_or(&[]) {
        match child.name.as_str() {
            "server" => {
                let addr_arg = child
                    .args
                    .first()
                    .ok_or_else(|| sem(&child.file, child.line, "server requires an address"))?;
                let mut addr = parse_listen(addr_arg).ok_or_else(|| {
                    sem(
                        &child.file,
                        child.line,
                        format!("invalid server address \"{addr_arg}\""),
                    )
                })?;
                // upstream "host:port" without an IP is resolved later; here we
                // accept IPv4/IPv6 literals and fall back to 127.0.0.1.
                if !addr_arg.contains(':') {
                    addr = SocketAddr::new(addr.ip(), 80);
                }
                let mut srv = UpstreamServer {
                    addr,
                    weight: 1,
                    backup: false,
                    down: false,
                    name: addr_arg.clone(),
                    max_fails: 1,
                    fail_timeout: Duration::from_secs(10),
                    max_conns: 0,
                };
                for p in &child.args[1..] {
                    if p == "backup" {
                        srv.backup = true;
                    } else if p == "down" {
                        srv.down = true;
                    } else if let Some(w) = p.strip_prefix("weight=") {
                        srv.weight = w.parse().unwrap_or(1).max(1);
                    } else if let Some(mf) = p.strip_prefix("max_fails=") {
                        srv.max_fails = mf.parse().unwrap_or(1);
                    } else if let Some(ft) = p.strip_prefix("fail_timeout=") {
                        if let Some(t) = parse_time(ft) {
                            srv.fail_timeout = t;
                        }
                    } else if let Some(mc) = p.strip_prefix("max_conns=") {
                        srv.max_conns = mc.parse().unwrap_or(0);
                    }
                }
                up.servers.push(srv);
            }
            "least_conn" => up.method = LbMethod::LeastConn,
            "ip_hash" => up.method = LbMethod::IpHash,
            "random" => {
                let two = child.args.first().map(|a| a == "two").unwrap_or(false);
                let least_conn = child.args.iter().any(|a| a == "least_conn");
                up.method = LbMethod::Random { two, least_conn };
            }
            "keepalive_time" => {
                if let Some(t) = child.args.first().and_then(|v| parse_time(v)) {
                    up.keepalive_time = t;
                }
            }
            "keepalive_requests" => {
                if let Some(n) = child.args.first().and_then(|v| v.parse::<u64>().ok()) {
                    up.keepalive_requests = n;
                }
            }
            "keepalive_timeout" => {
                if let Some(t) = child.args.first().and_then(|v| parse_time(v)) {
                    up.keepalive_timeout = t;
                }
            }
            "keepalive" => {
                up.keepalive = child
                    .args
                    .first()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
            }
            "hash" => {
                // `hash <complex value> [consistent]`.
                let key = child.args.first().cloned().unwrap_or_default();
                let consistent = child
                    .args
                    .get(1)
                    .map(|a| a == "consistent")
                    .unwrap_or(false);
                up.method = LbMethod::Hash { key, consistent };
            }
            "zone" | "queue" | "resolver" => {}
            other => {
                return Err(sem(
                    &child.file,
                    child.line,
                    format!("unknown directive \"{other}\" in upstream"),
                ))
            }
        }
    }

    if up.servers.is_empty() {
        return Err(sem(&d.file, d.line, "upstream has no servers"));
    }
    // `hash ... consistent`: build the ketama ring once, nginx-style.
    if let LbMethod::Hash {
        consistent: true, ..
    } = up.method
    {
        up.chash_points = build_chash_points(&up.servers);
    }
    Ok(up)
}

/// nginx's CRC-32 (the standard IEEE table, `ngx_crc32_table_init`): needed
/// byte-for-byte because the hash balancer's peer mapping depends on it.
/// One-shot CRC-32 (the zlib polynomial nginx uses for `hash` keys).
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    fn table_entry(i: u32) -> u32 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        c
    }
    let mut c = !crc;
    for &b in data {
        c = table_entry((c ^ u32::from(b)) & 0xff) ^ (c >> 8);
    }
    !c
}

/// Split a `server` string as `ngx_http_upstream_update_chash` does: scan from
/// the end over digits; a `:` ends the port; anything non-digit first means the
/// whole string is the host. `unix:` keeps everything after the prefix.
fn chash_host_port(server: &str) -> (&str, &str) {
    if server.len() >= 5 && server[..5].eq_ignore_ascii_case("unix:") {
        return (&server[5..], "");
    }
    let bytes = server.as_bytes();
    for j in 0..bytes.len() {
        let c = bytes[server.len() - j - 1];
        if c == b':' {
            return (&server[..server.len() - j - 1], &server[server.len() - j..]);
        }
        if !c.is_ascii_digit() {
            break;
        }
    }
    (server, "")
}

/// Cache::Memcached::Fast-compatible points: per peer `weight * 160` entries,
/// each `crc32(host \0 port prev_hash_le32)` chained through the previous
/// point's hash, sorted and deduplicated by hash.
pub fn build_chash_points(servers: &[UpstreamServer]) -> Vec<(u32, usize)> {
    let mut points: Vec<(u32, usize)> = Vec::new();
    for (i, s) in servers.iter().enumerate() {
        let (host, port) = chash_host_port(&s.name);
        let mut base = 0u32;
        base = crc32_update(base, host.as_bytes());
        base = crc32_update(base, b"\x00");
        base = crc32_update(base, port.as_bytes());
        let mut prev: u32 = 0;
        for _ in 0..(s.weight as usize * 160) {
            let hash = crc32_update(base, &prev.to_le_bytes());
            points.push((hash, i));
            prev = hash;
        }
    }
    points.sort_by_key(|&(h, _)| h);
    points.dedup_by(|a, b| a.0 == b.0);
    points
}

#[cfg(test)]
mod chash_tests {
    use super::*;

    /// The weighted ring must reproduce nginx's mapping (probed against
    /// nginx 1.28: keys 1..=10 over `{8081 w1, 8082 w1, 8083 w10}`).
    #[test]
    fn weighted_ring_matches_nginx() {
        let servers: Vec<UpstreamServer> = [
            ("127.0.0.1:28001", 1u32),
            ("127.0.0.1:28002", 1),
            ("127.0.0.1:28003", 10),
        ]
        .iter()
        .map(|(n, w)| UpstreamServer {
            addr: "127.0.0.1:28001".parse().unwrap(),
            weight: *w,
            backup: false,
            down: false,
            name: n.to_string(),
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
            max_conns: 0,
        })
        .collect();
        let ring = build_chash_points(&servers);
        assert_eq!(ring.len(), 1920);
        let expected = [2, 2, 2, 1, 2, 2, 2, 2, 2, 2];
        for (a, want) in expected.iter().enumerate() {
            let key = (a + 1).to_string();
            let kh = crc32_update(0, key.as_bytes());
            let i = ring.partition_point(|&(h, _)| h < kh);
            let got = ring[i % ring.len()].1;
            assert_eq!(got, *want, "key {} mapped to {} want {}", key, got, want);
        }
    }
}

/// Patch every location's `proxy_pass http://<name>` to the upstream index.
fn resolve_proxy_upstreams(http: &mut Http) -> Result<(), ConfigError> {
    let lookup: HashMap<String, usize> = http
        .upstreams
        .iter()
        .enumerate()
        .map(|(i, u)| (u.name.clone(), i))
        .collect();

    fn fix(cfg: &mut LocCfg, lookup: &HashMap<String, usize>) -> Result<(), ConfigError> {
        if let (Some(name), Some(pp)) = (cfg.proxy_upstream_name.clone(), cfg.proxy_pass.as_mut()) {
            match lookup.get(&name) {
                Some(&idx) => {
                    pp.target = ProxyTarget::Upstream(idx);
                    pp.host_header = name.clone();
                    if std::env::var_os("NGXRS_DEBUG_CONFIG").is_some() {
                        eprintln!("ngxrs: resolved proxy_pass {name} -> upstream #{idx}");
                    }
                }
                None => {
                    return Err(ConfigError::Semantic {
                        file: PathBuf::from("<config>"),
                        line: 0,
                        msg: format!("proxy_pass refers to unknown upstream \"{name}\""),
                    })
                }
            }
        }
        Ok(())
    }

    fn walk(locs: &mut [Location], lookup: &HashMap<String, usize>) -> Result<(), ConfigError> {
        for l in locs {
            fix(&mut l.cfg, lookup)?;
            walk(&mut l.nested, lookup)?;
        }
        Ok(())
    }

    fix(&mut http.default_loc, &lookup)?;
    for s in &mut http.servers {
        fix(&mut s.default_loc, &lookup)?;
        walk(&mut s.locations, &lookup)?;
    }
    let _ = http;
    Ok(())
}

/// `listen unix:/path` in addition to the TCP forms.
pub fn parse_listen_any(s: &str) -> Option<ListenAddr> {
    if let Some(path) = s.strip_prefix("unix:") {
        if path.is_empty() {
            return None;
        }
        return Some(ListenAddr::Unix(std::sync::Arc::new(
            std::path::PathBuf::from(path),
        )));
    }
    parse_listen(s).map(ListenAddr::Tcp)
}

fn parse_listen(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(port) = s.parse::<u16>() {
        return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
    }
    if s == "*" {
        return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80)));
    }
    if let Some(rest) = s.strip_prefix("*:") {
        if let Ok(port) = rest.parse::<u16>() {
            return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
        }
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 80));
        }
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, port));
            }
            if host == "*" {
                return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
            }
        }
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 80));
    }
    None
}

/// Translate the PCRE bits nginx accepts but Rust's regex does not: `\Q...\E`
/// quoting. Everything else maps directly.
fn translate_pcre(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(start) = rest.find("\\Q") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("\\E") {
            Some(end) => {
                out.push_str(&regex::escape(&after[..end]));
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&regex::escape(after));
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// `translate_pcre` for other modules (the referer matcher needs the same
/// `\Q...\E` handling).
pub fn translate_pcre_public(src: &str) -> String {
    translate_pcre(src)
}

fn build_regex(src: &str, ci: bool) -> Option<regex::Regex> {
    let translated = translate_pcre(src);
    let pattern = if ci {
        format!("(?i:{translated})")
    } else {
        translated
    };
    regex::Regex::new(&pattern).ok()
}

#[cfg(test)]
mod regex_tests {
    use super::translate_pcre;

    #[test]
    fn q_quote_is_escaped() {
        let out = translate_pcre("^(?P<name>[a-z]+)\\.example\\.com$");
        assert_eq!(out, "^(?P<name>[a-z]+)\\.example\\.com$");
        let quoted = translate_pcre("^\\Qfoo.bar\\E$");
        assert_eq!(quoted, "^foo\\.bar$");
    }
}

struct Builder {
    prefix: PathBuf,
    warnings: Vec<String>,
    /// `log_format name 'fmt'` seen at http scope. Location-level `access_log`
    /// needs it too, and nginx allows the format to be defined before any
    /// server that uses it.
    log_formats: LogFormats,
}

impl Builder {
    fn warn(&mut self, d: &Directive, msg: impl Into<String>) {
        self.warnings
            .push(format!("{}:{}: {}", d.file.display(), d.line, msg.into()));
    }

    fn unknown(&mut self, d: &Directive, ctx: &str) {
        self.warn(d, format!("unknown directive \"{}\" in {}", d.name, ctx));
    }

    /// Parse `mail { ... }`.
    fn parse_mail(&mut self, dirs: &[Directive]) -> Result<Vec<MailServer>, ConfigError> {
        let mut defaults = MailServer::default();
        let mut servers: Vec<MailServer> = Vec::new();
        let mut servers_dirs: Vec<&Directive> = Vec::new();
        // `ssl_certificate` and `ssl_certificate_key` may come in either order.
        let mut mail_cert: Option<PathBuf> = None;
        let mut mail_key: Option<PathBuf> = None;
        // Per-protocol authentication defaults; see `AuthSet`.
        let mut dflt_pop3 = AuthSet::default();
        let mut dflt_imap = AuthSet::default();
        let mut dflt_smtp = AuthSet::default();

        for d in dirs {
            match d.name.as_str() {
                "auth_http" => {
                    let v = d
                        .args
                        .first()
                        .ok_or_else(|| sem(&d.file, d.line, "auth_http requires a URL"))?;
                    defaults.auth_http =
                        Some(crate::mail::AuthHttp::parse(v).ok_or_else(|| {
                            sem(&d.file, d.line, format!("invalid auth_http URL \"{v}\""))
                        })?);
                }
                "auth_http_timeout" => {
                    if let Some(t) = d.args.first().and_then(|v| parse_time(v)) {
                        defaults.auth_http_timeout = t;
                    }
                }
                "proxy_timeout" => {
                    if let Some(t) = d.args.first().and_then(|v| parse_time(v)) {
                        defaults.proxy_timeout = t;
                    }
                }
                "proxy_pass_error_message" => {
                    if let Some(v) = d.args.first() {
                        defaults.pass_error_message = parse_on_off(v).unwrap_or(false);
                    }
                }
                "server" => servers_dirs.push(d),
                // `pop3_auth` / `imap_auth` / `smtp_auth` are valid in the mail
                // main context as well; there they set the server defaults.
                "pop3_auth" => dflt_pop3 = AuthSet::from_args(&d.args),
                "imap_auth" => dflt_imap = AuthSet::from_args(&d.args),
                "smtp_auth" => dflt_smtp = AuthSet::from_args(&d.args),
                // Accepted, not yet plumbed.
                "proxy_buffer"
                | "auth_http_header"
                | "resolver"
                | "resolver_timeout"
                | "log_format"
                | "timeout"
                | "proxy_protocol"
                | "max_errors"
                | "protocol"
                | "ssl_protocols"
                | "ssl_ciphers"
                | "ssl_prefer_server_ciphers"
                | "ssl_session_cache"
                | "ssl_session_timeout"
                | "ssl_conf_command"
                | "xclient"
                | "smtp_auth_methods"
                | "smtp_client_buffer"
                | "worker_aio_requests" => {}
                "starttls" => {
                    if let Some(v) = d.args.first().and_then(|v| StarttlsCfg::parse(v)) {
                        defaults.starttls = v;
                    }
                }
                "smtp_greeting_delay" => {
                    if let Some(t) = d.args.first().and_then(|v| parse_time(v)) {
                        defaults.greeting_delay = t;
                    }
                }
                "error_log" => {
                    if let Some(spec) = parse_log_spec(&self.prefix, &d.args) {
                        defaults.error_logs.push(spec);
                    }
                }
                "ssl_password_file" => {
                    if let Some(v) = d.args.first() {
                        defaults.ssl_password_file = Some(self.prefix.join(v));
                    }
                }
                "pop3_capabilities" | "imap_capabilities" | "smtp_capabilities" => {
                    defaults.capabilities = Some(d.args.clone());
                }
                "ssl_certificate" => {
                    if let Some(v) = d.args.first() {
                        mail_cert = Some(self.prefix.join(v));
                    }
                }
                "ssl_certificate_key" => {
                    if let Some(v) = d.args.first() {
                        mail_key = Some(self.prefix.join(v));
                    }
                }
                other => {
                    self.warnings.push(format!(
                        "{}:{}: unknown directive \"{other}\" in mail; ignored",
                        d.file.display(),
                        d.line
                    ));
                }
            }
        }

        // nginx accepts the certificate and key in either order, so the context
        // is built only once both paths are known.
        if let (Some(c), Some(k)) = (mail_cert.as_ref(), mail_key.as_ref()) {
            let pw = match &defaults.ssl_password_file {
                Some(p) => crate::tls::read_passwords(p).unwrap_or_default(),
                None => Vec::new(),
            };
            match crate::tls::build_mail_config_with(c, k, &pw) {
                Ok(cfg) => defaults.tls = Some(cfg),
                Err(e) => self
                    .warnings
                    .push(format!("cannot load mail certificate {}: {e}", c.display())),
            }
        }

        for sd in servers_dirs {
            let block = sd
                .block
                .as_ref()
                .ok_or_else(|| sem(&sd.file, sd.line, "mail server requires a block"))?;
            let mut srv = defaults.clone();
            let mut srv_cert: Option<PathBuf> = None;
            let mut srv_key: Option<PathBuf> = None;
            let mut srv_pop3: Option<AuthSet> = None;
            let mut srv_imap: Option<AuthSet> = None;
            let mut srv_smtp: Option<AuthSet> = None;
            // `listen <addr> [pop3|imap|smtp]`
            srv.listen = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 110));
            for child in block {
                match child.name.as_str() {
                    "listen" => {
                        let v = child.args.first().ok_or_else(|| {
                            sem(&child.file, child.line, "listen requires an address")
                        })?;
                        srv.listen = parse_listen(v).ok_or_else(|| {
                            sem(&child.file, child.line, format!("invalid listen \"{v}\""))
                        })?;
                        for extra in &child.args[1..] {
                            if extra == "ssl" {
                                srv.ssl = true;
                            }
                            if let Some(p) = mail_protocol(extra) {
                                srv.protocol = p;
                            }
                        }
                    }
                    "server_name" => {
                        if let Some(v) = child.args.first() {
                            srv.name = v.clone();
                        }
                    }
                    "protocol" => {
                        let v = child.args.first().ok_or_else(|| {
                            sem(&child.file, child.line, "protocol requires a value")
                        })?;
                        srv.protocol = mail_protocol(v).ok_or_else(|| {
                            sem(&child.file, child.line, format!("invalid protocol \"{v}\""))
                        })?;
                    }
                    // Kept per protocol and resolved after the block, because
                    // `listen ... imap` may come after the auth directive.
                    "pop3_auth" => srv_pop3 = Some(AuthSet::from_args(&child.args)),
                    "imap_auth" => srv_imap = Some(AuthSet::from_args(&child.args)),
                    "smtp_auth" => srv_smtp = Some(AuthSet::from_args(&child.args)),
                    "auth_http" => {
                        let v = child.args.first().ok_or_else(|| {
                            sem(&child.file, child.line, "auth_http requires a URL")
                        })?;
                        srv.auth_http = Some(crate::mail::AuthHttp::parse(v).ok_or_else(|| {
                            sem(
                                &child.file,
                                child.line,
                                format!("invalid auth_http URL \"{v}\""),
                            )
                        })?);
                    }
                    "auth_http_timeout" => {
                        if let Some(t) = child.args.first().and_then(|v| parse_time(v)) {
                            srv.auth_http_timeout = t;
                        }
                    }
                    "proxy_timeout" => {
                        if let Some(t) = child.args.first().and_then(|v| parse_time(v)) {
                            srv.proxy_timeout = t;
                        }
                    }
                    "proxy_pass_error_message" => {
                        if let Some(v) = child.args.first() {
                            srv.pass_error_message = parse_on_off(v).unwrap_or(false);
                        }
                    }
                    "starttls" => {
                        if let Some(v) = child.args.first().and_then(|v| StarttlsCfg::parse(v)) {
                            srv.starttls = v;
                        }
                    }
                    "smtp_greeting_delay" => {
                        if let Some(t) = child.args.first().and_then(|v| parse_time(v)) {
                            srv.greeting_delay = t;
                        }
                    }
                    "error_log" => {
                        if let Some(spec) = parse_log_spec(&self.prefix, &child.args) {
                            srv.error_logs.push(spec);
                        }
                    }
                    "ssl_password_file" => {
                        if let Some(v) = child.args.first() {
                            srv.ssl_password_file = Some(self.prefix.join(v));
                        }
                    }
                    "pop3_capabilities" | "imap_capabilities" | "smtp_capabilities" => {
                        srv.capabilities = Some(child.args.clone());
                    }
                    "ssl_certificate" => {
                        if let Some(v) = child.args.first() {
                            srv_cert = Some(self.prefix.join(v));
                        }
                    }
                    "ssl_certificate_key" => {
                        if let Some(v) = child.args.first() {
                            srv_key = Some(self.prefix.join(v));
                        }
                    }
                    // Accepted, not yet plumbed.
                    "proxy_buffer"
                    | "xclient"
                    | "ssl_protocols"
                    | "ssl_ciphers"
                    | "ssl_prefer_server_ciphers"
                    | "ssl_session_cache"
                    | "ssl_session_timeout"
                    | "auth_http_header"
                    | "proxy_protocol"
                    | "max_errors"
                    | "smtp_client_buffer"
                    | "smtp_auth_methods"
                    | "smtp_xclient"
                    | "timeout" => {}
                    other => {
                        self.warnings.push(format!(
                            "{}:{}: unknown directive \"{other}\" in mail server; ignored",
                            child.file.display(),
                            child.line
                        ));
                    }
                }
            }
            // A `mail server` may carry its own certificate; otherwise the
            // one from the `mail` block is inherited.
            if let (Some(c), Some(k)) = (srv_cert.as_ref(), srv_key.as_ref()) {
                let pw = match &srv.ssl_password_file {
                    Some(p) => crate::tls::read_passwords(p).unwrap_or_default(),
                    None => Vec::new(),
                };
                match crate::tls::build_mail_config_with(c, k, &pw) {
                    Ok(cfg) => srv.tls = Some(cfg),
                    Err(e) => self
                        .warnings
                        .push(format!("cannot load mail certificate {}: {e}", c.display())),
                }
            }

            // Apply the set belonging to this server's protocol.
            let set = match srv.protocol {
                crate::mail::Protocol::Pop3 => srv_pop3.unwrap_or(dflt_pop3),
                crate::mail::Protocol::Imap => srv_imap.unwrap_or(dflt_imap),
                crate::mail::Protocol::Smtp => srv_smtp.unwrap_or(dflt_smtp),
            };
            srv.auth_plain = set.plain;
            srv.auth_apop = set.apop;
            srv.auth_none = set.none;
            srv.auth_login = set.login;
            srv.auth_cram_md5 = set.cram_md5;
            srv.auth_external = set.external;
            servers.push(srv);
        }
        Ok(servers)
    }

    fn apply_loc(&mut self, d: &Directive, cfg: &mut LocCfg) -> Result<bool, ConfigError> {
        match d.name.as_str() {
            "root" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "root requires a path"))?;
                cfg.root = resolve_path(&self.prefix, v);
            }
            "alias" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "alias requires a path"))?;
                cfg.alias = Some(resolve_path(&self.prefix, v));
                cfg.alias_prefix_len = cfg.prefix_len;
            }
            "index" => {
                cfg.index = d.args.clone();
            }
            "charset" => {
                // Two consumers: the charset filter (declare + recode), and
                // autoindex, which counts name widths in characters rather than
                // bytes when the charset is utf-8.
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "charset requires a value"))?;
                cfg.charset_utf8 =
                    v.eq_ignore_ascii_case("utf-8") || v.eq_ignore_ascii_case("utf8");
                cfg.charset = if v == "off" {
                    CharsetSpec::Off
                } else if let Some(name) = v.strip_prefix('$') {
                    CharsetSpec::Var(name.to_string())
                } else {
                    CharsetSpec::Name(v.clone())
                };
            }
            "autoindex_format" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "autoindex_format requires a value"))?;
                cfg.autoindex_format = match v.as_str() {
                    "html" => AutoindexFormat::Html,
                    "json" => AutoindexFormat::Json,
                    "jsonp" => AutoindexFormat::Jsonp,
                    "xml" => AutoindexFormat::Xml,
                    _ => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid autoindex_format value \"{v}\""),
                        ))
                    }
                };
            }
            "autoindex" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "autoindex requires on|off"))?;
                cfg.autoindex = parse_on_off(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid autoindex value \"{v}\""))
                })?;
            }
            "access_log" => {
                let logs = cfg.access_logs.get_or_insert_with(Vec::new);
                if d.args.first().map(|s| s.as_str()) == Some("off") {
                    logs.clear();
                } else if let Some(mut al) = parse_access_log(&d.args, &self.prefix) {
                    // Resolve the format name against this level's
                    // `log_format` blocks.
                    let (text, esc) = resolve_format(&self.log_formats, &al.format);
                    al.format = text;
                    al.escape = al.escape.or(Some(esc));
                    logs.push(al);
                }
            }
            "auth_basic" => {
                // The realm may contain spaces, so join every argument.
                let realm = d.args.join(" ");
                cfg.auth_basic.realm = Some(realm);
            }
            "auth_basic_user_file" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "auth_basic_user_file requires a path"))?;
                // nginx resolves a relative path against the configuration
                // prefix; a `$var` in the value survives as text and is
                // expanded per request, so the anchoring happens first.
                cfg.auth_basic.user_file = Some(resolve_path(&self.prefix, v));
            }
            "auth_request" => {
                let v = d.args.first().map(|s| s.as_str()).unwrap_or("");
                cfg.auth_request = if v.is_empty() || v == "off" {
                    None
                } else {
                    Some(v.to_string())
                };
            }
            "auth_request_set" => {
                let var = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "auth_request_set requires a variable"))?;
                let value = d
                    .args
                    .get(1)
                    .ok_or_else(|| sem(&d.file, d.line, "auth_request_set requires a value"))?;
                let name = var.trim_start_matches('$').to_string();
                cfg.auth_request_set.push((name, value.clone()));
            }
            "satisfy" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "satisfy requires all|any"))?;
                cfg.satisfy_any = match v.as_str() {
                    "any" => true,
                    "all" => false,
                    other => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid satisfy value \"{other}\""),
                        ))
                    }
                };
            }
            "ssi" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "ssi requires on|off"))?;
                cfg.ssi = parse_on_off(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid ssi value \"{v}\"")))?;
            }
            "limit_rate" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "limit_rate requires a value"))?;
                cfg.limit_rate = Some(v.clone());
            }
            "limit_rate_after" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "limit_rate_after requires a size"))?;
                cfg.limit_rate_after = if v == "0" {
                    0
                } else {
                    parse_size(v)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid size \"{v}\"")))?
                };
            }
            "empty_gif" => cfg.empty_gif = true,
            "stub_status" => cfg.stub_status = true,
            "random_index" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "random_index requires on|off"))?;
                cfg.random_index = parse_on_off(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid random_index value \"{v}\""),
                    )
                })?;
            }
            "valid_referers" => {
                cfg.valid_referers_args = Some(d.args.clone());
            }
            "sub_filter" => {
                if d.args.len() < 2 {
                    return Err(sem(&d.file, d.line, "sub_filter requires two arguments"));
                }
                cfg.sub_filters.push((d.args[0].clone(), d.args[1].clone()));
            }
            "sub_filter_once" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "sub_filter_once requires on|off"))?;
                cfg.sub_filter_once = parse_on_off(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid sub_filter_once value \"{v}\""),
                    )
                })?;
            }
            "sub_filter_types" => {
                cfg.sub_filter_types = d.args.clone();
            }
            "sub_filter_buffering" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(&d.file, d.line, "sub_filter_buffering requires on|off")
                })?;
                cfg.sub_filter_buffering = parse_on_off(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid sub_filter_buffering value \"{v}\""),
                    )
                })?;
            }
            "sub_filter_last_modified" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(&d.file, d.line, "sub_filter_last_modified requires on|off")
                })?;
                cfg.sub_filter_last_modified = parse_on_off(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid sub_filter_last_modified value \"{v}\""),
                    )
                })?;
            }
            "gzip" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "gzip requires on|off"))?;
                cfg.gzip = parse_on_off(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid gzip value \"{v}\"")))?;
            }
            "client_body_in_file_only" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(&d.file, d.line, "client_body_in_file_only requires a value")
                })?;
                cfg.client_body_in_file_only = match v.as_str() {
                    "on" => Some(ClientBodyFileOnly::On),
                    "clean" => Some(ClientBodyFileOnly::Clean),
                    "off" => None,
                    _ => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid client_body_in_file_only value \"{v}\""),
                        ))
                    }
                };
            }
            "client_body_buffer_size" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(&d.file, d.line, "client_body_buffer_size requires a size")
                })?;
                cfg.client_body_buffer_size = parse_size(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid size \"{v}\"")))?;
            }
            "client_max_body_size" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "client_max_body_size requires a size"))?;
                cfg.client_max_body_size = if v == "0" {
                    u64::MAX
                } else {
                    parse_size(v)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid size \"{v}\"")))?
                };
            }
            "add_header" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "add_header requires at least 2 arguments",
                    ));
                }
                // The value may contain spaces and a trailing `always`.
                cfg.headers.push((d.args[0].clone(), d.args[1..].join(" ")));
            }
            "add_trailer" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "add_trailer requires at least 2 arguments",
                    ));
                }
                cfg.trailers
                    .push((d.args[0].clone(), d.args[1..].join(" ")));
            }
            "error_page" => {
                let mut codes: Vec<u16> = Vec::new();
                let mut uri: Option<String> = None;
                let mut override_status: Option<String> = None;
                for a in &d.args {
                    if a.starts_with('=') {
                        // `error_page 404 =200 /empty.gif`
                        override_status = Some(a.clone());
                    } else if let Ok(c) = a.parse::<u16>() {
                        codes.push(c);
                    } else {
                        uri = Some(a.clone());
                    }
                }
                let uri = uri.ok_or_else(|| sem(&d.file, d.line, "error_page requires a URI"))?;
                let stored = match override_status {
                    Some(o) => format!("{o} {uri}"),
                    None => uri,
                };
                for c in codes {
                    cfg.error_pages.insert(c, stored.clone());
                }
            }
            "rewrite" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "rewrite requires a regex and a replacement",
                    ));
                }
                let flag = match d.args.get(2).map(|s| s.as_str()) {
                    None => RewriteFlag::None,
                    Some("last") => RewriteFlag::Last,
                    Some("break") => RewriteFlag::Break,
                    Some("redirect") => RewriteFlag::Redirect,
                    Some("permanent") => RewriteFlag::Permanent,
                    Some(other) => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid rewrite flag \"{other}\""),
                        ))
                    }
                };
                let rw = compile_rewrite(&d.args[0], &d.args[1], flag).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid regex \"{}\"", d.args[0]))
                })?;
                cfg.rewrites.push(rw);
            }
            "set" => {
                if d.args.len() < 2 {
                    return Err(sem(&d.file, d.line, "set requires a variable and a value"));
                }
                cfg.steps.push(Step::Set(cfg.sets.len()));
                cfg.sets.push((d.args[0].clone(), d.args[1..].join(" ")));
            }
            "if" => {
                let block = d
                    .block
                    .as_ref()
                    .ok_or_else(|| sem(&d.file, d.line, "if requires a block"))?;
                let mut cond = parse_if_cond(&d.args)
                    .ok_or_else(|| sem(&d.file, d.line, "unsupported if condition"))?;
                let mut ifb = IfBlock {
                    proxy_pass: None,
                    proxy_upstream_name: None,
                    cond: IfCond::Truthy(String::new()),
                    rewrites: Vec::new(),
                    ret: None,
                    sets: Vec::new(),
                };
                for child in block {
                    match child.name.as_str() {
                        "rewrite" => {
                            let flag = match child.args.get(2).map(|s| s.as_str()) {
                                None => RewriteFlag::None,
                                Some("last") => RewriteFlag::Last,
                                Some("break") => RewriteFlag::Break,
                                Some("redirect") => RewriteFlag::Redirect,
                                Some("permanent") => RewriteFlag::Permanent,
                                Some(other) => {
                                    return Err(sem(
                                        &child.file,
                                        child.line,
                                        format!("invalid rewrite flag \"{other}\""),
                                    ))
                                }
                            };
                            if let Some(rw) = compile_rewrite(
                                child.args.first().map(|s| s.as_str()).unwrap_or(""),
                                child.args.get(1).map(|s| s.as_str()).unwrap_or(""),
                                flag,
                            ) {
                                ifb.rewrites.push(rw);
                            }
                        }
                        "return" => {
                            let code: u16 =
                                child.args.first().and_then(|c| c.parse().ok()).ok_or_else(
                                    || sem(&child.file, child.line, "return requires a status"),
                                )?;
                            ifb.ret = Some((code, child.args.get(1).cloned().unwrap_or_default()));
                        }
                        "set" => {
                            if child.args.len() >= 2 {
                                ifb.sets
                                    .push((child.args[0].clone(), child.args[1..].join(" ")));
                            }
                        }
                        "break" => {}
                        // nginx allows `proxy_pass` inside `if`; it takes over
                        // from the location while the condition holds.
                        "proxy_pass" => {
                            let v = child.args.first().ok_or_else(|| {
                                sem(&child.file, child.line, "proxy_pass requires a URL")
                            })?;
                            ifb.proxy_pass = Some(parse_proxy_pass(v).ok_or_else(|| {
                                sem(
                                    &child.file,
                                    child.line,
                                    format!("invalid proxy_pass URL \"{v}\""),
                                )
                            })?);
                            ifb.proxy_upstream_name = proxy_upstream_name(v);
                        }
                        other => {
                            return Err(sem(
                                &child.file,
                                child.line,
                                format!("directive \"{other}\" is not allowed inside if"),
                            ))
                        }
                    }
                }
                ifb.cond = cond;
                cond = IfCond::Truthy(String::new());
                let _ = cond;
                cfg.steps.push(Step::If(cfg.ifs.len()));
                cfg.ifs.push(ifb);
            }
            "break" => {}
            "return" => {
                if d.args.is_empty() {
                    return Err(sem(&d.file, d.line, "return requires a status code"));
                }
                // `return <non-numeric>` is nginx's shorthand for a 302 whose
                // Location is the argument (which may be a variable or an
                // expression like `http://127.0.0.1:8081$uri`). Only a leading
                // decimal number is a status code.
                match d.args[0].parse::<u16>() {
                    Ok(code) => {
                        let body = d.args.get(1).cloned().unwrap_or_default();
                        cfg.ret = Some((code, body));
                    }
                    Err(_) => {
                        let target = d.args[0].clone();
                        cfg.ret = Some((302, target));
                    }
                }
            }
            "try_files" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "try_files requires at least 2 arguments",
                    ));
                }
                cfg.try_files = d.args.clone();
            }
            "internal" => cfg.internal = true,
            "set_real_ip_from" => {
                // First directive in this scope replaces the inherited list,
                // `unix:` entries included: nginx keeps both shapes in one
                // per-scope array (`NGX_HTTP_REALIP_UNIX` is just another cidr
                // family), so `merge_loc_conf` copies or replaces them together.
                if !cfg.realip_from_set {
                    cfg.realip_from.clear();
                    cfg.realip_from_unix = false;
                    cfg.realip_from_set = true;
                }
                if let Some(v) = d.args.first() {
                    if v == "unix:" {
                        cfg.realip_from_unix = true;
                    } else {
                        match resolve_realip_from(v) {
                            Ok(cidrs) => cfg.realip_from.extend(cidrs),
                            Err(e) => self.warn(d, e),
                        }
                    }
                }
            }
            "real_ip_header" => {
                if let Some(v) = d.args.first() {
                    cfg.real_ip_header = v.clone();
                }
            }
            "real_ip_recursive" => {
                cfg.real_ip_recursive = d.args.first().map(|v| v == "on").unwrap_or(false);
            }
            "expires" => {
                // `expires` is TAKE12: only `modified <time>` uses two args.
                let spec = if d.args.len() >= 2 && d.args[0] == "modified" {
                    d.args[..2].join(" ")
                } else {
                    d.args.first().cloned().unwrap_or_else(|| "off".into())
                };
                // nginx: "expires modified @..." does not parse ("daily time
                // cannot be used with modified parameter").
                if let Some(rest) = spec.strip_prefix("modified ") {
                    if rest.trim_start().starts_with('@') {
                        return Err(sem(
                            &d.file,
                            d.line,
                            "daily time cannot be used with \"modified\" parameter".to_string(),
                        ));
                    }
                }
                cfg.expires = Some(spec);
            }
            "error_log" => {
                if let Some(spec) = parse_log_spec(&self.prefix, &d.args) {
                    cfg.error_logs.push(spec);
                }
            }
            "limit_req_log_level" => {
                if let Some(l) = d.args.first().and_then(|v| crate::log::Level::parse(v)) {
                    cfg.limit_req_log_level = l;
                }
            }
            "limit_conn_log_level" => {
                if let Some(l) = d.args.first().and_then(|v| crate::log::Level::parse(v)) {
                    cfg.limit_conn_log_level = l;
                }
            }
            "limit_req" => {
                // limit_req zone=NAME [burst=N] [nodelay | delay=N]
                let mut lr = LimitReq {
                    zone: String::new(),
                    burst: 0,
                    nodelay: false,
                    delay: None,
                };
                for a in &d.args {
                    if let Some(v) = a.strip_prefix("zone=") {
                        lr.zone = v.to_string();
                    } else if let Some(v) = a.strip_prefix("burst=") {
                        lr.burst = v.parse().unwrap_or(0);
                    } else if let Some(v) = a.strip_prefix("delay=") {
                        lr.delay = v.parse().ok();
                    } else if a == "nodelay" {
                        lr.nodelay = true;
                    }
                }
                if lr.zone.is_empty() {
                    return Err(sem(&d.file, d.line, "limit_req zone=NAME required"));
                }
                cfg.limit_reqs.push(lr);
            }
            "limit_conn" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "limit_conn needs zone and limit"))?;
                let n = d
                    .args
                    .get(1)
                    .ok_or_else(|| sem(&d.file, d.line, "limit_conn needs a limit"))?;
                cfg.limit_conns.push(LimitConn {
                    zone: v.clone(),
                    limit: n.parse().unwrap_or(0),
                });
            }
            "limit_req_status" | "limit_conn_status" => {
                if let Some(v) = d.args.first() {
                    if let Ok(code) = v.parse::<u16>() {
                        if d.name == "limit_req_status" {
                            cfg.limit_req_status = code;
                        } else {
                            cfg.limit_conn_status = code;
                        }
                    }
                }
            }
            "limit_req_dry_run" | "limit_conn_dry_run" => {
                let on = d.args.first().map(|v| v == "on").unwrap_or(false);
                if d.name == "limit_req_dry_run" {
                    cfg.limit_req_dry_run = on;
                } else {
                    cfg.limit_conn_dry_run = on;
                }
            }
            "proxy_bind" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "proxy_bind requires an address"))?;
                cfg.proxy_bind = Some(v.clone());
            }
            "allow" | "deny" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "allow/deny requires an address"))?;
                if v == "unix:" {
                    cfg.access.push(AccessRule {
                        deny: d.name == "deny",
                        net: None,
                        unix: true,
                    });
                } else {
                    let net = parse_cidr(v)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid address \"{v}\"")))?;
                    cfg.access.push(AccessRule {
                        deny: d.name == "deny",
                        net,
                        unix: false,
                    });
                }
            }
            "limit_except" => {
                let block = d
                    .block
                    .as_ref()
                    .ok_or_else(|| sem(&d.file, d.line, "limit_except requires a block"))?;
                let mut le = LimitExcept {
                    methods: d.args.iter().map(|m| m.to_uppercase()).collect(),
                    rules: Vec::new(),
                    proxy_pass: None,
                    proxy_upstream_name: None,
                };
                for child in block {
                    if child.name == "allow" || child.name == "deny" {
                        let v = child.args.first().ok_or_else(|| {
                            sem(&child.file, child.line, "allow/deny requires an address")
                        })?;
                        if v == "unix:" {
                            le.rules.push(AccessRule {
                                deny: child.name == "deny",
                                net: None,
                                unix: true,
                            });
                            continue;
                        }
                        let net = parse_cidr(v).ok_or_else(|| {
                            sem(&child.file, child.line, format!("invalid address \"{v}\""))
                        })?;
                        le.rules.push(AccessRule {
                            deny: child.name == "deny",
                            net,
                            unix: false,
                        });
                    } else if child.name == "proxy_pass" {
                        let v = child.args.first().ok_or_else(|| {
                            sem(&child.file, child.line, "proxy_pass requires a URL")
                        })?;
                        le.proxy_pass = Some(parse_proxy_pass(v).ok_or_else(|| {
                            sem(
                                &child.file,
                                child.line,
                                format!("invalid proxy_pass URL \"{v}\""),
                            )
                        })?);
                        le.proxy_upstream_name = proxy_upstream_name(v);
                    }
                }
                cfg.limit_except.push(le);
            }
            "absolute_redirect" | "server_name_in_redirect" | "port_in_redirect" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, format!("{} requires on|off", d.name)))?;
                let on = parse_on_off(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid {} value \"{v}\"", d.name))
                })?;
                match d.name.as_str() {
                    "absolute_redirect" => cfg.absolute_redirect = on,
                    "server_name_in_redirect" => cfg.server_name_in_redirect = on,
                    _ => cfg.port_in_redirect = on,
                }
            }
            "keepalive_requests" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "keepalive_requests requires a value"))?;
                cfg.keepalive_requests = Some(
                    v.parse::<u64>()
                        .map_err(|_| sem(&d.file, d.line, "invalid keepalive_requests"))?,
                );
            }
            "keepalive_timeout" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "keepalive_timeout requires a value"))?;
                let timeout = parse_time(v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid keepalive_timeout"))?;
                let header = d.args.get(1).and_then(|h| h.parse::<u32>().ok());
                cfg.keepalive_timeout = Some((timeout, header));
            }
            "keepalive_time" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "keepalive_time requires a value"))?;
                cfg.keepalive_time = Some(
                    parse_time(v).ok_or_else(|| sem(&d.file, d.line, "invalid keepalive_time"))?,
                );
            }
            "keepalive_disable" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "keepalive_disable requires a value"))?;
                cfg.keepalive_disable = match v.as_str() {
                    "msie6" => KeepaliveDisable::Msie6,
                    "safari" => KeepaliveDisable::Safari,
                    "none" => KeepaliveDisable::None,
                    other => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid keepalive_disable \"{other}\""),
                        ))
                    }
                };
            }
            "gzip_min_length" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "gzip_min_length requires a size"))?;
                cfg.gzip_min_length = parse_size(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid size \"{v}\"")))?;
            }
            "gzip_comp_level" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "gzip_comp_level requires a level"))?;
                cfg.gzip_comp_level = v
                    .parse::<u32>()
                    .ok()
                    .filter(|l| (1..=9).contains(l))
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid gzip level \"{v}\"")))?;
            }
            "gzip_types" => {
                cfg.gzip_types = d.args.clone();
            }
            "gzip_vary" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "gzip_vary requires on|off"))?;
                cfg.gzip_vary = parse_on_off(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid gzip_vary value \"{v}\""))
                })?;
            }
            "grpc_pass" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "grpc_pass requires a target"))?;
                // Keep the raw value: nginx resolves it per request so that
                // variables are allowed.
                cfg.grpc_pass = Some(v.clone());
            }
            "proxy_ssl_session_reuse" => {
                cfg.proxy_ssl_session_reuse = d.args.first().map(|v| v == "on").unwrap_or(true);
            }
            "proxy_ssl_name" => {
                cfg.proxy_ssl_name = d.args.first().cloned();
            }
            "proxy_ssl_verify"
            | "proxy_ssl_verify_depth"
            | "proxy_ssl_server_name"
            | "proxy_ssl_protocols"
            | "proxy_ssl_ciphers"
            | "proxy_ssl_trusted_certificate"
            | "proxy_ssl_crl"
            | "proxy_ssl_conf_command" => {
                // Accepted; verified TLS towards an upstream is not implemented
                // (nginx's default is `proxy_ssl_verify off`).
            }
            "proxy_redirect" => {
                let entry: Vec<String> = d.args.clone();
                if entry.is_empty() {
                    return Err(sem(&d.file, d.line, "proxy_redirect requires a value"));
                }
                // Replace, never append: nginx inherits the whole list from the
                // enclosing level only when this level declares none.
                cfg.proxy_redirect_src
                    .get_or_insert_with(Vec::new)
                    .push(entry);
            }
            "proxy_pass" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "proxy_pass requires a URL"))?;
                cfg.proxy_pass = Some(parse_proxy_pass(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid proxy_pass URL \"{v}\""))
                })?);
                cfg.proxy_pass.as_mut().unwrap().target =
                    cfg.proxy_pass.as_ref().unwrap().target.clone();
                if let Some(name) = proxy_upstream_name(v) {
                    cfg.proxy_upstream_name = Some(name);
                }
            }
            "proxy_set_header" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "proxy_set_header requires 2 arguments",
                    ));
                }
                cfg.proxy_set_headers
                    .push((d.args[0].clone(), d.args[1..].join(" ")));
            }
            "proxy_http_version" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "proxy_http_version requires a value"))?;
                cfg.proxy_http_version = match v.as_str() {
                    "1.0" => 0,
                    "1.1" => 1,
                    _ => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid proxy_http_version \"{v}\""),
                        ))
                    }
                };
            }
            "proxy_connect_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_connect_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid proxy_connect_timeout"))?;
                }
            }
            "proxy_read_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_read_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid proxy_read_timeout"))?;
                }
            }
            "proxy_send_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_send_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid proxy_send_timeout"))?;
                }
            }
            "proxy_buffering" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "proxy_buffering requires on|off"))?;
                cfg.proxy_buffering = parse_on_off(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid proxy_buffering \"{v}\""))
                })?;
            }
            "fastcgi_pass" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "fastcgi_pass requires an address"))?;
                // A value with a variable in it cannot be resolved here: nginx
                // resolves it per request, against an `upstream` name or a
                // literal `host:port`. Keeping the text is the only option.
                if v.contains('$') {
                    cfg.fastcgi_pass = Some(FastcgiPass {
                        addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                        spec: v.clone(),
                        dynamic: true,
                    });
                } else {
                    let addr = parse_listen(v).ok_or_else(|| {
                        sem(
                            &d.file,
                            d.line,
                            format!("invalid fastcgi_pass address \"{v}\""),
                        )
                    })?;
                    cfg.fastcgi_pass = Some(FastcgiPass {
                        addr,
                        spec: v.clone(),
                        dynamic: false,
                    });
                }
            }
            "slice" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "slice requires a size"))?;
                // nginx takes the usual size suffixes (`slice 1m`).
                let n = parse_size(v)
                    .filter(|n| *n > 0)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid slice size \"{v}\"")))?;
                cfg.slice = Some(n);
            }
            "server_tokens" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "server_tokens requires a value"))?;
                cfg.server_tokens = Some(match v.as_str() {
                    "off" => false,
                    // `build` also names the build in the version string; the
                    // build name is empty here, so it behaves like `on`.
                    "on" | "build" => true,
                    _ => return Err(sem(&d.file, d.line, "invalid server_tokens")),
                });
            }
            "gzip_static" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "gzip_static requires on|off"))?;
                // `always` sends the `.gz` even without `Accept-Encoding`, which
                // no suite exercises; treat it as `on` and note it.
                cfg.gzip_static = matches!(v.as_str(), "on" | "always");
            }
            "source_charset" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "source_charset requires a value"))?;
                cfg.source_charset = if v == "off" {
                    CharsetSpec::Off
                } else if let Some(name) = v.strip_prefix('$') {
                    CharsetSpec::Var(name.to_string())
                } else {
                    CharsetSpec::Name(v.clone())
                };
            }
            "charset_types" => {
                if d.args.len() == 1 && d.args[0] == "*" {
                    cfg.charset_types = Some(vec!["*".to_string()]);
                } else {
                    cfg.charset_types = Some(d.args.clone());
                }
            }
            "override_charset" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "override_charset requires on|off"))?;
                cfg.override_charset = parse_on_off(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid override_charset value \"{v}\""))
                })?;
            }
            "open_log_file_cache" => {
                // `open_log_file_cache max=N [inactive=T] [min_uses=N] [valid=T]`,
                // and the bare `off`/`min_uses=N` forms. `off` is the default,
                // expressed as `max = 0`.
                let mut c = OpenFileCache::default();
                for a in &d.args {
                    if a == "off" {
                        c.max = 0;
                    } else if let Some(v) = a.strip_prefix("max=") {
                        c.max = v.parse().unwrap_or(0);
                    } else if let Some(v) = a.strip_prefix("min_uses=") {
                        c.min_uses = v.parse().unwrap_or(1);
                    } else if let Some(v) = a.strip_prefix("inactive=") {
                        c.inactive = parse_time(v).unwrap_or(c.inactive);
                    } else if let Some(v) = a.strip_prefix("valid=") {
                        c.valid = parse_time(v).unwrap_or(c.valid);
                    }
                }
                cfg.open_log_file_cache = c;
            }
            "open_file_cache_errors" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "open_file_cache_errors requires on|off"))?;
                let on = parse_on_off(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid open_file_cache_errors value \"{v}\""),
                    )
                })?;
                cfg.open_log_file_cache.errors = on;
            }
            "log_not_found" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "log_not_found requires on|off"))?;
                cfg.log_not_found = parse_on_off(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid log_not_found value \"{v}\""))
                })?;
            }
            "disable_symlinks" => {
                let mut mode = None;
                let mut from = None;
                for (i, a) in d.args.iter().enumerate() {
                    if let Some(v) = a.strip_prefix("from=") {
                        from = Some(v.to_string());
                    } else if i == 0 {
                        mode = Some(match a.as_str() {
                            "off" => Symlinks::Off,
                            "on" => Symlinks::On,
                            "if_not_owner" => Symlinks::IfNotOwner,
                            _ => {
                                return Err(sem(
                                    &d.file,
                                    d.line,
                                    format!("invalid disable_symlinks value \"{a}\""),
                                ))
                            }
                        });
                    }
                }
                let mode = mode.ok_or_else(|| {
                    sem(&d.file, d.line, "disable_symlinks requires on|off|if_not_owner")
                })?;
                cfg.disable_symlinks = mode;
                cfg.disable_symlinks_from = from;
            }
            "resolver" => {
                // nginx allows `resolver` in http, server and location; the
                // instance is per directive, and its cache belongs to it.
                cfg.resolver = crate::resolver::Resolver::parse(&d.args, std::path::Path::new(""));
                if cfg.resolver.is_none() {
                    return Err(sem(&d.file, d.line, "invalid resolver"));
                }
            }
            "resolver_timeout" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "resolver_timeout requires a value"))?;
                cfg.resolver_timeout = Some(parse_time(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid resolver_timeout value \"{v}\""),
                    )
                })?);
            }
            "dav_methods" => {
                cfg.dav_methods = 0;
                for a in &d.args {
                    cfg.dav_methods |= match a.as_str() {
                        "PUT" => crate::dav::flags::PUT,
                        "DELETE" => crate::dav::flags::DELETE,
                        "MKCOL" => crate::dav::flags::MKCOL,
                        "COPY" => crate::dav::flags::COPY,
                        "MOVE" => crate::dav::flags::MOVE,
                        // `off` contributes nothing, which is also the default.
                        _ => 0,
                    };
                }
            }
            "dav_access" => {
                // `ngx_conf_set_access_slot`: start from 0600, and naming
                // `user:` clears those bits before they are OR-ed back in.
                let mut access = 0u32;
                let mut user = 0o600u32;
                for a in &d.args {
                    let (shift, rest) = if let Some(r) = a.strip_prefix("user:") {
                        user = 0;
                        (6u32, r)
                    } else if let Some(r) = a.strip_prefix("group:") {
                        (3u32, r)
                    } else if let Some(r) = a.strip_prefix("all:") {
                        (0u32, r)
                    } else {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid dav_access value \"{a}\""),
                        ));
                    };
                    let bits = match rest {
                        "rw" => 6u32,
                        "r" => 4u32,
                        _ => {
                            return Err(sem(
                                &d.file,
                                d.line,
                                format!("invalid dav_access value \"{a}\""),
                            ))
                        }
                    };
                    access |= bits << shift;
                }
                cfg.dav_access = access | user;
            }
            "create_full_put_path" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "create_full_put_path requires on|off"))?;
                cfg.dav_create_full_put_path = parse_on_off(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid create_full_put_path value \"{v}\""),
                    )
                })?;
            }
            "min_delete_depth" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "min_delete_depth requires a number"))?;
                cfg.dav_min_delete_depth = v.parse().map_err(|_| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid min_delete_depth value \"{v}\""),
                    )
                })?;
            }
            "secure_link" => {
                cfg.secure_link = d.args.first().cloned();
                cfg.secure_link_set = true;
            }
            "secure_link_md5" => {
                cfg.secure_link_md5 = d.args.first().cloned();
                cfg.secure_link_md5_set = true;
            }
            "secure_link_secret" => {
                cfg.secure_link_secret = d.args.first().cloned();
                cfg.secure_link_secret_set = true;
            }
            "fastcgi_catch_stderr" => {
                // nginx buffers STDERR and answers 502 when it contains one of
                // these strings (`ngx_http_fastcgi_module`'s
                // `fastcgi_catch_stderr`), which is how a PHP Fatal error is
                // turned into a gateway error instead of a half page.
                if let Some(v) = d.args.first() {
                    cfg.fastcgi_catch_stderr.push(v.clone());
                }
            }
            "fastcgi_param" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "fastcgi_param requires a name and a value",
                    ));
                }
                cfg.fastcgi_params.push(FastcgiParam {
                    name: d.args[0].clone(),
                    value: d.args[1..].join(" "),
                });
            }
            "proxy_request_buffering" | "fastcgi_request_buffering" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, format!("{} requires on|off", d.name)))?;
                let on = match v.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid value \"{v}\" in \"{}\" directive", d.name),
                        ))
                    }
                };
                if d.name == "proxy_request_buffering" {
                    cfg.proxy_request_buffering = on;
                } else {
                    cfg.fastcgi_request_buffering = on;
                }
            }
            "fastcgi_cache" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "fastcgi_cache requires a zone"))?;
                cfg.fastcgi_cache = if v == "off" { None } else { Some(v.clone()) };
            }
            "fastcgi_cache_key" => {
                cfg.fastcgi_cache_key = d.args.first().cloned();
            }
            "fastcgi_cache_valid" => {
                // `fastcgi_cache_valid [code ...] time`; a bare time means 200.
                let mut args = d.args.clone();
                let Some(time) = args.pop() else {
                    return Err(sem(&d.file, d.line, "fastcgi_cache_valid requires a time"));
                };
                let dur = parse_time(&time)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid time \"{time}\"")))?;
                let codes: Vec<u16> = if args.is_empty() {
                    vec![200]
                } else {
                    args.iter()
                        .filter_map(|c| c.parse::<u16>().ok())
                        .collect()
                };
                cfg.fastcgi_cache_valid.push((codes, dur));
            }
            "fastcgi_index" => {
                cfg.fastcgi_index = d.args.first().cloned();
            }
            "fastcgi_split_path_info" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(&d.file, d.line, "fastcgi_split_path_info requires a regex")
                })?;
                cfg.fastcgi_split_path_info = Some(
                    regex::Regex::new(v)
                        .map_err(|_| sem(&d.file, d.line, format!("invalid regex \"{v}\"")))?,
                );
            }
            "fastcgi_connect_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.fastcgi_connect_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid fastcgi_connect_timeout"))?;
                }
            }
            "fastcgi_read_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.fastcgi_read_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid fastcgi_read_timeout"))?;
                }
            }
            "uwsgi_pass" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "uwsgi_pass requires an address"))?;
                // `suwsgi://` is uwsgi over TLS: nginx strips the scheme,
                // takes the rest as the address, then wraps the connection.
                let tls = v.starts_with("suwsgi://");
                let bare = v.strip_prefix("suwsgi://").unwrap_or(v);
                let addr = parse_listen(bare)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid uwsgi_pass '{v}'")))?;
                cfg.uwsgi_pass = Some(UwsgiPass {
                    addr,
                    tls,
                    connect_timeout: Duration::from_secs(60),
                    read_timeout: Duration::from_secs(60),
                });
            }
            "uwsgi_param" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "uwsgi_param requires a name and a value",
                    ));
                }
                cfg.uwsgi_params.push(FastcgiParam {
                    name: d.args[0].clone(),
                    value: d.args[1..].join(" "),
                });
            }
            "uwsgi_connect_timeout" => {
                if let (Some(v), Some(pass)) = (d.args.first(), cfg.uwsgi_pass.as_mut()) {
                    pass.connect_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid uwsgi_connect_timeout"))?;
                }
            }
            "uwsgi_read_timeout" => {
                if let (Some(v), Some(pass)) = (d.args.first(), cfg.uwsgi_pass.as_mut()) {
                    pass.read_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid uwsgi_read_timeout"))?;
                }
            }
            "scgi_pass" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "scgi_pass requires an address"))?;
                let addr = parse_listen(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid scgi_pass \"{v}\"")))?;
                cfg.scgi_pass = Some(ScgiPass {
                    addr,
                    connect_timeout: Duration::from_secs(60),
                    read_timeout: Duration::from_secs(60),
                });
            }
            "scgi_param" => {
                if d.args.len() < 2 {
                    return Err(sem(
                        &d.file,
                        d.line,
                        "scgi_param requires a name and a value",
                    ));
                }
                cfg.scgi_params.push(FastcgiParam {
                    name: d.args[0].clone(),
                    value: d.args[1..].join(" "),
                });
            }
            "scgi_connect_timeout"
            | "scgi_read_timeout"
            | "scgi_send_timeout"
            | "scgi_buffer_size"
            | "scgi_buffers"
            | "scgi_busy_buffers_size"
            | "scgi_temp_file_write_size"
            | "scgi_max_temp_file_size"
            | "scgi_intercept_errors"
            | "scgi_pass_request_body"
            | "scgi_pass_request_headers"
            | "scgi_store"
            | "scgi_store_access"
            | "scgi_cache"
            | "scgi_cache_key"
            | "scgi_cache_valid"
            | "uwsgi_send_timeout"
            | "uwsgi_buffer_size"
            | "uwsgi_buffers"
            | "uwsgi_busy_buffers_size"
            | "uwsgi_temp_file_write_size"
            | "uwsgi_max_temp_file_size"
            | "uwsgi_intercept_errors"
            | "uwsgi_pass_request_body"
            | "uwsgi_pass_request_headers"
            | "uwsgi_modifier1"
            | "uwsgi_modifier2"
            | "uwsgi_store"
            | "uwsgi_store_access"
            | "uwsgi_cache"
            | "uwsgi_cache_key"
            | "uwsgi_cache_valid"
            | "uwsgi_ssl_server_name"
            | "uwsgi_ssl_verify" => {
                // Accepted, not yet honoured.
            }
            "uwsgi_ssl_certificate" => {
                if let Some(v) = d.args.first() {
                    cfg.uwsgi_ssl_certificate = Some(resolve_path(&self.prefix, v));
                }
            }
            "uwsgi_ssl_certificate_key" => {
                if let Some(v) = d.args.first() {
                    cfg.uwsgi_ssl_certificate_key = Some(resolve_path(&self.prefix, v));
                }
            }
            "uwsgi_ssl_password_file" => {
                if let Some(v) = d.args.first() {
                    cfg.uwsgi_ssl_password_file = Some(resolve_path(&self.prefix, v));
                }
            }
            "proxy_ssl_password_file" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_ssl_password_file = Some(resolve_path(&self.prefix, v));
                }
            }
            "proxy_ssl_certificate" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_ssl_certificate = Some(resolve_path(&self.prefix, v));
                }
            }
            "proxy_ssl_certificate_key" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_ssl_certificate_key = Some(resolve_path(&self.prefix, v));
                }
            }
            "fastcgi_send_timeout"
            | "fastcgi_buffer_size"
            | "fastcgi_buffers"
            | "fastcgi_busy_buffers_size"
            | "fastcgi_temp_file_write_size"
            | "fastcgi_max_temp_file_size"
            | "fastcgi_intercept_errors"
            | "fastcgi_pass_request_body"
            | "fastcgi_pass_request_headers"
            | "fastcgi_keep_conn"
            | "fastcgi_store"
            | "fastcgi_store_access"
            | "fastcgi_cache_no_cache"
            | "fastcgi_ignore_headers"
            | "fastcgi_hide_header" => {
                // Accepted, not yet honoured.
            }
            "proxy_cache" => {
                if let Some(v) = d.args.first() {
                    if v != "off" {
                        cfg.proxy_cache = Some(v.clone());
                    }
                }
            }
            "proxy_cookie_flags" => {
                if !cfg.cookie_flags_set {
                    cfg.proxy_cookie_flags = Some(Vec::new());
                    cfg.cookie_flags_set = true;
                }
                let list = cfg.proxy_cookie_flags.get_or_insert_with(Vec::new);
                if d.args.len() == 1 && d.args[0] == "off" {
                    list.clear();
                } else if let Some((name, rest)) = d.args.split_first() {
                    match crate::cookie::CookieFlags::parse(name, rest.to_vec()) {
                        Some(f) => list.push(f),
                        None => {
                            return Err(sem(
                                &d.file,
                                d.line,
                                "invalid pattern in proxy_cookie_flags",
                            ))
                        }
                    }
                }
            }
            "proxy_cookie_domain" | "proxy_cookie_path" => {
                let is_domain = d.name == "proxy_cookie_domain";
                let (slot, fresh) = if is_domain {
                    (&mut cfg.proxy_cookie_domains, &mut cfg.cookie_domains_set)
                } else {
                    (&mut cfg.proxy_cookie_paths, &mut cfg.cookie_paths_set)
                };
                // nginx replaces the inherited list wholesale.
                if !*fresh {
                    *slot = Some(Vec::new());
                    *fresh = true;
                }
                let list = slot.get_or_insert_with(Vec::new);
                match d.args.as_slice() {
                    [one] if one == "off" => list.clear(),
                    [from, to] => match crate::cookie::CookieRewrite::parse(from, to, is_domain) {
                        Some(rw) => list.push(rw),
                        None => {
                            return Err(sem(
                                &d.file,
                                d.line,
                                format!("invalid pattern in {}", d.name),
                            ))
                        }
                    },
                    _ => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("{} needs 2 arguments", d.name),
                        ))
                    }
                }
            }
            "proxy_ignore_headers" => {
                for a in &d.args {
                    match a.as_str() {
                        "Cache-Control" => cfg.proxy_cache_ignore.cache_control = true,
                        "Expires" => cfg.proxy_cache_ignore.expires = true,
                        "X-Accel-Expires" => cfg.proxy_cache_ignore.x_accel_expires = true,
                        "Set-Cookie" => cfg.proxy_cache_ignore.set_cookie = true,
                        "Vary" => cfg.proxy_cache_ignore.vary = true,
                        _ => {}
                    }
                }
            }
            "proxy_cache_lock" => {
                cfg.proxy_cache_lock = d.args.first().map(|v| v == "on").unwrap_or(false);
            }
            "proxy_cache_lock_timeout" | "proxy_cache_lock_age" => {
                if let Some(t) = d.args.first().and_then(|v| parse_time(v)) {
                    if d.name == "proxy_cache_lock_timeout" {
                        cfg.proxy_cache_lock_timeout = t;
                    } else {
                        cfg.proxy_cache_lock_age = t;
                    }
                }
            }
            "proxy_cache_convert_head" => {
                cfg.proxy_cache_convert_head = d.args.first().map(|v| v != "off").unwrap_or(true);
            }
            "proxy_cache_max_range_offset" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        "proxy_cache_max_range_offset requires a value",
                    )
                })?;
                cfg.proxy_cache_max_range_offset = Some(parse_size(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid proxy_cache_max_range_offset \"{v}\""),
                    )
                })?);
            }
            "proxy_limit_rate" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "proxy_limit_rate requires a value"))?;
                cfg.proxy_limit_rate = parse_size(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid proxy_limit_rate \"{v}\""))
                })?;
            }
            "proxy_intercept_errors" => {
                cfg.proxy_intercept_errors = d.args.first().map(|v| v != "off").unwrap_or(true);
            }
            "max_ranges" => {
                cfg.max_ranges = d.args.first().and_then(|v| v.parse().ok());
            }
            "proxy_force_ranges" => {
                cfg.proxy_force_ranges = d.args.first().map(|v| v != "off").unwrap_or(true);
            }
            "proxy_cache_background_update" => {
                cfg.proxy_cache_background_update =
                    d.args.first().map(|v| v != "off").unwrap_or(true);
            }
            "proxy_cache_revalidate" => {
                cfg.proxy_cache_revalidate = d.args.first().map(|v| v != "off").unwrap_or(true);
            }
            "proxy_cache_use_stale" => {
                cfg.proxy_cache_use_stale_updating =
                    d.args.iter().any(|a| a.eq_ignore_ascii_case("updating"));
                if d.args.iter().any(|a| a == "off") {
                    cfg.proxy_cache_use_stale_updating = false;
                    cfg.proxy_cache_use_stale_codes.clear();
                }
                // `error` covers any 5xx; `timeout` / `invalid_header` are
                // upstream-failure events rather than statuses. Named statuses
                // arrive as `http_404`.
                cfg.proxy_cache_use_stale_codes.clear();
                for a in &d.args {
                    if a.eq_ignore_ascii_case("error") {
                        cfg.proxy_cache_use_stale_codes.extend(500..=599);
                    } else if let Some(code) = a.strip_prefix("http_") {
                        if let Ok(c) = code.parse::<u16>() {
                            cfg.proxy_cache_use_stale_codes.push(c);
                        }
                    }
                }
            }
            "proxy_cache_methods" => {
                // Accepted; only GET/HEAD are cached, which is the default.
            }
            "proxy_cache_min_uses" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "proxy_cache_min_uses requires a value"))?;
                cfg.proxy_cache_min_uses = v.parse::<u32>().map_err(|_| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid proxy_cache_min_uses \"{v}\""),
                    )
                })?;
            }
            "proxy_cache_valid" => {
                // proxy_cache_valid [code ...] time;
                let mut codes = Vec::new();
                let mut dur = None;
                let mut any = false;
                for a in &d.args {
                    if a == "any" {
                        any = true;
                        continue;
                    }
                    match a.parse::<u16>() {
                        Ok(c) => codes.push(c),
                        Err(_) => dur = parse_time(a),
                    }
                }
                if any {
                    // `any` matches every status.
                    codes = (0u16..=999).collect();
                } else if codes.is_empty() {
                    codes = vec![200, 301, 302];
                }
                if let Some(dur) = dur {
                    cfg.proxy_cache_valid.push((codes, dur));
                }
            }
            "proxy_cache_key" => {
                cfg.proxy_cache_key = d.args.first().cloned();
            }
            "proxy_no_cache" => cfg.proxy_no_cache = d.args.clone(),
            "proxy_cache_bypass" => cfg.proxy_cache_bypass = d.args.clone(),
            "proxy_next_upstream" => cfg.proxy_next_upstream = next_upstream_flags(&d.args),
            "proxy_next_upstream_tries" => {
                cfg.proxy_next_upstream_tries =
                    d.args.first().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "proxy_next_upstream_timeout" => {
                if let Some(t) = d.args.first().and_then(|v| parse_time(v)) {
                    cfg.proxy_next_upstream_timeout = t;
                }
            }
            "grpc_next_upstream" => cfg.grpc_next_upstream = next_upstream_flags(&d.args),
            "grpc_next_upstream_tries" => {
                cfg.grpc_next_upstream_tries =
                    d.args.first().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "grpc_next_upstream_timeout" => {
                if let Some(t) = d.args.first().and_then(|v| parse_time(v)) {
                    cfg.grpc_next_upstream_timeout = t;
                }
            }
            "proxy_buffers"
            | "proxy_buffer_size"
            | "proxy_busy_buffers_size"
            | "proxy_max_temp_file_size"
            | "proxy_temp_file_write_size"
            | "proxy_redirect"
            | "proxy_cache"
            | "proxy_cache_valid"
            | "proxy_cache_key"
            | "proxy_cache_bypass"
            | "proxy_no_cache"
            | "proxy_pass_request_body"
            | "proxy_pass_request_headers"
            | "proxy_ssl_server_name"
            | "proxy_ssl_verify" => {
                // Accepted, not yet honoured.
            }
            "limit_rate" | "limit_rate_after" | "sendfile" | "tcp_nopush" | "tcp_nodelay"
            | "default_type" | "merge_slashes"
            | "open_file_cache" | "etag" | "msie_padding" => {
                // Accepted at this scope but not yet plumbed through: handled at
                // http/server level where relevant, otherwise silently accepted.
                return Ok(true);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn parse_location(&mut self, d: &Directive, parent: &LocCfg) -> Result<Location, ConfigError> {
        let block = d
            .block
            .as_ref()
            .ok_or_else(|| sem(&d.file, d.line, "location requires a block"))?;

        let matcher = match d.args.as_slice() {
            [one] if one.starts_with('@') => Match::Named(one.clone()),
            [one] => Match::Prefix(one.clone()),
            [m, v] => match m.as_str() {
                "=" => Match::Exact(v.clone()),
                "~" => Match::Regex {
                    re: build_regex(v, false)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid regex \"{v}\"")))?,
                    ci: false,
                    src: v.clone(),
                },
                "~*" => Match::Regex {
                    re: build_regex(v, true)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid regex \"{v}\"")))?,
                    ci: true,
                    src: v.clone(),
                },
                "^~" => Match::PrefixNoRegex(v.clone()),
                other => {
                    return Err(sem(
                        &d.file,
                        d.line,
                        format!("invalid location modifier \"{other}\""),
                    ))
                }
            },
            _ => return Err(sem(&d.file, d.line, "invalid location arguments")),
        };

        let mut cfg = parent.clone();
        // `sub_filter` entries accumulate, with this scope's own rules first and
        // the inherited ones after (nginx's merge order). Each rule sees the
        // previous rule's output, so getting this backwards makes a location's
        // own `sub_filter` run on an already-rewritten body.
        cfg.sub_filter_inherited = parent
            .sub_filters
            .iter()
            .chain(parent.sub_filter_inherited.iter())
            .cloned()
            .collect();
        cfg.sub_filters = Vec::new();
        // A nested location does **not** inherit `proxy_pass`. nginx only
        // creates the proxy module's location config for a location that
        // declares a directive of that module, and inheritance happens through
        // that config -- so a nested location with no proxy directive has no
        // proxy handler at all. Measured on nginx 1.28: with
        // `location /p { proxy_pass .../replacement; location /p/plain { } }`,
        // `/p/plain` is served statically (404), not proxied.
        cfg.proxy_pass = None;
        cfg.proxy_upstream_name = None;
        // `proxy_redirect` declared in this block replaces the inherited list,
        // so the raw list must start empty here. Leaving the parent's entries in
        // place made a parent's `off` outrank a child's own rule.
        cfg.proxy_redirect_src = None;
        // `secure_link*` inheritance (see the field docs). This scope's own
        // flags arrive here untouched; the parent's were consumed by its own
        // merge, so only this block's declarations matter.
        cfg.secure_link_set = false;
        cfg.secure_link_md5_set = false;
        cfg.secure_link_secret_set = false;
        // `set_real_ip_from` follows nginx's array merge: a location with no
        // directive inherits the parent's list, one with any directive replaces
        // it entirely. Clearing the "already declared" flag is what makes the
        // first directive in this scope replace instead of append -- without it
        // a nested location silently grew the parent's list.
        cfg.realip_from_set = false;
        // Cookie rewrites are replaced, not inherited-into.
        cfg.cookie_domains_set = false;
        cfg.cookie_paths_set = false;
        cfg.cookie_flags_set = false;
        cfg.prefix_len = match &matcher {
            Match::Exact(s) | Match::Prefix(s) | Match::PrefixNoRegex(s) => s.len(),
            _ => 0,
        };
        // `proxy_redirect` needs this location's own prefix, so it can only be
        // resolved here -- and only *after* the directives below are applied,
        // because `default` reads the `proxy_pass` written in this block.
        let loc_prefix = match &matcher {
            Match::Exact(s) | Match::Prefix(s) | Match::PrefixNoRegex(s) => s.clone(),
            _ => String::new(),
        };

        // Two passes: this block's own directives first, so `proxy_redirect`
        // can be resolved (it reads `proxy_pass`), then the nested locations,
        // which inherit the *resolved* list.
        for child in block.iter().filter(|c| c.name != "location") {
            if !self.apply_loc(child, &mut cfg)? {
                self.unknown(child, "location");
            }
        }
        resolve_proxy_redirects(&mut cfg, &loc_prefix);
        merge_secure_link(&mut cfg);
        let mut nested = Vec::new();
        for child in block.iter().filter(|c| c.name == "location") {
            nested.push(self.parse_location(child, &cfg)?);
        }

        Ok(Location {
            matcher,
            cfg,
            nested,
        })
    }

    fn parse_server(
        &mut self,
        d: &Directive,
        index: usize,
        http_default: &LocCfg,
        log_formats: &LogFormats,
        http_keepalive: Duration,
        http_tokens: bool,
        http_http2: bool,
        http_header_field_limit: usize,
        http_header_bufs: usize,
    ) -> Result<(Server, Vec<(ListenAddr, bool, bool, bool, bool)>), ConfigError> {
        let block = d
            .block
            .as_ref()
            .ok_or_else(|| sem(&d.file, d.line, "server requires a block"))?;

        let mut default_loc = http_default.clone();
        // The server scope has its own `sub_filter` list too; `http`-level
        // rules are inherited after it.
        default_loc.sub_filter_inherited = http_default
            .sub_filters
            .iter()
            .chain(http_default.sub_filter_inherited.iter())
            .cloned()
            .collect();
        default_loc.sub_filters = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut locations: Vec<Location> = Vec::new();
        let mut access_logs: Vec<AccessLog> = Vec::new();
        // (addr, is_default, ssl): TLS is decided per listen socket, not per
        // server — nginx lets one server block serve `listen 8081;` alongside
        // `listen 8082 ssl;`.
        let mut listens: Vec<(ListenAddr, bool, bool, bool, bool)> = Vec::new();
        let mut keepalive = http_keepalive;
        let mut tokens = http_tokens;
        let mut access_log_off = false;
        let mut server_ifs: Vec<IfBlock> = Vec::new();
        let mut server_sets: Vec<(String, String)> = Vec::new();
        let mut server_steps: Vec<Step> = Vec::new();
        let mut ssl = false;
        let mut quic = false;
        let mut http2 = http_http2;
        let mut header_field_limit = http_header_field_limit;
        let mut header_bufs = http_header_bufs;
        let mut ssl_certificate: Option<PathBuf> = None;
        let mut ssl_certificate_key: Option<PathBuf> = None;
        let mut ssl_password_file: Option<PathBuf> = None;
        let mut cert_cache = CertCacheCfg::default();
        let mut ssl_verify_client: u8 = 0;
        let mut ssl_client_certificate: Option<PathBuf> = None;
        let mut ssl_trusted_certificate: Option<PathBuf> = None;

        for child in block {
            match child.name.as_str() {
                "listen" => {
                    let addr = child
                        .args
                        .first()
                        .and_then(|a| parse_listen_any(a))
                        .ok_or_else(|| {
                            sem(
                                &child.file,
                                child.line,
                                format!(
                                    "invalid listen address \"{}\"",
                                    child.args.first().cloned().unwrap_or_default()
                                ),
                            )
                        })?;
                    let is_default = child.args[1..]
                        .iter()
                        .any(|p| p == "default_server" || p == "default");
                    let listen_ssl = child.args[1..].iter().any(|p| p == "ssl");
                    if listen_ssl {
                        ssl = true;
                    }
                    if child.args[1..].iter().any(|p| p == "http2") {
                        http2 = true;
                    }
                    // `quic` is a separate transport, not an HTTP/2 switch.
                    let quic_now = child.args[1..].iter().any(|p| p == "quic");
                    if quic_now {
                        quic = true;
                    }
                    let pp_now = child.args[1..].iter().any(|p| p == "proxy_protocol");
                    listens.push((addr, is_default, listen_ssl, quic_now, pp_now));
                }
                "server_name" => {
                    names.extend(child.args.iter().cloned());
                    default_loc.server_name = child
                        .args
                        .iter()
                        .find(|n| !n.is_empty() && !n.starts_with('~') && !n.starts_with('*'))
                        .cloned()
                        .or_else(|| child.args.first().cloned())
                        .unwrap_or_default();
                }
                "location" => {
                    let loc = self.parse_location(child, &default_loc)?;
                    locations.push(loc);
                }
                "access_log" => {
                    if child.args.first().map(|s| s.as_str()) == Some("off") {
                        access_logs.clear();
                        access_log_off = true;
                    } else if !access_log_off {
                        if let Some(mut al) = parse_access_log(&child.args, &self.prefix) {
                            let (text, esc) = resolve_format(log_formats, &al.format);
                            al.format = text;
                            al.escape = al.escape.or(Some(esc));
                            access_logs.push(al);
                        }
                    }
                }
                "keepalive_timeout" => {
                    if let Some(v) = child.args.first() {
                        keepalive = parse_time(v).ok_or_else(|| {
                            sem(&child.file, child.line, "invalid keepalive_timeout")
                        })?;
                        // Locations inherit this, and the second argument is the
                        // value for the `Keep-Alive: timeout=` header.
                        self.apply_loc(child, &mut default_loc)?;
                    }
                }
                "ssl_certificate" => {
                    if let Some(v) = child.args.first() {
                        // Certs only populate the store; TLS is enabled by
                        // `listen ... ssl`, exactly as in nginx.
                        ssl_certificate = Some(resolve_path(&self.prefix, v));
                    }
                }
                "ssl_password_file" => {
                    if let Some(v) = child.args.first() {
                        ssl_password_file = Some(resolve_path(&self.prefix, v));
                    }
                }
                "ssl_certificate_cache" => {
                    cert_cache = parse_cert_cache(&child.args, &child.file, child.line)?;
                }
                "ssl_certificate_key" => {
                    if let Some(v) = child.args.first() {
                        ssl_certificate_key = Some(resolve_path(&self.prefix, v));
                    }
                }
                "ssl_verify_client" => {
                    ssl_verify_client = match child.args.first().map(|s| s.as_str()) {
                        Some("on") => 1,
                        Some("optional") => 2,
                        Some("optional_no_ca") => 3,
                        Some("off") | None => 0,
                        Some(other) => {
                            return Err(sem(
                                &child.file,
                                child.line,
                                &format!("invalid ssl_verify_client value \"{other}\" (must be on, off, optional or optional_no_ca)"),
                            ))
                        }
                    };
                }
                "ssl_client_certificate" => {
                    if let Some(v) = child.args.first() {
                        ssl_client_certificate = Some(resolve_path(&self.prefix, v));
                    }
                }
                "ssl_trusted_certificate" => {
                    if let Some(v) = child.args.first() {
                        ssl_trusted_certificate = Some(resolve_path(&self.prefix, v));
                    }
                }
                "ssl_protocols"
                | "ssl_ciphers"
                | "ssl_prefer_server_ciphers"
                | "ssl_session_cache"
                | "ssl_session_timeout"
                | "ssl_session_tickets"
                | "ssl_dhparam"
                | "ssl_ecdh_curve"
                | "ssl_stapling"
                | "ssl_stapling_verify"
                | "ssl_buffer_size"
                | "ssl_early_data"
                | "ssl_conf_command"
                | "http2_max_field_size"
                | "http2_max_header_size"
                | "http2_idle_timeout"
                | "http2_body_preread_size"
                | "http2_chunk_size"
                | "http2_max_concurrent_streams"
                | "http2_recv_buffer_size" => {
                    // Parsed and accepted; rustls/h2 pick safe defaults.
                }
                // nginx 1.25.1+: `http2 on|off` at http/server level enables h2
                // without repeating it on every `listen`.
                "http2" => {
                    http2 = child.args.first().map(|v| v == "on").unwrap_or(true);
                }
                "large_client_header_buffers" => {
                    let num = child
                        .args
                        .first()
                        .and_then(|v| v.parse::<usize>().ok())
                        .ok_or_else(|| {
                            sem(
                                &child.file,
                                child.line,
                                "invalid large_client_header_buffers",
                            )
                        })?;
                    let size = child
                        .args
                        .get(1)
                        .and_then(|v| parse_size(v))
                        .ok_or_else(|| {
                            sem(
                                &child.file,
                                child.line,
                                "invalid large_client_header_buffers size",
                            )
                        })?;
                    header_bufs = num.max(1);
                    header_field_limit = size as usize;
                }
                "server_tokens" => {
                    if let Some(v) = child.args.first() {
                        tokens = match v.as_str() {
                            "on" | "build" => true,
                            "off" => false,
                            _ => return Err(sem(&child.file, child.line, "invalid server_tokens")),
                        };
                    }
                }
                "error_page" => {
                    self.apply_loc(child, &mut default_loc)?;
                }
                "if" | "set" => {
                    // Server-level `if`/`set` run before location selection.
                    self.apply_loc(child, &mut default_loc)?;
                    // `set` and `if` are hoisted out of the server block but
                    // must keep their relative order, so re-index the steps.
                    let moved = std::mem::take(&mut default_loc.ifs);
                    let if_base = server_ifs.len();
                    server_ifs.extend(moved);
                    let moved_sets = std::mem::take(&mut default_loc.sets);
                    let set_base = server_sets.len();
                    server_sets.extend(moved_sets);
                    for st in std::mem::take(&mut default_loc.steps) {
                        server_steps.push(match st {
                            Step::Set(i) => Step::Set(set_base + i),
                            Step::If(i) => Step::If(if_base + i),
                        });
                    }
                }
                _ => {
                    if !self.apply_loc(child, &mut default_loc)? {
                        self.unknown(child, "server");
                    }
                }
            }
        }

        let mut regex_names = Vec::new();
        let mut regex_names_src = Vec::new();
        for n in &names {
            if let Some(re) = n.strip_prefix('~') {
                if let Some(r) = build_regex(re, true) {
                    regex_names.push(r.clone());
                    regex_names_src.push((r, re.to_string()));
                } else {
                    self.warn(d, format!("invalid server_name regex \"{n}\""));
                }
            }
        }

        if listens.is_empty() {
            listens.push((
                ListenAddr::Tcp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80))),
                false,
                ssl,
                false,
                false,
            ));
        }

        // `valid_referers ... server_names` refers to this server's names, which
        // are only final now: nginx resolves it at merge time for the same
        // reason (a `server_name` may follow the location).
        let plain_names: Vec<String> = names
            .iter()
            .filter(|n| !n.starts_with('~'))
            .cloned()
            .collect();
        let regex_srcs: Vec<String> = names
            .iter()
            .filter_map(|n| n.strip_prefix('~').map(|s| s.to_string()))
            .collect();
        let resolve = |cfg: &mut LocCfg| {
            if let Some(args) = cfg.valid_referers_args.clone() {
                cfg.valid_referers = Some(crate::referer::ValidReferers::parse(
                    &args,
                    &plain_names,
                    &regex_srcs,
                ));
            }
        };
        resolve(&mut default_loc);
        fn walk_locations(locs: &mut [Location], f: &dyn Fn(&mut LocCfg)) {
            for l in locs.iter_mut() {
                f(&mut l.cfg);
                walk_locations(&mut l.nested, f);
            }
        }
        walk_locations(&mut locations, &resolve);

        Ok((
            Server {
                idx: index,
                names,
                ssl_certificate_cache: cert_cache,
                ssl_trusted_certificate,
                error_pages: default_loc.error_pages.clone(),
                default_loc,
                locations,
                access_logs,
                keepalive_timeout: keepalive,
                server_tokens: tokens,
                header_field_limit,
                header_block_limit: header_field_limit * header_bufs,
                access_log_off,
                ifs: server_ifs,
                sets: server_sets,
                steps: server_steps,
                regex_names,
                regex_names_src,
                ssl,
                ssl_certificate,
                ssl_certificate_key,
                ssl_password_file,
                ssl_verify_client,
                ssl_client_certificate,
                http2,
            },
            listens,
        ))
    }
}

/// Parse the `stream {}` block: upstreams first, then listeners.
/// A `geo [$source] $result { ... }` block, shared by `http` and `stream`.
///
/// `include` inside the block is expanded before this runs, so an included file
/// contributes ordinary `key value;` directives.
fn parse_geo(d: &Directive) -> Result<crate::geo::GeoDef, ConfigError> {
    let (source, var) = match d.args.as_slice() {
        [v] => (None, v.trim_start_matches('$').to_string()),
        [src, v] => (Some(src.clone()), v.trim_start_matches('$').to_string()),
        _ => return Err(sem(&d.file, d.line, "geo needs $variable")),
    };
    let mut def = crate::geo::GeoDef::new(source, var);
    for c in d.block.as_deref().unwrap_or(&[]) {
        match c.name.as_str() {
            "ranges" => def.set_ranges(),
            "proxy_recursive" => def.proxy_recursive = true,
            "proxy" => {
                if let Some(v) = c.args.first() {
                    def.add_proxy(v);
                }
            }
            "default" => {
                if let Some(v) = c.args.first() {
                    def.set_default(v.clone());
                }
            }
            "delete" => {
                if let Some(v) = c.args.first() {
                    def.delete(v);
                }
            }
            key => {
                if let Some(v) = c.args.first() {
                    def.add(key, v.clone());
                }
            }
        }
    }
    Ok(def)
}

/// A `split_clients $source $result { ... }` block, shared by `http` and
/// `stream`.
fn parse_split_clients(d: &Directive) -> Result<crate::split::SplitClients, ConfigError> {
    if d.args.len() < 2 {
        return Err(sem(
            &d.file,
            d.line,
            "split_clients needs $source and $result",
        ));
    }
    let mut entries: Vec<(String, String)> = Vec::new();
    for c in d.block.as_deref().unwrap_or(&[]) {
        // The percentage is the *directive name* (`51.2%` is lexed as a bare
        // token) and the value is its single argument.
        if let Some(v) = c.args.first() {
            entries.push((c.name.clone(), v.clone()));
        }
    }
    crate::split::SplitClients::parse(&d.args[0], d.args[1].trim_start_matches('$'), &entries)
        .map_err(|e| sem(&d.file, d.line, e))
}

/// A `map $source $result { ... }` block, shared by `http` and `stream`.
fn parse_map(d: &Directive) -> Result<crate::mapping::MapDef, ConfigError> {
    if d.args.len() < 2 {
        return Err(sem(&d.file, d.line, "map needs $source and $result"));
    }
    let mut def = crate::mapping::MapDef {
        source: d.args[0].clone(),
        var: d.args[1].trim_start_matches('$').to_string(),
        hostnames: false,
        volatile: false,
        default: None,
        entries: Vec::new(),
    };
    for c in d.block.as_deref().unwrap_or(&[]) {
        match c.name.as_str() {
            "hostnames" => def.hostnames = true,
            "volatile" => def.volatile = true,
            "default" => def.default = c.args.first().cloned(),
            _ => {
                // `key value;` -- the lexer already unescaped `\k`.
                if let Some(v) = c.args.first() {
                    // `\include` escapes a directive-looking key.
                    let key = c.name.strip_prefix('\\').unwrap_or(&c.name).to_string();
                    def.entries.push(crate::mapping::Entry {
                        key,
                        value: v.clone(),
                    });
                }
            }
        }
    }
    Ok(def)
}

/// `ssl_verify_client off|on|optional|optional_no_ca` in stream context.
fn verify_client_mode(d: &Directive) -> Result<u8, ConfigError> {
    match d.args.first().map(|s| s.as_str()) {
        Some("off") => Ok(0),
        Some("on") => Ok(1),
        Some("optional") => Ok(2),
        Some("optional_no_ca") => Ok(3),
        _ => Err(sem(&d.file, d.line, "invalid ssl_verify_client value")),
    }
}

fn build_stream(dirs: &[Directive], b: &mut Builder) -> Result<StreamSection, ConfigError> {
    let mut section = StreamSection::default();
    let mut server_dirs: Vec<&Directive> = Vec::new();
    // Certificates at `stream {}` level are inherited by every server.
    let mut stream_cert: Option<PathBuf> = None;
    let mut stream_key: Option<PathBuf> = None;
    let mut stream_password: Option<PathBuf> = None;
    let mut stream_verify_client: u8 = 0;
    let mut stream_client_ca: Option<PathBuf> = None;
    let mut stream_trusted: Option<PathBuf> = None;
    // `log_format` in stream context, and the stream-level `access_log`.
    let mut stream_log_formats = LogFormats::default();
    let mut stream_access_logs: Vec<AccessLog> = Vec::new();
    let mut stream_proxy_ssl = false;
    // `stream { proxy_protocol on; }`: the default every server inherits.
    let mut stream_proxy_protocol: Option<bool> = None;
    let mut stream_session_reuse = true;
    let mut stream_connect_timeout = std::time::Duration::from_secs(60);
    // nginx's stream default proxy_timeout is 10m.
    let mut stream_proxy_timeout = std::time::Duration::from_secs(600);

    for d in dirs {
        match d.name.as_str() {
            "upstream" => {
                let name = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "stream upstream requires a name"))?
                    .clone();
                // The same peer description the http balancer uses: weight,
                // backup, down, max_fails/fail_timeout and now max_conns.
                let mut servers: Vec<UpstreamServer> = Vec::new();
                let mut method = LbMethod::RoundRobin;
                let mut hash_key = String::new();
                for child in d.block.as_ref().map(|x| x.as_slice()).unwrap_or(&[]) {
                    match child.name.as_str() {
                        "least_conn" => {
                            method = LbMethod::LeastConn;
                            continue;
                        }
                        "random" => {
                            let two = child.args.first().map(|a| a == "two").unwrap_or(false);
                            let least_conn = child.args.iter().any(|a| a == "least_conn");
                            method = LbMethod::Random { two, least_conn };
                            continue;
                        }
                        "hash" => {
                            hash_key = child.args.first().cloned().unwrap_or_default();
                            let consistent =
                                child.args.get(1).map(|a| a == "consistent").unwrap_or(false);
                            method = LbMethod::Hash {
                                key: hash_key.clone(),
                                consistent,
                            };
                            continue;
                        }
                        // Accepted, no data-path meaning for a raw TCP proxy.
                        "keepalive" | "keepalive_timeout" | "keepalive_time"
                        | "keepalive_requests" | "zone" | "queue" | "resolver" => continue,
                        "server" => {}
                        _ => continue,
                    }
                    let a = child.args.first().ok_or_else(|| {
                        sem(&child.file, child.line, "server requires an address")
                    })?;
                    let mut addr = parse_listen(a).ok_or_else(|| {
                        sem(
                            &child.file,
                            child.line,
                            format!("invalid server address \"{a}\""),
                        )
                    })?;
                    if !a.contains(':') {
                        addr = SocketAddr::new(addr.ip(), 80);
                    }
                    let mut srv = UpstreamServer {
                        addr,
                        weight: 1,
                        backup: false,
                        down: false,
                        name: a.clone(),
                        max_fails: 1,
                        fail_timeout: Duration::from_secs(10),
                        max_conns: 0,
                    };
                    for p in &child.args[1..] {
                        if p == "backup" {
                            srv.backup = true;
                        } else if p == "down" {
                            srv.down = true;
                        } else if let Some(w) = p.strip_prefix("weight=") {
                            srv.weight = w.parse().unwrap_or(1).max(1);
                        } else if let Some(mf) = p.strip_prefix("max_fails=") {
                            srv.max_fails = mf.parse().unwrap_or(1);
                        } else if let Some(ft) = p.strip_prefix("fail_timeout=") {
                            if let Some(t) = parse_time(ft) {
                                srv.fail_timeout = t;
                            }
                        } else if let Some(mc) = p.strip_prefix("max_conns=") {
                            srv.max_conns = mc.parse().unwrap_or(0);
                        }
                    }
                    servers.push(srv);
                }
                if servers.is_empty() {
                    return Err(sem(&d.file, d.line, "stream upstream has no servers"));
                }
                section.upstreams.push(StreamUpstream {
                    name,
                    servers,
                    method,
                    hash_key,
                });
            }
            "server" => server_dirs.push(d),
            "geo" => section.geos.push(parse_geo(d)?),
            "map" => section.maps.push(parse_map(d)?),
            "split_clients" => section.splits.push(parse_split_clients(d)?),
            "resolver"
            | "limit_conn_zone"
            | "limit_req_zone"
            | "variables_hash_max_size"
            | "variables_hash_bucket_size"
            | "preread_buffer_size"
            | "ssl_protocols"
            | "ssl_ciphers"
            | "ssl_session_cache"
            | "ssl_session_timeout"
            | "ssl_dhparam"
            | "ssl_prefer_server_ciphers"
            | "ssl_handshake_timeout"
            | "ssl_ecdh_curve" => {}
            "error_log" => {}
            "ssl_certificate" => {
                if let Some(p) = d.args.first() {
                    stream_cert = Some(b.prefix.join(p));
                }
            }
            "ssl_certificate_key" => {
                if let Some(p) = d.args.first() {
                    stream_key = Some(b.prefix.join(p));
                }
            }
            "ssl_password_file" => {
                if let Some(p) = d.args.first() {
                    stream_password = Some(b.prefix.join(p));
                }
            }
            "log_format" => {
                if d.args.len() >= 2 {
                    let (start, esc) = match d.args.get(1).and_then(|a| a.strip_prefix("escape="))
                    {
                        Some("json") => (2, Escape::Json),
                        Some("none") => (2, Escape::None),
                        Some(_) => (2, Escape::Default),
                        None => (1, Escape::Default),
                    };
                    stream_log_formats.insert(d.args[0].clone(), d.args[start..].concat(), esc);
                }
            }
            "access_log" => {
                if d.args.first().map(|s| s.as_str()) == Some("off") {
                    stream_access_logs.clear();
                } else if let Some(mut al) = parse_access_log(&d.args, &b.prefix) {
                    let (text, esc) = resolve_format(&stream_log_formats, &al.format);
                    al.format = text;
                    al.escape = al.escape.or(Some(esc));
                    stream_access_logs.push(al);
                }
            }
            "ssl_verify_client" => {
                stream_verify_client = verify_client_mode(d)?;
            }
            "ssl_client_certificate" => {
                if let Some(p) = d.args.first() {
                    stream_client_ca = Some(b.prefix.join(p));
                }
            }
            "ssl_trusted_certificate" => {
                if let Some(p) = d.args.first() {
                    stream_trusted = Some(b.prefix.join(p));
                }
            }
            "proxy_protocol" => {
                // `stream { proxy_protocol on; }`: the inherited default.
                stream_proxy_protocol = Some(
                    d.args
                        .first()
                        .map(|v| v == "on")
                        .ok_or_else(|| sem(&d.file, d.line, "proxy_protocol requires on|off"))?,
                );
            }
            "proxy_ssl" => {
                if let Some(v) = d.args.first() {
                    match v.as_str() {
                        "on" => stream_proxy_ssl = true,
                        "off" => stream_proxy_ssl = false,
                        _ => return Err(sem(&d.file, d.line, "invalid proxy_ssl value")),
                    }
                }
            }
            "proxy_ssl_session_reuse" => {
                if let Some(v) = d.args.first() {
                    stream_session_reuse = v != "off";
                }
            }
            "proxy_connect_timeout" => {
                if let Some(v) = d.args.first() {
                    stream_connect_timeout =
                        crate::config::parse_time(v).unwrap_or(stream_connect_timeout);
                }
            }
            "proxy_timeout" => {
                if let Some(v) = d.args.first() {
                    stream_proxy_timeout =
                        crate::config::parse_time(v).unwrap_or(stream_proxy_timeout);
                }
            }
            other => b.warn(
                d,
                format!("unknown directive \"{other}\" in stream context; ignored"),
            ),
        }
    }

    for sd in server_dirs {
        let mut per_server_timeout = false;
        let mut per_server_proxy_timeout = false;
        let mut cfg = StreamServerCfg {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            udp: false,
            proxy_pass: None,
            error_logs: Vec::new(),
            ssl: false,
            ssl_certificate: None,
            ssl_certificate_key: None,
            ssl_password_file: None,
            proxy_ssl: false,
            proxy_ssl_session_reuse: true,
            proxy_ssl_name: None,
            return_text: None,
            proxy_timeout: stream_proxy_timeout,
            proxy_connect_timeout: Duration::from_secs(60),
            ssl_verify_client: stream_verify_client,
            ssl_client_certificate: stream_client_ca.clone(),
            ssl_trusted_certificate: stream_trusted.clone(),
            sets: Vec::new(),
            access_logs: stream_access_logs.clone(),
            proxy_protocol: None,
            listen_proxy_protocol: false,
        };
        let mut have_listen = false;
        // `(address, ssl)`: `listen ... ssl` is a property of the LISTENER, not of
        // the server. Sharing one `cfg.ssl` across every `listen` made a plain
        // `listen 8080` in a server that also had `listen 8443 ssl` try to
        // handshake TLS (`stream_ssl_variables.t`, "no ssl").
        let mut listens: Vec<(SocketAddr, bool)> = Vec::new();
        for child in sd.block.as_ref().map(|x| x.as_slice()).unwrap_or(&[]) {
            match child.name.as_str() {
                "listen" => {
                    let a = child.args.first().ok_or_else(|| {
                        sem(&child.file, child.line, "listen requires an address")
                    })?;
                    let addr = parse_listen(a).ok_or_else(|| {
                        sem(
                            &child.file,
                            child.line,
                            format!("invalid listen address \"{a}\""),
                        )
                    })?;
                    cfg.listen = addr;
                    let this_ssl = child.args[1..].iter().any(|p| p == "ssl");
                    listens.push((addr, this_ssl));
                    if child.args[1..].iter().any(|p| p == "udp") {
                        cfg.udp = true;
                    }
                    if this_ssl {
                        cfg.ssl = true;
                    }
                    if child.args[1..].iter().any(|p| p == "proxy_protocol") {
                        cfg.listen_proxy_protocol = true;
                    }
                    have_listen = true;
                }
                "proxy_pass" => {
                    cfg.proxy_pass = child.args.first().cloned();
                }
                "set" => {
                    if let Some(name) = child.args.first() {
                        cfg.sets.push((
                            name.trim_start_matches('$').to_string(),
                            child.args[1..].join(" "),
                        ));
                    }
                }
                "proxy_protocol" => {
                    cfg.proxy_protocol = Some(
                        child
                            .args
                            .first()
                            .map(|v| v == "on")
                            .ok_or_else(|| sem(&child.file, child.line, "proxy_protocol requires on|off"))?,
                    );
                }
                "proxy_timeout" => {
                    if let Some(v) = child.args.first() {
                        cfg.proxy_timeout = parse_time(v)
                            .ok_or_else(|| sem(&child.file, child.line, "invalid proxy_timeout"))?;
                        per_server_proxy_timeout = true;
                    }
                }
                "proxy_connect_timeout" => {
                    if let Some(v) = child.args.first() {
                        cfg.proxy_connect_timeout = parse_time(v).ok_or_else(|| {
                            sem(&child.file, child.line, "invalid proxy_connect_timeout")
                        })?;
                        per_server_timeout = true;
                    }
                }
                "return" => {
                    cfg.return_text = Some(child.args.join(" "));
                }
                "error_log" => {
                    if let Some(spec) = parse_log_spec(&b.prefix.clone(), &child.args) {
                        cfg.error_logs.push(spec);
                    }
                }
                "ssl_certificate" => {
                    if let Some(p) = child.args.first() {
                        cfg.ssl_certificate = Some(b.prefix.join(p));
                    }
                }
                "ssl_certificate_key" => {
                    if let Some(p) = child.args.first() {
                        cfg.ssl_certificate_key = Some(b.prefix.join(p));
                    }
                }
                "ssl_password_file" => {
                    if let Some(p) = child.args.first() {
                        cfg.ssl_password_file = Some(b.prefix.join(p));
                    }
                }

                "access_log" => {
                    if child.args.first().map(|s| s.as_str()) == Some("off") {
                        cfg.access_logs.clear();
                    } else if let Some(mut al) = parse_access_log(&child.args, &b.prefix) {
                        let (text, esc) = resolve_format(&stream_log_formats, &al.format);
                        al.format = text;
                        al.escape = al.escape.or(Some(esc));
                        cfg.access_logs.push(al);
                    }
                }
                "ssl_verify_client" => {
                    cfg.ssl_verify_client = verify_client_mode(child)?;
                }
                "ssl_client_certificate" => {
                    if let Some(p) = child.args.first() {
                        cfg.ssl_client_certificate = Some(b.prefix.join(p));
                    }
                }
                "ssl_trusted_certificate" => {
                    if let Some(p) = child.args.first() {
                        cfg.ssl_trusted_certificate = Some(b.prefix.join(p));
                    }
                }
                "proxy_ssl" => {
                    if let Some(v) = child.args.first() {
                        match v.as_str() {
                            "on" => cfg.proxy_ssl = true,
                            "off" => cfg.proxy_ssl = false,
                            _ => {
                                return Err(sem(&child.file, child.line, "invalid proxy_ssl value"))
                            }
                        }
                    }
                }
                "proxy_ssl_session_reuse" => {
                    if let Some(v) = child.args.first() {
                        cfg.proxy_ssl_session_reuse = v != "off";
                    }
                }
                "proxy_ssl_name" => {
                    if let Some(v) = child.args.first() {
                        cfg.proxy_ssl_name = Some(v.clone());
                    }
                }
                "proxy_protocol"
                | "proxy_buffer_size"
                | "proxy_responses"
                | "preread_buffer_size"
                | "preread_timeout"
                | "set"
                | "ssl_session_cache"
                | "ssl_session_timeout"
                | "ssl_prefer_server_ciphers"
                | "ssl_ciphers"
                | "ssl_protocols"
                | "if"
                | "proxy_ssl_server_name"
                | "proxy_ssl_verify"
                | "proxy_requests"
                | "proxy_ssl_protocols"
                | "proxy_ssl_ciphers"
                | "proxy_ssl_trusted_certificate" => {}
                other => {
                    return Err(sem(
                        &child.file,
                        child.line,
                        format!("unknown directive \"{other}\" in stream server"),
                    ))
                }
            }
        }
        if !have_listen {
            return Err(sem(&sd.file, sd.line, "stream server has no listen"));
        }
        if cfg.ssl_certificate.is_none() {
            cfg.ssl_certificate = stream_cert.clone();
        }
        if cfg.ssl_certificate_key.is_none() {
            cfg.ssl_certificate_key = stream_key.clone();
        }
        if cfg.ssl_password_file.is_none() {
            cfg.ssl_password_file = stream_password.clone();
        }
        if !cfg.proxy_ssl {
            cfg.proxy_ssl = stream_proxy_ssl;
        }
        if stream_session_reuse == false {
            cfg.proxy_ssl_session_reuse = false;
        }
        // `proxy_connect_timeout` / `proxy_timeout` set at `stream {}` level
        // apply to every server that did not override them.
        if !per_server_timeout {
            cfg.proxy_connect_timeout = stream_connect_timeout;
        }
        if !per_server_proxy_timeout {
            cfg.proxy_timeout = stream_proxy_timeout;
        }
        // A server that says nothing inherits the `stream {}` default; the
        // directive is off when neither mentions it.
        if cfg.proxy_protocol.is_none() {
            cfg.proxy_protocol = Some(stream_proxy_protocol.unwrap_or(false));
        }
        // `listen` is repeatable in a stream server, and nginx opens one socket
        // per directive. Collapsing them to one address dropped every listener
        // but the last, which is what `stream_map.t` (four `listen` lines in one
        // server) ran into.
        if listens.is_empty() {
            section.servers.push(cfg);
        } else {
            for (addr, this_ssl) in listens {
                let mut c = cfg.clone();
                c.listen = addr;
                c.ssl = this_ssl;
                section.servers.push(c);
            }
        }
    }
    Ok(section)
}

/// `ssl_certificate_cache off|max=N[inactive=time][valid=time]`.
fn parse_cert_cache(args: &[String], file: &Path, line: u32) -> Result<CertCacheCfg, ConfigError> {
    if args.len() == 1 && args[0] == "off" {
        return Ok(CertCacheCfg::default());
    }
    let mut cfg = CertCacheCfg::default();
    let mut have_max = false;
    for a in args {
        if let Some(v) = a.strip_prefix("max=") {
            cfg.max = v
                .parse()
                .map_err(|_| sem(file, line, "invalid ssl_certificate_cache max"))?;
            have_max = true;
        } else if let Some(v) = a.strip_prefix("inactive=") {
            cfg.inactive =
                Some(parse_time(v).ok_or_else(|| sem(file, line, "invalid inactive time"))?);
        } else if let Some(v) = a.strip_prefix("valid=") {
            cfg.valid = Some(parse_time(v).ok_or_else(|| sem(file, line, "invalid valid time"))?);
        }
    }
    if !have_max {
        return Err(sem(
            file,
            line,
            "ssl_certificate_cache requires max= when not off",
        ));
    }
    Ok(cfg)
}

pub fn build(
    tree: Vec<Directive>,
    prefix: &Path,
    conf_path: PathBuf,
) -> Result<Config, ConfigError> {
    let mut b = Builder {
        prefix: prefix.to_path_buf(),
        warnings: Vec::new(),
        log_formats: LogFormats::default(),
    };

    // nginx defaults to a single worker; `auto` expands to the CPU count.
    // nginx defaults to a single worker; `auto` expands to the CPU count.
    let mut worker_processes = 1usize; // 0 = auto
    let mut daemon = true;
    let mut pid: Option<PathBuf> = None;
    let mut error_log: Option<PathBuf> = None;
    let mut error_logs: Vec<LogSpec> = Vec::new();
    let mut http_roots: Vec<Directive> = Vec::new();
    let mut stream_dirs: Vec<Directive> = Vec::new();
    let mut mail_dirs: Vec<Directive> = Vec::new();
    let mut saw_http = false;

    for d in tree {
        match d.name.as_str() {
            "worker_processes" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "worker_processes requires a value"))?;
                worker_processes = if v == "auto" {
                    0
                } else {
                    v.parse::<usize>()
                        .map_err(|_| sem(&d.file, d.line, "invalid worker_processes"))?
                };
            }
            "daemon" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "daemon requires on|off"))?;
                daemon =
                    parse_on_off(v).ok_or_else(|| sem(&d.file, d.line, "invalid daemon value"))?;
            }
            "pid" => {
                if let Some(p) = d.args.first() {
                    pid = Some(resolve_path(prefix, p));
                }
            }
            "error_log" => {
                if let Some(p) = d.args.first() {
                    if p != "stderr" {
                        error_log = Some(resolve_path(prefix, p));
                    }
                }
                if let Some(spec) = parse_log_spec(&prefix, &d.args) {
                    error_logs.push(spec);
                }
            }
            "events"
            | "worker_rlimit_nofile"
            | "worker_connections"
            | "use"
            | "accept_mutex"
            | "multi_accept"
            | "worker_aio_requests" => {}
            "http" => {
                if saw_http {
                    return Err(sem(&d.file, d.line, "\"http\" directive is duplicate"));
                }
                saw_http = true;
                http_roots = d.block.clone().unwrap_or_default();
            }
            "stream" => {
                stream_dirs = d.block.clone().unwrap_or_default();
            }
            "mail" => {
                mail_dirs = d.block.clone().unwrap_or_default();
            }
            other => {
                b.warn(
                    &d,
                    format!("unknown directive \"{other}\" in main context; ignored"),
                );
            }
        }
    }

    let mut http = Http {
        charset_maps: Vec::new(),
        charsets: crate::charset::Charsets::default(),
        client_body_temp_path: PathBuf::new(),
        ssl_certificate_cache: CertCacheCfg::default(),
        ssl_certificate: None,
        ssl_certificate_key: None,
        ssl_password_file: None,
        quic_groups: Vec::new(),
        servers: Vec::new(),
        groups: Vec::new(),
        mime: MimeMap::new(),
        default_type: "text/plain".to_string(),
        keepalive_timeout: DEFAULT_KEEPALIVE,
        keepalive_requests: 1000,
        sendfile: false,
        tcp_nopush: false,
        http2: false,
        resolver: None,
        resolver_timeout: None,
        large_client_header_buffers: (4, 8192),
        tcp_nodelay: true,
        gzip: false,
        server_tokens: true,
        client_max_body_size: DEFAULT_CLIENT_MAX_BODY,
        default_loc: LocCfg::new(prefix.to_path_buf()),
        upstreams: Vec::new(),
        cache_zones: Vec::new(),
        maps: Vec::new(),
        split_clients: Vec::new(),
        geos: Vec::new(),
        limit_req_zones: Vec::new(),
        limit_conn_zones: Vec::new(),
        default_access_logs: vec![AccessLog {
            path: prefix.join("logs/access.log"),
            path_template: None,
            format: "combined".to_string(),
            if_cond: None,
            escape: Some(Escape::Default),
            cache: None,
        }],
        log_formats: LogFormats::default(),
    };

    // ---- http-level: globals first, then servers -------------------------
    let mut server_dirs: Vec<Directive> = Vec::new();
    let mut http_access_log_set = false;
    let mut upstream_index: HashMap<String, usize> = HashMap::new();

    for d in &http_roots {
        match d.name.as_str() {
            "server" => server_dirs.push(d.clone()),
            "geo" => http.geos.push(parse_geo(d)?),
            "map" => http.maps.push(parse_map(d)?),
            "split_clients" => http.split_clients.push(parse_split_clients(d)?),
            "limit_req_zone" | "limit_conn_zone" => {
                // limit_req_zone KEY zone=NAME:SIZE rate=Nr/s
                let key = d
                    .args
                    .first()
                    .cloned()
                    .ok_or_else(|| sem(&d.file, d.line, "zone requires a key"))?;
                let mut name = String::new();
                let mut rate = 0.0f64;
                for a in &d.args[1..] {
                    if let Some(v) = a.strip_prefix("zone=") {
                        name = v.split(':').next().unwrap_or("").to_string();
                    } else if let Some(v) = a.strip_prefix("rate=") {
                        rate = parse_rate_spec(v)
                            .ok_or_else(|| sem(&d.file, d.line, "invalid rate"))?;
                    }
                }
                if name.is_empty() {
                    return Err(sem(&d.file, d.line, "zone=NAME:SIZE required"));
                }
                if d.name == "limit_req_zone" {
                    http.limit_req_zones.push(LimitReqZone {
                        name,
                        key,
                        rate,
                        state: Arc::new(crate::limit::ReqZone::new(rate)),
                    });
                } else {
                    http.limit_conn_zones.push(LimitConnZone {
                        name,
                        key,
                        state: Arc::new(crate::limit::ConnZone::new()),
                    });
                }
            }
            "limit_req_status" | "limit_conn_status" => {
                let v = d
                    .args
                    .first()
                    .ok_or_else(|| sem(&d.file, d.line, "status required"))?;
                let code: u16 = v
                    .parse()
                    .map_err(|_| sem(&d.file, d.line, "invalid status"))?;
                if d.name == "limit_req_status" {
                    http.default_loc.limit_req_status = code;
                } else {
                    http.default_loc.limit_conn_status = code;
                }
            }
            "types" => {
                if let Some(block) = &d.block {
                    for t in block {
                        for ext in &t.args {
                            http.mime.insert(&t.name, ext);
                        }
                    }
                }
            }
            "charset_map" => {
                // `charset_map <src> <dst> { <hex> <hex>; ... }`. Both names are
                // registered as charsets even without a built-in table, and the
                // pairs are the *only* mapping that will exist between them.
                if d.args.len() == 2 {
                    if let Some(block) = &d.block {
                        let mut pairs = Vec::new();
                        for p in block {
                            // Our `Directive` keeps the first token as `name`,
                            // so nginx's two-element `58 59` is `name` + one arg.
                            if p.args.len() == 1 {
                                if let (Ok(from), Ok(to)) = (
                                    u8::from_str_radix(&p.name, 16),
                                    parse_hex_bytes(&p.args[0]),
                                ) {
                                    pairs.push((from, to));
                                }
                            }
                        }
                        http.charset_maps.push((
                            (d.args[0].clone(), d.args[1].clone()),
                            pairs,
                        ));
                    }
                }
            }
            "default_type" => {
                if let Some(v) = d.args.first() {
                    http.default_type = v.clone();
                }
            }
            "sendfile" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.sendfile = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid sendfile value"))?;
            }
            "tcp_nopush" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.tcp_nopush = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid tcp_nopush value"))?;
            }
            "tcp_nodelay" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.tcp_nodelay = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid tcp_nodelay value"))?;
            }
            "http2" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.http2 =
                    parse_on_off(&v).ok_or_else(|| sem(&d.file, d.line, "invalid http2 value"))?;
            }
            "resolver" => {
                http.resolver = crate::resolver::Resolver::parse(&d.args, prefix);
                if http.resolver.is_none() {
                    return Err(sem(&d.file, d.line, "invalid resolver"));
                }
            }
            "resolver_timeout" => {
                let v = d.args.first().ok_or_else(|| {
                    sem(&d.file, d.line, "resolver_timeout requires a value")
                })?;
                http.resolver_timeout = Some(parse_time(v).ok_or_else(|| {
                    sem(
                        &d.file,
                        d.line,
                        format!("invalid resolver_timeout value \"{v}\""),
                    )
                })?);
            }
            "ssl_certificate" => {
                if let Some(v) = d.args.first() {
                    http.ssl_certificate = Some(resolve_path(prefix, v));
                }
            }
            "ssl_certificate_key" => {
                if let Some(v) = d.args.first() {
                    http.ssl_certificate_key = Some(resolve_path(prefix, v));
                }
            }
            "ssl_password_file" => {
                if let Some(v) = d.args.first() {
                    http.ssl_password_file = Some(resolve_path(prefix, v));
                }
            }
            "ssl_certificate_cache" => {
                http.ssl_certificate_cache = parse_cert_cache(&d.args, &d.file, d.line)?;
            }
            "large_client_header_buffers" => {
                let num = d
                    .args
                    .first()
                    .and_then(|v| v.parse::<usize>().ok())
                    .ok_or_else(|| sem(&d.file, d.line, "invalid large_client_header_buffers"))?;
                let size = d.args.get(1).and_then(|v| parse_size(v)).ok_or_else(|| {
                    sem(&d.file, d.line, "invalid large_client_header_buffers size")
                })?;
                http.large_client_header_buffers = (num.max(1), size as usize);
            }
            "keepalive_timeout" => {
                if let Some(v) = d.args.first() {
                    http.keepalive_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid keepalive_timeout"))?;
                }
            }
            "keepalive_requests" => {
                if let Some(v) = d.args.first() {
                    http.keepalive_requests = v
                        .parse()
                        .map_err(|_| sem(&d.file, d.line, "invalid keepalive_requests"))?;
                }
            }
            "gzip" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.gzip =
                    parse_on_off(&v).ok_or_else(|| sem(&d.file, d.line, "invalid gzip value"))?;
                b.apply_loc(d, &mut http.default_loc)?;
            }
            "gzip_min_length" | "gzip_comp_level" | "gzip_types" | "gzip_vary" => {
                b.apply_loc(d, &mut http.default_loc)?;
            }
            "server_tokens" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.server_tokens = match v.as_str() {
                    "on" | "build" => true,
                    "off" => false,
                    _ => return Err(sem(&d.file, d.line, "invalid server_tokens")),
                };
            }
            "client_body_temp_path" => {
                if let Some(v) = d.args.first() {
                    http.client_body_temp_path = PathBuf::from(v);
                }
            }
            "client_body_in_file_only" => {
                if let Some(v) = d.args.first() {
                    let f = match v.as_str() {
                        "on" => Some(ClientBodyFileOnly::On),
                        "clean" => Some(ClientBodyFileOnly::Clean),
                        "off" => None,
                        _ => {
                            return Err(sem(
                                &d.file,
                                d.line,
                                format!("invalid client_body_in_file_only value \"{v}\""),
                            ))
                        }
                    };
                    http.default_loc.client_body_in_file_only = f;
                }
            }
            "client_body_buffer_size" => {
                if let Some(v) = d.args.first() {
                    http.default_loc.client_body_buffer_size =
                        parse_size(v).ok_or_else(|| sem(&d.file, d.line, "invalid size"))?;
                }
            }
            "client_max_body_size" => {
                if let Some(v) = d.args.first() {
                    http.client_max_body_size = if v == "0" {
                        u64::MAX
                    } else {
                        parse_size(v).ok_or_else(|| sem(&d.file, d.line, "invalid size"))?
                    };
                }
            }
            "log_format" => {
                if d.args.len() >= 2 {
                    let name = d.args[0].clone();
                    // `log_format name escape=json '...'`: the escape parameter
                    // is not a format string.
                    let (start, esc) = match d.args.get(1).and_then(|a| a.strip_prefix("escape=")) {
                        Some("json") => (2, Escape::Json),
                        Some("none") => (2, Escape::None),
                        Some(_) => (2, Escape::Default),
                        None => (1, Escape::Default),
                    };
                    let fmt = d.args[start..].concat();
                    http.log_formats.insert(name.clone(), fmt.clone(), esc);
                    b.log_formats.insert(name, fmt, esc);
                }
            }
            "access_log" => {
                if !http_access_log_set {
                    http.default_access_logs.clear();
                    http_access_log_set = true;
                }
                if d.args.first().map(|s| s.as_str()) == Some("off") {
                    http.default_access_logs.clear();
                } else if let Some(mut al) = parse_access_log(&d.args, prefix) {
                    let (text, esc) = resolve_format(&http.log_formats, &al.format);
                    al.format = text;
                    al.escape = al.escape.or(Some(esc));
                    http.default_access_logs.push(al);
                }
            }
            "root"
            | "index"
            | "autoindex"
            | "ssi"
            | "add_header"
            | "add_trailer"
            | "error_page"
            | "auth_basic"
            | "auth_basic_user_file"
            | "auth_request"
            | "satisfy"
            | "expires" => {
                b.apply_loc(d, &mut http.default_loc)?;
            }
            "upstream" => {
                let mut up = parse_upstream(d)?;
                if http.upstreams.iter().any(|u| u.name == up.name) {
                    return Err(sem(
                        &d.file,
                        d.line,
                        format!("duplicate upstream \"{}\"", up.name),
                    ));
                }
                // preserve declaration order for stable round-robin indices
                up.name = up.name.clone();
                upstream_index.insert(up.name.clone(), http.upstreams.len());
                http.upstreams.push(up);
            }
            // `proxy_cache_path` and `fastcgi_cache_path` take exactly the same
            // arguments and register into the same zone table: nginx's zones are
            // keyed by name, and one zone may be shared by both modules.
            "proxy_cache_path" | "fastcgi_cache_path" => {
                let zone = parse_cache_zone(d, prefix)?;
                http.cache_zones.push(zone);
            }
            "location"
            | "if"
            | "map"
            | "resolver"
            | "geo"
            | "split_clients"
            | "limit_req_zone"
            | "limit_conn_zone"
            | "proxy_cache_path"
            | "charset"
            | "log_format_escape"
            | "types_hash_max_size"
            | "server_names_hash_bucket_size"
            | "open_file_cache"
            | "access_log_off"
            | "default_type_off" => {
                if d.name == "map"
                    || d.name == "limit_req_zone"
                    || d.name == "geo"
                    || d.name == "split_clients"
                {
                    b.warn(
                        d,
                        format!("directive \"{}\" is not implemented yet; ignored", d.name),
                    );
                }
            }
            _ => {
                if !b.apply_loc(d, &mut http.default_loc)? {
                    b.unknown(d, "http");
                }
            }
        }
    }

    let mut groups: BTreeMap<String, ListenGroup> = BTreeMap::new();
    let mut listens_by_server: Vec<(usize, Vec<(ListenAddr, bool, bool, bool, bool)>)> = Vec::new();

    for (i, sd) in server_dirs.iter().enumerate() {
        let (server, listens) = b.parse_server(
            sd,
            i,
            &http.default_loc,
            &http.log_formats,
            http.keepalive_timeout,
            http.server_tokens,
            http.http2,
            http.large_client_header_buffers.1,
            http.large_client_header_buffers.0,
        )?;
        // Certificates declared in the `http` block are inherited by servers
        // that do not override them.
        let mut server = server;
        if server.ssl_certificate.is_none() {
            server.ssl_certificate = http.ssl_certificate.clone();
        }
        if server.ssl_certificate_key.is_none() {
            server.ssl_certificate_key = http.ssl_certificate_key.clone();
        }
        if server.ssl_password_file.is_none() {
            server.ssl_password_file = http.ssl_password_file.clone();
        }
        if server.ssl_certificate_cache == CertCacheCfg::default() {
            server.ssl_certificate_cache = http.ssl_certificate_cache.clone();
        }
        if server.names.is_empty() {
            // nginx default server_name is ""
        }
        listens_by_server.push((i, listens.clone()));
        http.servers.push(server);
    }

    {
        let defaults = http.default_access_logs.clone();
        for s in &mut http.servers {
            if !s.access_log_off && s.access_logs.is_empty() {
                s.access_logs = defaults.clone();
            }
        }
    }

    resolve_proxy_upstreams(&mut http)?;

    // QUIC lives on UDP, so `<port>/tcp` and `<port>/udp` are distinct
    // sockets; keying both by port would merge them.
    let mut quic_groups: BTreeMap<String, ListenGroup> = BTreeMap::new();

    for (idx, listens) in listens_by_server {
        for (addr, is_default, listen_ssl, listen_quic, listen_pp) in listens {
            let table: &mut BTreeMap<String, ListenGroup> = if listen_quic {
                &mut quic_groups
            } else {
                &mut groups
            };
            // nginx groups servers by *listening socket*, i.e. by address and
            // port together: `listen 127.0.0.1:8081` and `listen [::1]:8081`
            // are two sockets even though they share a port. Keying by port
            // alone silently dropped one of them.
            let (key, tcp_addr, unix) = match &addr {
                ListenAddr::Tcp(a) => (format!("tcp:{a}"), *a, None),
                ListenAddr::Unix(p) => (
                    format!("unix:{}", p.display()),
                    UNIX_PLACEHOLDER,
                    Some(p.clone()),
                ),
            };
            let group = table.entry(key).or_insert_with(|| ListenGroup {
                addr: tcp_addr,
                unix,
                servers: Vec::new(),
                default_server: 0,
                ssl: listen_ssl,
                quic: listen_quic,
                proxy_protocol: listen_pp,
            });
            if let ListenAddr::Tcp(a) = &addr {
                if a.ip().is_unspecified() {
                    group.addr = *a;
                }
            }
            if !group.servers.contains(&idx) {
                group.servers.push(idx);
            }
            if is_default {
                group.default_server = idx;
            }
            if listen_ssl {
                group.ssl = true;
            }
        }
    }

    for (_port, mut g) in groups {
        if !g.servers.contains(&g.default_server) {
            // keep nginx's "first server on this address" default
            g.default_server = g.servers[0];
        }
        http.groups.push(g);
    }
    for (_port, mut g) in quic_groups {
        if !g.servers.contains(&g.default_server) {
            g.default_server = g.servers[0];
        }
        http.quic_groups.push(g);
    }

    // A config may legitimately have no `http {}` at all (mail-only or
    // stream-only), so only reject when every module is empty.
    let stream = build_stream(&stream_dirs, &mut b)?;
    let mail_servers_probe = b.parse_mail(&mail_dirs)?;
    if http.groups.is_empty() && stream.servers.is_empty() && mail_servers_probe.is_empty() {
        return Err(sem(&conf_path, 0, "no server listen sockets configured"));
    }

    // nginx defaults to `<prefix>/logs/nginx.pid` and `<prefix>/logs/error.log`.
    let pid = Some(pid.unwrap_or_else(|| prefix.join("logs/nginx.pid")));
    let error_log = Some(error_log.unwrap_or_else(|| prefix.join("logs/error.log")));

    // nginx defaults `client_body_temp_path` to `<prefix>/client_body_temp`.
    if http.client_body_temp_path.as_os_str().is_empty() {
        http.client_body_temp_path = prefix.join("client_body_temp");
    }

    // The `charset_map` blocks become the runtime registry here, once every
    // block has been seen.
    build_charsets(&mut http);

    crate::config::set_maps(http.maps.clone());
    crate::config::set_splits(http.split_clients.clone());
    crate::config::set_geos(http.geos.clone());

    Ok(Config {
        prefix: prefix.to_path_buf(),
        conf_path,
        worker_processes,
        daemon,
        pid,
        error_log,
        error_logs,
        http,
        stream,
        mail_servers: mail_servers_probe,
        warnings: b.warnings,
    })
}

impl Location {
    /// nginx syntax for this location's matcher, used by `-T`.
    pub fn pattern(&self) -> String {
        match &self.matcher {
            Match::Exact(s) => format!("= {s}"),
            Match::Prefix(s) => s.clone(),
            Match::PrefixNoRegex(s) => format!("^~ {s}"),
            Match::Regex { src, ci, .. } => {
                if *ci {
                    format!("~* {src}")
                } else {
                    format!("~ {src}")
                }
            }
            Match::Named(s) => s.clone(),
        }
    }
}

impl Server {
    /// `$server_name`: the first configured name, as nginx reports it.
    pub fn name_display(&self) -> &str {
        self.names.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// nginx's `auto_redirect`: a request for `/foo` is answered with a 301 to
    /// `/foo/` when a location named `/foo/` exists.
    pub fn auto_redirect(&self, path: &str) -> Option<String> {
        if path.ends_with('/') {
            return None;
        }
        let mut want = String::with_capacity(path.len() + 1);
        want.push_str(path);
        want.push('/');
        fn has(locs: &[Location], want: &str) -> bool {
            for l in locs {
                match &l.matcher {
                    Match::Prefix(p) | Match::PrefixNoRegex(p) if p == want => return true,
                    _ => {}
                }
                if has(&l.nested, want) {
                    return true;
                }
            }
            false
        }
        if has(&self.locations, &want) {
            Some(want)
        } else {
            None
        }
    }

    pub fn locate(&self, path: &str) -> &LocCfg {
        match match_list(&self.locations, path) {
            Some(c) => c,
            None => &self.default_loc,
        }
    }

    /// `locate`, plus the captures of the winning regex location.
    ///
    /// nginx stores them in `r->captures`, which makes `$1`..`$9` and any named
    /// group usable in `proxy_pass`, `fastcgi_param`, `add_header` and so on.
    /// `match_list` only returns the config, so the winning `Location` is found
    /// again here.
    pub fn locate_with_captures(&self, path: &str) -> (&LocCfg, Vec<(String, String)>) {
        let cfg = self.locate(path);
        let mut caps = Vec::new();
        if let Some(l) = find_location(&self.locations, path, cfg) {
            if let Match::Regex { re, .. } = &l.matcher {
                if let Some(c) = re.captures(path) {
                    for i in 1..10 {
                        if let Some(m) = c.get(i) {
                            caps.push((i.to_string(), m.as_str().to_string()));
                        }
                    }
                    for name in re.capture_names().flatten() {
                        if let Some(m) = c.name(name) {
                            caps.push((name.to_string(), m.as_str().to_string()));
                        }
                    }
                }
            }
        }
        (cfg, caps)
    }

    /// Resolve a named location (`location @fallback { ... }`), which nginx uses
    /// as an `error_page` target. Named locations never take part in prefix or
    /// regex matching.
    pub fn locate_named(&self, name: &str) -> Option<&LocCfg> {
        self.locations.iter().find_map(|l| match &l.matcher {
            Match::Named(n) if n == name => Some(&l.cfg),
            _ => None,
        })
    }
}

/// Find the `Location` whose config `match_list` selected. Mirrors its order so
/// the two cannot disagree.
fn find_location<'a>(list: &'a [Location], path: &str, want: &LocCfg) -> Option<&'a Location> {
    let mut best: Option<&'a Location> = None;
    for l in list {
        match &l.matcher {
            Match::Exact(s) if s == path => return Some(l),
            Match::Prefix(s) | Match::PrefixNoRegex(s) => {
                if path.starts_with(s.as_str())
                    && best.map_or(true, |b| prefix_of(&b.matcher).len() < s.len())
                {
                    best = Some(l);
                }
            }
            _ => {}
        }
    }
    if let Some(b) = best {
        if let Some(child) = find_location(&b.nested, path, want) {
            return Some(child);
        }
        if matches!(b.matcher, Match::PrefixNoRegex(_)) {
            return Some(b);
        }
        if std::ptr::eq(&b.cfg, want) && !has_regex_child(&b.nested, path) {
            return Some(b);
        }
    }
    for l in list {
        if let Match::Regex { re, .. } = &l.matcher {
            if re.is_match(path) {
                if let Some(child) = find_location(&l.nested, path, want) {
                    return Some(child);
                }
                return Some(l);
            }
        }
    }
    best
}

fn has_regex_child(list: &[Location], path: &str) -> bool {
    list.iter().any(|l| match &l.matcher {
        Match::Regex { re, .. } => re.is_match(path) || has_regex_child(&l.nested, path),
        Match::Prefix(s) | Match::PrefixNoRegex(s) => {
            path.starts_with(s.as_str()) && has_regex_child(&l.nested, path)
        }
        _ => false,
    })
}

fn match_list<'a>(list: &'a [Location], path: &str) -> Option<&'a LocCfg> {
    let mut best: Option<&'a Location> = None;
    for l in list {
        match &l.matcher {
            Match::Exact(s) if s == path => return Some(&l.cfg),
            Match::Prefix(s) | Match::PrefixNoRegex(s) => {
                if path.starts_with(s.as_str())
                    && best.map_or(true, |b| prefix_of(&b.matcher).len() < s.len())
                {
                    best = Some(l);
                }
            }
            _ => {}
        }
    }

    if let Some(b) = best {
        if let Some(child) = match_list(&b.nested, path) {
            return Some(child);
        }
        if matches!(b.matcher, Match::PrefixNoRegex(_)) {
            return Some(&b.cfg);
        }
    }

    for l in list {
        if let Match::Regex { re, .. } = &l.matcher {
            if re.is_match(path) {
                if let Some(child) = match_list(&l.nested, path) {
                    return Some(child);
                }
                return Some(&l.cfg);
            }
        }
    }

    best.map(|b| &b.cfg)
}

fn prefix_of(m: &Match) -> &str {
    match m {
        Match::Exact(s) | Match::Prefix(s) | Match::PrefixNoRegex(s) => s,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_times() {
        assert_eq!(parse_size("10k"), Some(10240));
        assert_eq!(parse_size("1m"), Some(1048576));
        assert_eq!(parse_time("65s").unwrap().as_secs(), 65);
        assert_eq!(parse_time("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_time("100").unwrap().as_millis(), 100_000);
    }

    #[test]
    fn listen_forms() {
        assert_eq!(
            parse_listen("8080"),
            Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)))
        );
        assert_eq!(
            parse_listen("127.0.0.1:8081"),
            Some(SocketAddr::from(([127, 0, 0, 1], 8081)))
        );
        assert_eq!(
            parse_listen("*:8082"),
            Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8082)))
        );
        assert_eq!(
            parse_listen("[::]:8083"),
            Some(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 8083)))
        );
    }

    #[test]
    fn realip_from_forms() {
        // Literal, CIDR, hostname (resolved through getaddrinfo) and `unix:`
        // are the four shapes nginx accepts.
        assert_eq!(
            resolve_realip_from("192.0.2.1").unwrap(),
            vec![(std::net::IpAddr::from([192, 0, 2, 1]), 32)]
        );
        assert_eq!(
            resolve_realip_from("192.0.2.0/24").unwrap(),
            vec![(std::net::IpAddr::from([192, 0, 2, 0]), 24)]
        );
        let local = resolve_realip_from("localhost").unwrap();
        assert!(local.contains(&(std::net::IpAddr::from([127, 0, 0, 1]), 32)));
        assert!(local.iter().all(|(_, b)| *b == 32 || *b == 128));
        // A name that does not resolve is reported, not silently dropped.
        assert!(resolve_realip_from("no-such-host.invalid").is_err());
        assert!(resolve_realip_from("").is_err());
    }

    #[test]
    fn realip_unix_is_not_an_address() {
        let c = build_from(
            "events {}\nhttp { server { listen 8080; location / {\n\
             set_real_ip_from unix:;\n\
             set_real_ip_from 10.0.0.0/8;\n\
             location /nested { set_real_ip_from 127.0.0.1; }\n\
             } } }\n",
        );
        let loc = &c.http.servers[0].locations[0].cfg;
        assert!(loc.realip_from_unix);
        assert_eq!(loc.realip_from, vec![(std::net::IpAddr::from([10, 0, 0, 0]), 8)]);
        // A nested scope that declares any `set_real_ip_from` replaces the
        // inherited list as a whole, `unix:` entries included.
        let nested = &c.http.servers[0].locations[0].nested[0].cfg;
        assert!(!nested.realip_from_unix);
        assert_eq!(
            nested.realip_from,
            vec![(std::net::IpAddr::from([127, 0, 0, 1]), 32)]
        );
    }

    fn build_from(src: &str) -> Config {
        let tree = super::super::parser::parse_str(Path::new("t.conf"), src).unwrap();
        build(tree, Path::new("/prefix"), PathBuf::from("t.conf")).unwrap()
    }

    #[test]
    fn location_matching_order() {
        let cfg = build_from(
            r#"
            events {}
            http {
              server {
                listen 8080;
                location / { return 200 "root"; }
                location /api/ { return 200 "api"; }
                location = /exact { return 200 "exact"; }
                location ~ \.php$ { return 200 "php"; }
                location ^~ /static/ { return 200 "static"; }
                location ~ ^/static/x { return 200 "regex-static"; }
              }
            }
        "#,
        );
        let s = &cfg.http.servers[0];
        assert_eq!(s.locate("/api/x").ret.as_ref().unwrap().1, "api");
        assert_eq!(s.locate("/exact").ret.as_ref().unwrap().1, "exact");
        assert_eq!(s.locate("/a.php").ret.as_ref().unwrap().1, "php");
        assert_eq!(s.locate("/static/x").ret.as_ref().unwrap().1, "static");
        assert_eq!(s.locate("/other").ret.as_ref().unwrap().1, "root");
    }
}

/// Turn the raw `proxy_redirect` arguments into rules.
///
/// `default` is nginx's mapping from the proxy_pass URL back to the location
/// prefix: `http://<host_header><proxy_pass uri>` -> `<location prefix>`. It is
/// also what applies when the directive is absent entirely.
fn resolve_proxy_redirects(cfg: &mut LocCfg, prefix: &str) {
    let Some(src) = cfg.proxy_redirect_src.clone() else {
        // Not declared here: inherit whatever the parent resolved, except that
        // a location with none anywhere still gets nginx's implicit `default`.
        if cfg.proxy_redirects.is_empty() {
            cfg.proxy_redirects = implicit_default(cfg, prefix);
        }
        return;
    };
    let mut out: Vec<RedirectRule> = Vec::new();
    for entry in src {
        let first = entry.first().map(|s| s.as_str()).unwrap_or("");
        if first == "off" {
            out.clear();
            out.push(RedirectRule::Off);
            break;
        }
        if first == "default" {
            if let Some(pp) = &cfg.proxy_pass {
                let from = match &pp.uri {
                    Some(u) => format!("{}{}", scheme_of(pp), u),
                    None => format!("{}/", scheme_of(pp)),
                };
                out.push(RedirectRule::Prefix {
                    from,
                    to: prefix.to_string(),
                });
            }
            continue;
        }
        let second = entry.get(1).cloned().unwrap_or_default();
        if let Some(body) = first.strip_prefix("~*") {
            if let Some(re) = build_regex(body, true) {
                out.push(RedirectRule::Regex { re, to: second });
            }
        } else if let Some(body) = first.strip_prefix('~') {
            if let Some(re) = build_regex(body, false) {
                out.push(RedirectRule::Regex { re, to: second });
            }
        } else {
            out.push(RedirectRule::Prefix {
                from: first.to_string(),
                to: second,
            });
        }
    }
    if out.is_empty() {
        out = implicit_default(cfg, prefix);
    }
    cfg.proxy_redirects = out;
}

/// `http://` or `https://` followed by the authority, which is how nginx writes
/// the `from` side of a `proxy_redirect` rule.
fn scheme_of(pp: &ProxyPass) -> String {
    format!(
        "{}://{}",
        if pp.https { "https" } else { "http" },
        pp.host_header
    )
}

/// nginx's implicit `proxy_redirect default`. It only applies when `proxy_pass`
/// carries a URI part; `proxy_redirect default` is explicitly invalid otherwise.
fn implicit_default(cfg: &LocCfg, prefix: &str) -> Vec<RedirectRule> {
    match (&cfg.proxy_pass, prefix.is_empty()) {
        (Some(pp), false) => match &pp.uri {
            Some(u) if !u.contains('$') => vec![RedirectRule::Prefix {
                from: format!("{}{}", scheme_of(pp), u),
                to: prefix.to_string(),
            }],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Decode the hex byte string on the right-hand side of a `charset_map` pair
/// (`58` -> [0x58], `0410` -> [0xD0, 0x90]).
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, ()> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).ok_or(())?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or(())?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// `*_cache_path <path> [levels=..] [keys_zone=name:size] [max_size=..]
/// [inactive=..]`. Shared by the proxy and fastcgi variants, which are
/// argument-for-argument identical.
fn parse_cache_zone(d: &Directive, prefix: &Path) -> Result<CacheZone, ConfigError> {
    let path_arg = d
        .args
        .first()
        .ok_or_else(|| sem(&d.file, d.line, format!("{} requires a path", d.name)))?;
    let mut zone = CacheZone {
        lock: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        uses: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        name: String::new(),
        path: resolve_path(prefix, path_arg),
        max_size: 1024 * 1024 * 1024,
        inactive: Duration::from_secs(600),
        levels: None,
    };
    for a in &d.args[1..] {
        if let Some(v) = a.strip_prefix("keys_zone=") {
            zone.name = v.split(':').next().unwrap_or(v).to_string();
        } else if let Some(v) = a.strip_prefix("max_size=") {
            if let Some(n) = parse_size(v) {
                zone.max_size = n;
            }
        } else if let Some(v) = a.strip_prefix("inactive=") {
            if let Some(t) = parse_time(v) {
                zone.inactive = t;
            }
        } else if let Some(v) = a.strip_prefix("levels=") {
            zone.levels = Some(v.to_string());
        }
    }
    if zone.name.is_empty() {
        return Err(sem(
            &d.file,
            d.line,
            format!("{} requires keys_zone=name:size", d.name),
        ));
    }
    Ok(zone)
}
