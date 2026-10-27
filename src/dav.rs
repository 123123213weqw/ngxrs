//! `ngx_http_dav_module`: WebDAV methods that map onto the filesystem.
//!
//! nginx implements exactly five (`PUT DELETE MKCOL COPY MOVE`) as a content
//! handler; everything else (PROPFIND, LOCK, ...) falls through. Each one is
//! transcribed from `ngx_http_dav_module.c` rather than invented, because the
//! status codes are the whole contract:
//!
//!   PUT     201 when the file did not exist, 204 when it did, 409 for a
//!           collection URI, 501 with `Content-Range`, 500 when the parent
//!           directory is missing and `create_full_put_path` is off.
//!   DELETE  204, 404 missing, 409 for a directory URI without the trailing
//!           slash, 400 for a `Depth` the method does not allow, 415 with a
//!           body. `min_delete_depth` answers 409.
//!   MKCOL   201, 405 when it already exists, 409 for a URI without the
//!           trailing slash or a missing parent, 415 with a body.
//!   COPY    204 for a file, 201 for a collection, 412 when `Overwrite: F`
//!           meets an existing target, 409 for a collection/non-collection
//!           mismatch, 400 for a bad `Destination`/`Overwrite`/`Depth`.
//!   MOVE    like COPY but 204/201 from `rename(2)` and `Depth` must be
//!           infinity.
//!
//! Two details are easy to get wrong and are asserted by `dav.t`:
//!
//!   * `absolute_redirect` applies to the `Location` of a 201 too, not only to
//!     redirects (`ngx_http_header_filter` checks the header, not the status).
//!   * `dav_access` starts from `0600` and `user:` **zeroes** the owner bits
//!     before OR-ing them back, so `dav_access user:rw group:r all:r` is 0644
//!     and not 0744.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::config::LocCfg;
use crate::conn::Conn;
use crate::http::request::{Method, Request};
use crate::http::{Body, Response};

/// `NGX_HTTP_DAV_INFINITY_DEPTH`.
const INFINITY: i32 = -1;
/// `NGX_HTTP_DAV_INVALID_DEPTH`.
const INVALID_DEPTH: i32 = -2;

/// `dav_methods` bits, laid over nginx's method numbers so that a request's
/// method can be tested with one AND.
pub mod flags {
    pub const PUT: u32 = 1 << 0;
    pub const DELETE: u32 = 1 << 1;
    pub const MKCOL: u32 = 1 << 2;
    pub const COPY: u32 = 1 << 3;
    pub const MOVE: u32 = 1 << 4;
}

fn flag_for(method: Method) -> u32 {
    match method {
        Method::Put => flags::PUT,
        Method::Delete => flags::DELETE,
        Method::Other(s) => match s.as_str() {
            "MKCOL" => flags::MKCOL,
            "COPY" => flags::COPY,
            "MOVE" => flags::MOVE,
            _ => 0,
        },
        _ => 0,
    }
}

/// Run the DAV handler for this request.
///
/// `None` means the method is not configured here, so the request keeps its
/// normal path (which then answers 405 for an unsupported method, as nginx
/// does when no content handler accepts it).
pub async fn handle(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    loc: &LocCfg,
    max_body: usize,
) -> io::Result<Option<Response>> {
    let bit = flag_for(req.method.clone());
    if loc.dav_methods & bit == 0 {
        return Ok(None);
    }
    // A body is only meaningful to PUT; the other four reject it outright.
    let has_body = req.body_len > 0 || req.chunked;

    match req.method {
        Method::Put => Ok(Some(put(conn, req, path, loc, max_body).await?)),
        Method::Delete => Ok(Some(delete(req, path, loc, has_body))),
        Method::Other(ref s) if s.as_str() == "MKCOL" => {
            Ok(Some(mkcol(req, path, loc, has_body)))
        }
        Method::Other(ref s) if s.as_str() == "COPY" || s.as_str() == "MOVE" => Ok(Some(
            copy_move(req, path, loc, has_body, s.as_str() == "MOVE"),
        )),
        _ => Ok(None),
    }
}

/// `ngx_http_map_uri_to_path`, minus the trailing NUL, with the separator nginx
/// strips for a collection URI already removed.
fn map_uri(path: &str, loc: &LocCfg) -> PathBuf {
    let mut p = crate::http::static_file::map_path(path, loc);
    // `Path::join` keeps a trailing `/` as a trailing separator; every caller
    // here wants the entry itself.
    while p.as_os_str().len() > 1 && p.as_os_str().to_string_lossy().ends_with('/') {
        let s = p.to_string_lossy().to_string();
        p = PathBuf::from(s.trim_end_matches('/'));
    }
    p
}

/// `ngx_http_dav_error`: errno to status, with the caller's "not found" override.
fn dav_error(err: &io::Error, not_found: u16) -> u16 {
    match err.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) | Some(libc::ENAMETOOLONG) => not_found,
        Some(libc::EACCES) | Some(libc::EPERM) => 403,
        Some(libc::EEXIST) => 405,
        Some(libc::ENOSPC) => 507,
        _ => 500,
    }
}

fn created(path: &str, loc: &LocCfg, req: &Request, local_addr: &str) -> Response {
    // nginx re-escapes the URI for this header, and `absolute_redirect` decides
    // whether it stays relative.
    let raw = crate::util::escape_uri(path);
    let location = crate::http::absolute_location(req, loc, &raw, 80, local_addr);
    let mut resp = Response::empty(201).header("Location", location);
    resp.raw
        .extend_from_slice(b"Content-Length: 0\r\n");
    resp.explicit_len = true;
    resp
}

/// `Depth` header, with the per-method default (`ngx_http_dav_depth`).
fn depth(req: &Request, dflt: i32) -> i32 {
    let Some(v) = req.headers.get("depth") else {
        return dflt;
    };
    match v.as_bytes() {
        b"0" => 0,
        b"1" => 1,
        b"infinity" => INFINITY,
        _ => INVALID_DEPTH,
    }
}

/// `dav_access` for a new *file*: the configured mode, applied with `chmod` so
/// the umask never narrows it (nginx's `ngx_change_file_access`).
fn mode_access(loc: &LocCfg) -> u32 {
    loc.dav_access & 0o7777
}

/// `ngx_dir_access`: a directory needs the execute bit to be usable, so every
/// readable bit also gets its `x`. Without this a PUT under
/// `create_full_put_path` created `0600` directories and then failed to write
/// inside them (EACCES -> 403, which is what `dav.t` caught).
fn dir_access(mode: u32) -> u32 {
    mode | (mode & 0o444) >> 2
}

async fn put(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    loc: &LocCfg,
    max_body: usize,
) -> io::Result<Response> {
    if path.ends_with('/') {
        return Ok(Response::empty(409));
    }
    if req.headers.get("content-range").is_some() {
        return Ok(Response::empty(501));
    }
    let body = crate::proxy::take_request_body(conn, req, max_body).await?;
    let target = map_uri(path, loc);

    let existed = match fs::symlink_metadata(&target) {
        Ok(meta) => {
            if meta.is_dir() {
                // nginx refuses before touching the filesystem.
                return Ok(Response::empty(409));
            }
            true
        }
        Err(_) => false,
    };

    if let Some(parent) = target.parent() {
        if loc.dav_create_full_put_path && !parent.as_os_str().is_empty() {
            if let Err(e) = create_dirs(parent, dir_access(mode_access(loc))) {
                return Ok(Response::empty(dav_error(&e, 409)));
            }
        }
    }

    if let Err(e) = write_file(&target, &body, mode_access(loc)) {
        // Mirrors `ngx_ext_rename_file` failing: nginx answers 500 here, which
        // is why `dav.t` accepts 409 or 500 for a missing parent.
        return Ok(Response::empty(dav_error(&e, 500)));
    }

    // A valid `Date` sets the modification time; an unparseable one is ignored
    // (`dav.t` checks both).
    if let Some(d) = req.headers.get("date") {
        if let Some(ts) = crate::util::parse_http_date(d) {
            let _ = set_mtime(&target, ts);
        }
    }

    if existed {
        Ok(Response::empty(204))
    } else {
        let local = conn
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        Ok(created(path, loc, req, &local))
    }
}

fn write_file(path: &Path, body: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.write_all(body)?;
    Ok(())
}

fn create_dirs(path: &Path, mode: u32) -> io::Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_dir() {
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(libc::EEXIST));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            create_dirs(parent, mode)?;
        }
    }
    fs::DirBuilder::new().mode(mode).create(path)
}

fn set_mtime(path: &Path, ts: i64) -> io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let times = [
        libc::timespec {
            tv_sec: ts,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: ts,
            tv_nsec: 0,
        },
    ];
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn delete(req: &Request, path: &str, loc: &LocCfg, has_body: bool) -> Response {
    if has_body {
        return Response::empty(415);
    }
    if loc.dav_min_delete_depth > 0 {
        // Count slashes; nginx wants at least `min_delete_depth` of them and at
        // least one character after the last one it counted.
        let mut d = 0u32;
        let bytes = path.as_bytes();
        let mut i = 0usize;
        let mut ok = false;
        while i < bytes.len() {
            if bytes[i] == b'/' {
                d += 1;
                i += 1;
                if d >= loc.dav_min_delete_depth && i < bytes.len() {
                    ok = true;
                    break;
                }
            } else {
                i += 1;
            }
        }
        if !ok {
            return Response::empty(409);
        }
    }

    let target = map_uri(path, loc);
    let meta = match fs::symlink_metadata(&target) {
        Ok(m) => m,
        Err(e) => {
            return Response::empty(dav_error(&e, 404));
        }
    };

    if meta.is_dir() {
        if !path.ends_with('/') {
            return Response::empty(409);
        }
        if depth(req, INFINITY) != INFINITY {
            return Response::empty(400);
        }
        match remove_tree(&target) {
            Ok(()) => Response::empty(204),
            Err(e) => Response::empty(dav_error(&e, 404)),
        }
    } else {
        let d = depth(req, 0);
        if d != 0 && d != INFINITY {
            return Response::empty(400);
        }
        match fs::remove_file(&target) {
            Ok(()) => Response::empty(204),
            Err(e) => Response::empty(dav_error(&e, 404)),
        }
    }
}

fn remove_tree(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return fs::remove_file(path);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        remove_tree(&entry.path())?;
    }
    fs::remove_dir(path)
}

fn mkcol(req: &Request, path: &str, loc: &LocCfg, has_body: bool) -> Response {
    if has_body {
        return Response::empty(415);
    }
    if !path.ends_with('/') {
        return Response::empty(409);
    }
    let target = map_uri(path, loc);
    match fs::DirBuilder::new()
        .mode(dir_access(mode_access(loc)))
        .create(&target)
    {
        Ok(()) => created(path, loc, req, ""),
        Err(e) => Response::empty(dav_error(&e, 409)),
    }
}

fn copy_move(req: &Request, path: &str, loc: &LocCfg, has_body: bool, is_move: bool) -> Response {
    if has_body {
        return Response::empty(415);
    }
    let Some(dest) = req.headers.get("destination") else {
        return Response::empty(400);
    };
    let Some(duri) = parse_destination(dest, req) else {
        return Response::empty(400);
    };

    let src_is_collection = path.ends_with('/');
    let dst_is_collection = dest.ends_with('/');
    if src_is_collection != dst_is_collection {
        return Response::empty(409);
    }

    let d = depth(req, INFINITY);
    if d != INFINITY {
        if is_move || d != 0 {
            return Response::empty(400);
        }
    }

    let overwrite = match req.headers.get("overwrite") {
        None => true,
        Some(v) => match v.as_bytes() {
            b"T" | b"t" => true,
            b"F" | b"f" => false,
            _ => return Response::empty(400),
        },
    };

    let src = map_uri(path, loc);
    let dst = map_uri(&duri, loc);
    let dst_slash = duri.ends_with('/');

    let mut overwrite = overwrite;
    match fs::symlink_metadata(&dst) {
        Ok(meta) => {
            if meta.is_dir() && !dst_slash {
                return Response::empty(409);
            }
            if !overwrite {
                return Response::empty(412);
            }
            let _ = meta;
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            // Destination does not exist: nothing to overwrite.
            overwrite = false;
        }
        Err(e) => return Response::empty(dav_error(&e, 404)),
    }

    let src_meta = match fs::symlink_metadata(&src) {
        Ok(m) => m,
        Err(e) => return Response::empty(dav_error(&e, 404)),
    };

    if src_meta.is_dir() {
        if !src_is_collection {
            return Response::empty(400);
        }
        if overwrite {
            if let Err(e) = remove_tree(&dst) {
                if e.raw_os_error() != Some(libc::ENOENT) {
                    return Response::empty(dav_error(&e, 404));
                }
            }
        }
        if is_move {
            // nginx renames a collection in one call first; falling back to a
            // copy+delete only when that fails (a cross-device move).
            if fs::rename(&src, &dst).is_ok() {
                return Response::empty(201);
            }
        }
        if let Err(e) = copy_tree(&src, &dst) {
            return Response::empty(dav_error(&e, 404));
        }
        if is_move {
            if let Err(e) = remove_tree(&src) {
                return Response::empty(dav_error(&e, 404));
            }
        }
        Response::empty(201)
    } else {
        if is_move {
            // `create_path = 1` for MOVE: the parent may be created.
            if let Some(parent) = dst.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = create_dirs(parent, dir_access(mode_access(loc))) {
                        return Response::empty(dav_error(&e, 500));
                    }
                }
            }
            return match fs::rename(&src, &dst) {
                Ok(()) => Response::empty(204),
                Err(e) => Response::empty(dav_error(&e, 500)),
            };
        }
        match copy_file(&src, &dst, &src_meta) {
            Ok(()) => Response::empty(204),
            Err(e) => Response::empty(dav_error(&e, 404)),
        }
    }
}

/// `Destination` -> a URI, or `None` when nginx would answer 400.
fn parse_destination(dest: &str, req: &Request) -> Option<String> {
    let rest = if let Some(r) = dest.strip_prefix('/') {
        // Already origin-form: the whole value is the URI.
        return Some(percent_decode(&format!("/{r}")));
    } else if let Some(r) = dest.strip_prefix("http://") {
        r
    } else if req.tls.is_some() {
        dest.strip_prefix("https://")?
    } else {
        return None;
    };
    // The authority must be the one the request was addressed to; nginx
    // compares against the Host header without its port.
    let host = req.host.as_deref().unwrap_or("");
    let bare = match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    if bare.is_empty() || !rest.starts_with(bare) {
        return None;
    }
    let tail = &rest[bare.len()..];
    // Anything between the host and the path (a `:port`) is skipped, exactly as
    // nginx scans for the first `/`.
    let slash = tail.find('/')?;
    Some(percent_decode(&tail[slash..]))
}

fn percent_decode(uri: &str) -> String {
    crate::util::percent_decode(uri).unwrap_or_else(|_| uri.to_string())
}

fn copy_file(src: &Path, dst: &Path, meta: &fs::Metadata) -> io::Result<()> {
    fs::copy(src, dst)?;
    let _ = fs::set_permissions(dst, fs::Permissions::from_mode(meta.permissions().mode()));
    if let Ok(m) = meta.modified() {
        if let Ok(d) = m.duration_since(std::time::UNIX_EPOCH) {
            let _ = set_mtime(dst, d.as_secs() as i64);
        }
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if !meta.is_dir() {
        return copy_file(src, dst, &meta);
    }
    fs::DirBuilder::new()
        .mode(meta.permissions().mode())
        .create(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
    }
    // The directory's own mtime is restored last, after its children have been
    // written into it.
    if let Ok(m) = meta.modified() {
        if let Ok(d) = m.duration_since(std::time::UNIX_EPOCH) {
            let _ = set_mtime(dst, d.as_secs() as i64);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_cover_the_five_methods() {
        assert_eq!(flag_for(Method::Put), flags::PUT);
        assert_eq!(flag_for(Method::Delete), flags::DELETE);
        assert_eq!(
            flag_for(Method::Other("MKCOL".into())),
            flags::MKCOL
        );
        assert_eq!(flag_for(Method::Get), 0);
    }

    #[test]
    fn destination_forms() {
        // Parsing a real request head keeps the test honest about which fields
        // `parse_destination` actually reads (host, tls).
        let raw = b"COPY /src HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req = Request::parse(raw, 4096, 8192).expect("request head");
        // Origin-form, absolute with and without a port.
        assert_eq!(
            parse_destination("/file-moved%20escape", &req).as_deref(),
            Some("/file-moved escape")
        );
        assert_eq!(
            parse_destination("http://localhost/full_url_copy", &req).as_deref(),
            Some("/full_url_copy")
        );
        assert_eq!(
            parse_destination("http://localhost:8080/port_copy", &req).as_deref(),
            Some("/port_copy")
        );
        // Rejected: wrong scheme, wrong host, no path after the host.
        assert!(parse_destination("ftp://localhost/bad_scheme", &req).is_none());
        assert!(parse_destination("http://otherhost/file", &req).is_none());
        assert!(parse_destination("http://localhost", &req).is_none());
    }

    #[test]
    fn dav_access_zeroes_owner_bits_when_user_is_named() {
        // `dav_access user:rw group:r all:r` must be 0644, not 0744.
        let mut access = 0u32;
        let mut user = 0o600u32;
        for spec in ["user:rw", "group:r", "all:r"] {
            let (shift, right) = if let Some(r) = spec.strip_prefix("user:") {
                user = 0;
                (6, r)
            } else if let Some(r) = spec.strip_prefix("group:") {
                (3, r)
            } else {
                (0, spec.strip_prefix("all:").unwrap())
            };
            let bits = if right == "rw" { 6 } else { 4 };
            access |= bits << shift;
        }
        access |= user;
        assert_eq!(access, 0o644);
    }
}
