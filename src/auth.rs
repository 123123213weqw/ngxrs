//! `auth_basic` and the credential file it reads.
//!
//! The file format is nginx's (`ngx_http_auth_basic_module`): one
//! `user:hash` pair per line, `#` comments, blank lines skipped. The hash may be
//! prefixed with `{PLAIN}`, `{SHA}` or `{SSHA}`; an unprefixed hash is passed to
//! the platform `crypt(3)`, which covers DES, MD5 (`$1$`), SHA-256 (`$5$`) and
//! SHA-512 (`$6$`).
//!
//! Behaviours confirmed against nginx rather than assumed:
//!
//! * A missing or unreadable user file is **not** a config error: nginx logs it
//!   and answers 401.
//! * A malformed `Authorization` header (bad base64, no colon, wrong scheme)
//!   answers 401, not 400.
//! * `return` runs in the rewrite phase, so it short-circuits *before*
//!   `auth_basic` ever runs. A location whose only content is `return 200` is
//!   therefore unauthenticated even with `auth_basic` set.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// What `auth_basic` was configured to do in a location.
#[derive(Clone, Debug, Default)]
pub struct BasicAuth {
    /// `None` means the directive is absent (inherited from the parent).
    pub realm: Option<String>,
    pub user_file: Option<std::path::PathBuf>,
}

impl BasicAuth {
    /// `auth_basic off` is not a realm but a disable switch.
    pub fn is_off(&self) -> bool {
        matches!(self.realm.as_deref(), Some("off"))
    }

    pub fn enabled(&self) -> bool {
        matches!(self.realm.as_deref(), Some(r) if !r.is_empty() && r != "off")
    }
}

/// Outcome of checking an `Authorization` header.
pub enum Verdict {
    /// Credentials accepted.
    Ok,
    /// Rejected; the caller answers 401 with the realm.
    Reject,
}

/// Parse a `user:password` set of credentials from an `Authorization: Basic`
/// header value, returning `None` when it is not usable.
fn basic_credentials(header: &str) -> Option<(String, String)> {
    let value = header.trim();
    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let raw = crate::util::base64_decode(b64.trim())?;
    let text = String::from_utf8(raw).ok()?;
    // The split is on the *first* colon: passwords may contain colons.
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Load a user file into `user -> hash` form. Returns `None` when the file
/// cannot be read, which nginx treats as "reject everyone".
fn load_user_file(path: &Path) -> Option<HashMap<String, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((user, hash)) = line.split_once(':') else {
            continue;
        };
        map.insert(user.to_string(), hash.to_string());
    }
    Some(map)
}

/// Verify a plaintext password against a stored hash.
fn hash_matches(stored: &str, password: &str) -> bool {
    if let Some(plain) = stored.strip_prefix("{PLAIN}") {
        return plain == password;
    }
    if let Some(b64) = stored.strip_prefix("{SHA}") {
        let Some(want) = crate::util::base64_decode(b64) else {
            return false;
        };
        let got =
            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes());
        return want == got.as_ref();
    }
    if let Some(b64) = stored.strip_prefix("{SSHA}") {
        // Salted SHA-1: the digest is base64(sha1(password + salt) || salt).
        let Some(raw) = crate::util::base64_decode(b64) else {
            return false;
        };
        if raw.len() <= 20 {
            return false;
        }
        let (digest, salt) = raw.split_at(20);
        let mut input = password.as_bytes().to_vec();
        input.extend_from_slice(salt);
        let got = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
        return digest == got.as_ref();
    }
    // Apache's MD5 crypt. nginx implements this itself (`ngx_crypt_apr1` in
    // src/os/unix/ngx_user.c) because libcrypt generally does not: on this
    // host `crypt("password", "$apr1$salt$...")` returns `*0`, while nginx
    // verifies the same hash. `htpasswd -m`, Apache's default, writes this
    // format.
    if stored.starts_with("$apr1$") {
        return apr1::verify(stored, password);
    }
    // Fall back to crypt(3).
    crypt_verify(password, stored)
}

/// `crypt` lives in `libcrypt` on Linux (glibc split it out of libc, and the
/// `libc` crate does not export it), so the library is linked explicitly the
/// same way nginx links `-lcrypt`. On macOS it is part of libSystem.
#[cfg_attr(target_os = "linux", link(name = "crypt"))]
extern "C" {
    /// From `libcrypt`. The libc crate does not expose it on every target, so
    /// it is bound here.
    fn crypt(key: *const std::ffi::c_char, salt: *const std::ffi::c_char) -> *mut std::ffi::c_char;
}

/// `crypt(3)` is not reentrant on all platforms, so calls are serialised.
static CRYPT_LOCK: Mutex<()> = Mutex::new(());

fn crypt_verify(password: &str, stored: &str) -> bool {
    let Ok(pw) = std::ffi::CString::new(password) else {
        return false;
    };
    let Ok(salt) = std::ffi::CString::new(stored) else {
        return false;
    };
    let _guard = CRYPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: both arguments are valid NUL-terminated strings that outlive the
    // call, and the result is only read while the lock is held.
    let out = unsafe { crypt(pw.as_ptr(), salt.as_ptr()) };
    if out.is_null() {
        return false;
    }
    let got = unsafe { std::ffi::CStr::from_ptr(out) };
    let got = got.to_bytes();
    // Compare without early exit to avoid leaking the length of a match.
    let want = stored.as_bytes();
    got.len() == want.len() && got.iter().zip(want).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

/// Check a request's `Authorization` header against a location's basic-auth
/// configuration.
///
/// `user_file` is the path already expanded for this request: nginx allows a
/// variable there (`auth_basic_user_file $arg_f`), and a relative path is
/// resolved against the configuration prefix, both of which the caller does
/// because only it has the request variables.
pub fn check(basic: &BasicAuth, auth_header: Option<&str>, user_file: Option<&Path>) -> Verdict {
    if !basic.enabled() {
        return Verdict::Ok;
    }
    let Some(header) = auth_header else {
        return Verdict::Reject;
    };
    let Some((user, password)) = basic_credentials(header) else {
        return Verdict::Reject;
    };
    let Some(file) = user_file else {
        // Configured without a user file: nobody can authenticate.
        return Verdict::Reject;
    };
    let Some(users) = load_user_file(file) else {
        return Verdict::Reject;
    };
    match users.get(&user) {
        Some(stored) if hash_matches(stored, &password) => Verdict::Ok,
        _ => Verdict::Reject,
    }
}

/// Apache's `$apr1$` MD5 crypt (the format `htpasswd -m` writes), with the MD5
/// it needs. nginx carries its own copy (`ngx_crypt_apr1`) because libcrypt
/// usually lacks this variant; the same is true here.
mod apr1 {
    /// MD5 (RFC 1321). In-tree because the dependency set has no MD5: `ring`
    /// ships SHA-1/SHA-256 only, and one legacy password hash does not justify
    /// a new crate.
    const ITOA64: &[u8; 64] =
        b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    fn to64(mut v: u32, n: usize, out: &mut String) {
        for _ in 0..n {
            out.push(ITOA64[(v & 0x3f) as usize] as char);
            v >>= 6;
        }
    }

    /// `$apr1$<salt>$<hash>` for a password and an already-truncated salt.
    pub(super) fn hash(password: &str, salt: &str) -> String {
        let pw = password.as_bytes();
        let salt = &salt.as_bytes()[..salt.len().min(8)];

        let mut ctx = crate::md5::Ctx::new();
        ctx.update(pw);
        ctx.update(b"$apr1$");
        ctx.update(salt);

        let mut inner = crate::md5::Ctx::new();
        inner.update(pw);
        inner.update(salt);
        inner.update(pw);
        let mut fin = inner.digest();

        let mut n = pw.len();
        while n > 0 {
            let take = n.min(16);
            ctx.update(&fin[..take]);
            n -= take;
        }
        // "Then something really weird": one bit per password-length bit, high
        // to low, appending a NUL for a set bit and the first password byte for
        // a clear one.
        let mut i = pw.len();
        while i > 0 {
            if i & 1 == 1 {
                ctx.update(&[0u8]);
            } else {
                ctx.update(&pw[..1]);
            }
            i >>= 1;
        }
        fin = ctx.digest();

        for round in 0..1000 {
            let mut c = crate::md5::Ctx::new();
            if round & 1 == 1 {
                c.update(pw);
            } else {
                c.update(&fin);
            }
            if round % 3 != 0 {
                c.update(salt);
            }
            if round % 7 != 0 {
                c.update(pw);
            }
            if round & 1 == 1 {
                c.update(&fin);
            } else {
                c.update(pw);
            }
            fin = c.digest();
        }

        let mut out = String::from("$apr1$");
        out.push_str(std::str::from_utf8(salt).unwrap_or_default());
        out.push('$');
        let l = |a: u8, b: u8, c: u8| ((a as u32) << 16) | ((b as u32) << 8) | c as u32;
        to64(l(fin[0], fin[6], fin[12]), 4, &mut out);
        to64(l(fin[1], fin[7], fin[13]), 4, &mut out);
        to64(l(fin[2], fin[8], fin[14]), 4, &mut out);
        to64(l(fin[3], fin[9], fin[15]), 4, &mut out);
        to64(l(fin[4], fin[10], fin[5]), 4, &mut out);
        to64(fin[11] as u32, 2, &mut out);
        out
    }

    /// Verify a stored `$apr1$...` hash against a password.
    pub fn verify(stored: &str, password: &str) -> bool {
        let rest = match stored.strip_prefix("$apr1$") {
            Some(r) => r,
            None => return false,
        };
        // `$apr1$salt$hash`; a missing `$` means a malformed entry, which nginx
        // treats as a mismatch rather than an error.
        let Some((salt, _)) = rest.split_once('$') else {
            return false;
        };
        let got = hash(password, salt);
        // Constant-ish comparison: both sides are fixed-length ASCII.
        got.len() == stored.len()
            && got
                .bytes()
                .zip(stored.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0
    }
}

/// Append the `WWW-Authenticate` line for a realm, escaping quotes the way nginx
/// does when it builds the header.
pub fn www_authenticate(realm: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(b"WWW-Authenticate: Basic realm=\"");
    for &b in realm.as_bytes() {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.extend_from_slice(b"\"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a scratch user file; the path is unique per test name.
    fn write_userfile(name: &str, contents: &str) -> std::path::PathBuf {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ngxrs-auth-test-{name}-{}.htpasswd",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        path
    }

    #[test]
    fn plain_hash_matches() {
        assert!(hash_matches("{PLAIN}secret", "secret"));
        assert!(!hash_matches("{PLAIN}secret", "Secret"));
    }

    #[test]
    fn sha_hash_matches() {
        // base64(sha1("secret"))
        assert!(hash_matches("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", "secret"));
        assert!(!hash_matches("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", "wrong"));
    }

    #[test]
    fn basic_header_parsing_splits_on_first_colon() {
        // "user:pa:ss" -> user = "user", pass = "pa:ss"
        let cred = crate::util::base64_encode(b"user:pa:ss");
        let (u, p) = basic_credentials(&format!("Basic {cred}")).expect("parse");
        assert_eq!(u, "user");
        assert_eq!(p, "pa:ss");
    }

    #[test]
    fn malformed_headers_are_rejected() {
        assert!(basic_credentials("Basic !!!notbase64").is_none());
        assert!(basic_credentials("Bearer x").is_none());
        // No colon in the decoded credentials.
        let cred = crate::util::base64_encode(b"useronly");
        assert!(basic_credentials(&format!("Basic {cred}")).is_none());
    }

    #[test]
    fn md5_matches_rfc1321() {
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut c = crate::md5::Ctx::new();
        assert_eq!(hex(c.digest()), "d41d8cd98f00b204e9800998ecf8427e");
        c = crate::md5::Ctx::new();
        c.update(b"a");
        c.update(b"bc");
        assert_eq!(hex(c.digest()), "900150983cd24fb0d6963f7d28e17f72");
        c = crate::md5::Ctx::new();
        c.update(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(hex(c.digest()), "9e107d9d372bb6826bd81d3542a419d6");
    }

    #[test]
    fn apr1_matches_apache_htpasswd() {
        // The vector from nginx-tests auth_basic.t: user `apr1`, hash for
        // password "password" with salt "salt".
        assert_eq!(
            apr1::hash("password", "salt"),
            "$apr1$salt$Xxd1irWT9ycqoYxGFn4cb."
        );
        assert!(apr1::verify("$apr1$salt$Xxd1irWT9ycqoYxGFn4cb.", "password"));
        assert!(!apr1::verify("$apr1$salt$Xxd1irWT9ycqoYxGFn4cb.", "123"));
        // Long salts are truncated to eight characters, as apr1 specifies.
        assert_eq!(
            apr1::hash("password", "saltsalt9"),
            apr1::hash("password", "saltsalt")
        );
        // Malformed entries are a mismatch, never a panic.
        assert!(!apr1::verify("$apr1$nosalt", "x"));
        assert!(!apr1::verify("$apr1$", "x"));
    }

    #[test]
    fn off_disables_and_absence_allows() {
        let off = BasicAuth {
            realm: Some("off".to_string()),
            user_file: None,
        };
        assert!(matches!(check(&off, None, None), Verdict::Ok));
        let absent = BasicAuth::default();
        assert!(matches!(check(&absent, None, None), Verdict::Ok));
    }

    #[test]
    fn missing_user_file_rejects() {
        let cfg = BasicAuth {
            realm: Some("r".to_string()),
            user_file: Some(std::path::PathBuf::from("/nonexistent/htpasswd")),
        };
        let cred = crate::util::base64_encode(b"user:secret");
        assert!(matches!(
            check(
                &cfg,
                Some(&format!("Basic {cred}")),
                Some(Path::new("/nonexistent/htpasswd"))
            ),
            Verdict::Reject
        ));
    }

    #[test]
    fn valid_credentials_accepted() {
        let path = write_userfile("valid", "user:{PLAIN}secret\n# comment\n\nother:{PLAIN}x\n");
        let cfg = BasicAuth {
            realm: Some("r".to_string()),
            user_file: Some(path.clone()),
        };
        let cred = crate::util::base64_encode(b"user:secret");
        assert!(matches!(
            check(&cfg, Some(&format!("Basic {cred}")), Some(&path)),
            Verdict::Ok
        ));
        let bad = crate::util::base64_encode(b"user:nope");
        assert!(matches!(
            check(&cfg, Some(&format!("Basic {bad}")), Some(&path)),
            Verdict::Reject
        ));
    }

    #[test]
    fn realm_is_escaped() {
        let mut out = Vec::new();
        www_authenticate(r#"say "hi""#, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "WWW-Authenticate: Basic realm=\"say \\\"hi\\\"\"\r\n"
        );
    }
}
