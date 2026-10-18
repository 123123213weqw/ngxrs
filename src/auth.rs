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
pub fn check(basic: &BasicAuth, auth_header: Option<&str>) -> Verdict {
    if !basic.enabled() {
        return Verdict::Ok;
    }
    let Some(header) = auth_header else {
        return Verdict::Reject;
    };
    let Some((user, password)) = basic_credentials(header) else {
        return Verdict::Reject;
    };
    let Some(file) = &basic.user_file else {
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
    fn off_disables_and_absence_allows() {
        let off = BasicAuth {
            realm: Some("off".to_string()),
            user_file: None,
        };
        assert!(matches!(check(&off, None), Verdict::Ok));
        let absent = BasicAuth::default();
        assert!(matches!(check(&absent, None), Verdict::Ok));
    }

    #[test]
    fn missing_user_file_rejects() {
        let cfg = BasicAuth {
            realm: Some("r".to_string()),
            user_file: Some(std::path::PathBuf::from("/nonexistent/htpasswd")),
        };
        let cred = crate::util::base64_encode(b"user:secret");
        assert!(matches!(
            check(&cfg, Some(&format!("Basic {cred}"))),
            Verdict::Reject
        ));
    }

    #[test]
    fn valid_credentials_accepted() {
        let path = write_userfile("valid", "user:{PLAIN}secret\n# comment\n\nother:{PLAIN}x\n");
        let cfg = BasicAuth {
            realm: Some("r".to_string()),
            user_file: Some(path),
        };
        let cred = crate::util::base64_encode(b"user:secret");
        assert!(matches!(
            check(&cfg, Some(&format!("Basic {cred}"))),
            Verdict::Ok
        ));
        let bad = crate::util::base64_encode(b"user:nope");
        assert!(matches!(
            check(&cfg, Some(&format!("Basic {bad}"))),
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
