//! Bearer-token authentication for the HTTP transport.
//!
//! The auth file is a list of `label=token` lines. The label is what appears in
//! the audit trail; the token is the secret. Rules enforced at load time:
//!
//! - token at least 16 characters,
//! - label is letters, digits, `-` or `_`,
//! - no duplicate tokens,
//! - on Unix, the file must not be readable or writable by group or other.
//!
//! Tokens are compared in constant time so a wrong guess does not leak how many
//! characters of a token were right.

use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Auth {
    principals: Vec<(String, String)>,
}

/// Stamped onto the HTTP request by the auth middleware so a tool call can be
/// attributed to the token that made it. Inserted into the request extensions,
/// which rmcp copies into the tool handler's request context.
#[derive(Clone, Debug)]
pub struct Principal(pub String);

impl Auth {
    pub fn none() -> Auth {
        Auth {
            principals: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.principals.is_empty()
    }

    /// Returns the label whose token matches the Authorization header, or None.
    pub fn check(&self, header: Option<&str>) -> Option<String> {
        let value = header?.trim();
        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))?
            .trim();
        for (label, secret) in &self.principals {
            if constant_time_eq(token, secret) {
                return Some(label.clone());
            }
        }
        None
    }
}

pub fn load(path: &Path) -> Result<Auth, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|e| format!("cannot read auth file {}: {e}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "auth file {} is mode {mode:04o}; tokens must not be readable by group or other (chmod 600)",
                path.display()
            ));
        }
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("cannot read auth file {}: {e}", path.display()))?;
    let mut principals = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((label, token)) = line.split_once('=') else {
            return Err(format!(
                "auth file {} line {}: expected 'label=token', got '{line}'",
                path.display(),
                i + 1
            ));
        };
        let label = label.trim();
        let token = token.trim();
        if label.is_empty()
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "auth file {} line {}: label must be letters, digits, - or _",
                path.display(),
                i + 1
            ));
        }
        if token.len() < 16 {
            return Err(format!(
                "auth file {} line {}: token for '{label}' is {}/16 characters minimum",
                path.display(),
                i + 1,
                token.len()
            ));
        }
        if principals.iter().any(|(_, t)| t == token) {
            return Err(format!(
                "auth file {} line {}: duplicate token for label '{label}'",
                path.display(),
                i + 1
            ));
        }
        principals.push((label.to_string(), token.to_string()));
    }
    if principals.is_empty() {
        return Err(format!(
            "auth file {} has no 'label=token' entries",
            path.display()
        ));
    }
    Ok(Auth { principals })
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pgg-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join("tokens.txt")
    }

    #[cfg(unix)]
    fn owner_only(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn accepts_wellformed_tokens() {
        let path = scratch("ok");
        std::fs::write(
            &path,
            "analyst=abcdefghij123456\nauditor=0123456789012345\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let auth = load(&path).unwrap();
        assert_eq!(
            auth.check(Some("Bearer abcdefghij123456")).unwrap(),
            "analyst"
        );
        assert_eq!(
            auth.check(Some("bearer 0123456789012345")).unwrap(),
            "auditor"
        );
        assert!(auth.check(Some("Bearer wrong-token-value")).is_none());
        assert!(auth.check(Some("abcdefghij123456")).is_none());
        assert!(auth.check(None).is_none());
    }

    #[test]
    fn refuses_short_tokens() {
        let path = scratch("short");
        std::fs::write(&path, "x=abc\n").unwrap();
        #[cfg(unix)]
        owner_only(&path);
        let err = load(&path).unwrap_err();
        assert!(err.contains("16 characters minimum"));
    }

    #[test]
    fn refuses_duplicates() {
        let path = scratch("dup");
        std::fs::write(&path, "a=abcdefghij123456\nb=abcdefghij123456\n").unwrap();
        #[cfg(unix)]
        owner_only(&path);
        let err = load(&path).unwrap_err();
        assert!(err.contains("duplicate token"));
    }

    #[test]
    fn refuses_group_readable_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = scratch("perms");
            std::fs::write(&path, "a=abcdefghij123456\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = load(&path).unwrap_err();
            assert!(err.contains("chmod 600"), "got: {err}");
        }
    }

    #[test]
    fn constant_time_compare_rejects_length_mismatch() {
        assert!(!constant_time_eq("abcdefghij123456", "abcdefghij12345"));
        assert!(constant_time_eq("abcdefghij123456", "abcdefghij123456"));
        assert!(!constant_time_eq("abcdefghij123456", "abcdefghij123457"));
    }
}
