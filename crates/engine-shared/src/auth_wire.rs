//! Pure wire helpers for token-type discrimination without pulling in `pasetors`.

use base64::Engine;

pub const PROJECT_DEVICE_TOKEN_TYPE: &str = "dynodoc.project-device-session.v1";
pub const PROJECT_DEVICE_FOOTER_JSON: &[u8] = br#"{"typ":"dynodoc.project-device-session.v1"}"#;

/// Returns `true` iff `token` is a `v4.local.<payload>.<footer>` Paseto token whose
/// unauthenticated base64url footer equals [`PROJECT_DEVICE_FOOTER_JSON`].
pub fn is_project_device_token(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some("v4"), Some("local"), Some(payload), Some(footer), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    if payload.is_empty() || footer.is_empty() {
        return false;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(footer)
        .is_ok_and(|bytes| bytes == PROJECT_DEVICE_FOOTER_JSON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_project_device_footer_from_account_and_malformed_tokens() {
        let footer =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(PROJECT_DEVICE_FOOTER_JSON);
        let device_tok = format!("v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.{footer}");
        assert!(is_project_device_token(&device_tok));

        // Account token has 3 parts (no footer)
        assert!(!is_project_device_token(
            "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));

        // Different footer or wrong version/purpose or extra segment
        let other_footer =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"typ":"other"}"#);
        assert!(!is_project_device_token(&format!(
            "v4.local.AAAA.{other_footer}"
        )));
        assert!(!is_project_device_token(&format!(
            "v4.public.AAAA.{footer}"
        )));
        assert!(!is_project_device_token(&format!(
            "v4.local.AAAA.{footer}.extra"
        )));
        assert!(!is_project_device_token("v4.local.."));
        assert!(!is_project_device_token("not-a-token"));
    }
}
