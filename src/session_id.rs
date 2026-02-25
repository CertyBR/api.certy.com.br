use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::error::{AppError, AppResult};

const SESSION_ID_BYTES: usize = 48;
const SESSION_ID_MIN_LEN: usize = 32;
const SESSION_ID_MAX_LEN: usize = 128;

pub fn generate_session_id() -> String {
    let mut bytes = [0u8; SESSION_ID_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn validate_session_id(raw: &str) -> AppResult<String> {
    let session_id = raw.trim();

    if !(SESSION_ID_MIN_LEN..=SESSION_ID_MAX_LEN).contains(&session_id.len()) {
        return Err(AppError::validation("session_id inválido."));
    }

    if !session_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppError::validation("session_id inválido."));
    }

    Ok(session_id.to_owned())
}
