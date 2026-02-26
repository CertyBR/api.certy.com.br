use std::time::Duration;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::config::AppConfig;

const CODE_LENGTH: usize = 6;

#[derive(Clone)]
pub struct EmailVerificationService {
    secret: String,
    ttl: Duration,
    max_attempts: u32,
}

impl EmailVerificationService {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            secret: config.email_verification_secret.clone(),
            ttl: config.email_verification_code_ttl,
            max_attempts: config.email_verification_max_attempts,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    pub fn generate_code(&self) -> String {
        let value: u32 = rand::thread_rng().gen_range(0..1_000_000);
        format!("{value:06}")
    }

    pub fn hash_code(&self, session_id: &str, code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.secret.as_bytes());
        hasher.update(b":");
        hasher.update(session_id.as_bytes());
        hasher.update(b":");
        hasher.update(code.as_bytes());
        let digest = hasher.finalize();
        hex_encode(&digest)
    }

    pub fn validate_code_format(&self, raw: &str) -> Result<String, String> {
        let code = raw.trim();
        if code.len() != CODE_LENGTH || !code.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("Código de verificação inválido.".to_owned());
        }
        Ok(code.to_owned())
    }

    pub fn verify_code(&self, session_id: &str, submitted_code: &str, stored_hash: &str) -> bool {
        let submitted_hash = self.hash_code(session_id, submitted_code);
        submitted_hash == stored_hash
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::EmailVerificationService;
    use crate::config::AppConfig;

    fn test_config() -> AppConfig {
        AppConfig {
            bind_addr: "0.0.0.0:8080".to_owned(),
            database_url: "postgres://postgres:postgres@localhost:5432/certy".to_owned(),
            proxy_shared_token: None,
            email_validation_api_url: "https://api.likn.dev/v1/public/email-validation/validate"
                .to_owned(),
            email_validation_timeout: Duration::from_millis(4500),
            email_verification_code_ttl: Duration::from_secs(600),
            email_verification_max_attempts: 5,
            email_verification_max_resends: 3,
            email_verification_resend_interval: Duration::from_secs(600),
            email_verification_secret: "certy-test-secret".to_owned(),
            resend_api_key: None,
            resend_api_url: "https://api.resend.com/emails".to_owned(),
            resend_from_email: "certy.zerocert@send.likncorp.com".to_owned(),
            resend_from_name: "Certy by ZeroCert".to_owned(),
            smtp_host: None,
            smtp_port: 587,
            smtp_username: None,
            smtp_password: None,
            smtp_from_email: None,
            smtp_from_name: "Certy".to_owned(),
            smtp_starttls: true,
            dns_check_resolver_url: "https://dns.google/resolve".to_owned(),
            dns_check_timeout: Duration::from_millis(4500),
            acme_directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned(),
            acme_account_contact_email: None,
            acme_account_credentials_json: None,
            session_ttl: Duration::from_secs(3600),
            poll_timeout: Duration::from_secs(120),
            poll_initial_delay: Duration::from_millis(500),
            poll_backoff: 1.8,
        }
    }

    #[test]
    fn validates_code_format() {
        let service = EmailVerificationService::new(&test_config());
        assert!(service.validate_code_format("123456").is_ok());
        assert!(service.validate_code_format("12a456").is_err());
        assert!(service.validate_code_format("12345").is_err());
    }

    #[test]
    fn hash_verification_matches() {
        let service = EmailVerificationService::new(&test_config());
        let session_id = "session_abc";
        let code = "123456";
        let hash = service.hash_code(session_id, code);
        assert!(service.verify_code(session_id, code, &hash));
        assert!(!service.verify_code(session_id, "654321", &hash));
    }
}
