use std::env;
use std::time::Duration;

use instant_acme::LetsEncrypt;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub proxy_shared_token: Option<String>,
    pub email_validation_api_url: String,
    pub email_validation_timeout: Duration,
    pub email_verification_code_ttl: Duration,
    pub email_verification_max_attempts: u32,
    pub email_verification_max_resends: u32,
    pub email_verification_resend_interval: Duration,
    pub email_verification_secret: String,
    pub resend_api_key: Option<String>,
    pub resend_api_url: String,
    pub resend_from_email: String,
    pub resend_from_name: String,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from_email: Option<String>,
    pub smtp_from_name: String,
    pub smtp_starttls: bool,
    pub dns_check_resolver_url: String,
    pub dns_check_timeout: Duration,
    pub acme_directory_url: String,
    pub acme_account_contact_email: Option<String>,
    pub acme_account_credentials_json: Option<String>,
    pub session_ttl: Duration,
    pub poll_timeout: Duration,
    pub poll_initial_delay: Duration,
    pub poll_backoff: f32,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let acme_directory_url = match env::var("ACME_DIRECTORY_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => {
                let use_staging = env_bool("ACME_USE_STAGING", false);
                if use_staging {
                    LetsEncrypt::Staging.url().to_owned()
                } else {
                    LetsEncrypt::Production.url().to_owned()
                }
            }
        };

        let backend_port = env::var("BACKEND_PORT")
            .ok()
            .map(|raw| raw.trim().to_owned())
            .filter(|raw| !raw.is_empty())
            .and_then(|raw| raw.parse::<u16>().ok())
            .unwrap_or_else(|| {
                panic!(
                    "variável obrigatória ausente/inválida: BACKEND_PORT (esperado inteiro de 1 a 65535)"
                )
            });
        let bind_addr = format!("0.0.0.0:{backend_port}");

        Self {
            bind_addr,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/certy".to_owned()),
            proxy_shared_token: env::var("PROXY_SHARED_TOKEN")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            email_validation_api_url: env::var("EMAIL_VALIDATION_API_URL")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| {
                    "https://api.likn.dev/v1/public/email-validation/validate".to_owned()
                }),
            email_validation_timeout: Duration::from_millis(env_u64(
                "EMAIL_VALIDATION_TIMEOUT_MS",
                4500,
            )),
            email_verification_code_ttl: Duration::from_secs(
                env_u64("EMAIL_VERIFICATION_CODE_TTL_MINUTES", 10) * 60,
            ),
            email_verification_max_attempts: env_u64("EMAIL_VERIFICATION_MAX_ATTEMPTS", 5) as u32,
            email_verification_max_resends: env_u64("EMAIL_VERIFICATION_MAX_RESENDS", 3) as u32,
            email_verification_resend_interval: Duration::from_secs(
                env_u64("EMAIL_VERIFICATION_RESEND_INTERVAL_MINUTES", 10) * 60,
            ),
            email_verification_secret: env::var("EMAIL_VERIFICATION_SECRET")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "certy-dev-secret-change-me".to_owned()),
            resend_api_key: env::var("RESEND_API_KEY")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            resend_api_url: env::var("RESEND_API_URL")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "https://api.resend.com/emails".to_owned()),
            resend_from_email: env::var("RESEND_FROM_EMAIL")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "certy.zerocert@send.likncorp.com".to_owned()),
            resend_from_name: env::var("RESEND_FROM_NAME")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "Certy by ZeroCert".to_owned()),
            smtp_host: env::var("SMTP_HOST")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            smtp_port: env_u16("SMTP_PORT", 587),
            smtp_username: env::var("SMTP_USERNAME")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            smtp_password: env::var("SMTP_PASSWORD")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            smtp_from_email: env::var("SMTP_FROM_EMAIL")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            smtp_from_name: env::var("SMTP_FROM_NAME")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "Certy".to_owned()),
            smtp_starttls: env_bool("SMTP_STARTTLS", true),
            dns_check_resolver_url: env::var("DNS_CHECK_RESOLVER_URL")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "https://dns.google/resolve".to_owned()),
            dns_check_timeout: Duration::from_millis(env_u64("DNS_CHECK_TIMEOUT_MS", 4500)),
            acme_directory_url,
            acme_account_contact_email: env::var("ACME_ACCOUNT_CONTACT_EMAIL")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            acme_account_credentials_json: env::var("ACME_ACCOUNT_CREDENTIALS_JSON")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            session_ttl: Duration::from_secs(env_u64("SESSION_TTL_MINUTES", 60) * 60),
            poll_timeout: Duration::from_secs(env_u64("ACME_POLL_TIMEOUT_SECONDS", 120)),
            poll_initial_delay: Duration::from_millis(env_u64("ACME_POLL_INITIAL_DELAY_MS", 500)),
            poll_backoff: env_f32("ACME_POLL_BACKOFF", 1.8),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(default)
}

fn env_f32(key: &str, default: f32) -> f32 {
    env::var(key)
        .ok()
        .and_then(|raw| raw.parse::<f32>().ok())
        .filter(|value| *value > 1.0)
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "y" | "on")
        }
        Err(_) => default,
    }
}
