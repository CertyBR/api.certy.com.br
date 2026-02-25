use std::env;
use std::time::Duration;

use instant_acme::LetsEncrypt;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub proxy_shared_token: Option<String>,
    pub acme_directory_url: String,
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

        Self {
            bind_addr: env::var("BACKEND_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_owned()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/certy".to_owned()),
            proxy_shared_token: env::var("PROXY_SHARED_TOKEN")
                .ok()
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty()),
            acme_directory_url,
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
