use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::config::AppConfig;

#[derive(Clone)]
pub struct EmailValidationService {
    client: reqwest::Client,
    endpoint: String,
    timeout: Duration,
}

#[derive(Debug, Error)]
pub enum EmailValidationError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Upstream(String),
}

#[derive(Debug, Deserialize)]
struct LiknEmailValidationResponse {
    valid: bool,
    #[serde(default)]
    format_valid: bool,
    #[serde(default)]
    is_disposable: bool,
    #[serde(default)]
    dns_valid: bool,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LiknErrorResponse {
    error: Option<String>,
}

impl EmailValidationService {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: config.email_validation_api_url.clone(),
            timeout: config.email_validation_timeout,
        }
    }

    pub async fn validate_email(&self, email: &str) -> Result<(), EmailValidationError> {
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[("email", email)])
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|err| {
                EmailValidationError::Upstream(format!(
                    "Falha ao validar e-mail em serviço externo: {err}"
                ))
            })?;

        if response.status().is_success() {
            let payload = response
                .json::<LiknEmailValidationResponse>()
                .await
                .map_err(|err| {
                    EmailValidationError::Upstream(format!(
                        "Resposta inválida do serviço de validação de e-mail: {err}"
                    ))
                })?;
            return validate_payload(payload);
        }

        let status = response.status().as_u16();
        let body = response
            .json::<LiknErrorResponse>()
            .await
            .ok()
            .and_then(|value| value.error)
            .unwrap_or_else(|| "Serviço de validação de e-mail indisponível.".to_owned());

        Err(EmailValidationError::Upstream(format!(
            "Falha ao validar e-mail (HTTP {status}): {body}"
        )))
    }
}

fn validate_payload(payload: LiknEmailValidationResponse) -> Result<(), EmailValidationError> {
    if !payload.valid {
        return Err(EmailValidationError::Invalid(first_error(
            payload.errors,
            "E-mail inválido.".to_owned(),
        )));
    }

    if !payload.format_valid {
        return Err(EmailValidationError::Invalid(first_error(
            payload.errors,
            "Formato de e-mail inválido.".to_owned(),
        )));
    }

    if payload.is_disposable {
        return Err(EmailValidationError::Invalid(
            "Use um e-mail permanente. E-mails descartáveis não são aceitos.".to_owned(),
        ));
    }

    if !payload.dns_valid {
        return Err(EmailValidationError::Invalid(
            "Domínio de e-mail sem DNS/MX válido.".to_owned(),
        ));
    }

    Ok(())
}

fn first_error(errors: Vec<String>, fallback: String) -> String {
    errors
        .into_iter()
        .find(|item| !item.trim().is_empty())
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::{EmailValidationError, LiknEmailValidationResponse, validate_payload};

    #[test]
    fn accepts_valid_email_payload() {
        let payload = LiknEmailValidationResponse {
            valid: true,
            format_valid: true,
            is_disposable: false,
            dns_valid: true,
            errors: vec![],
        };

        assert!(validate_payload(payload).is_ok());
    }

    #[test]
    fn rejects_disposable_email() {
        let payload = LiknEmailValidationResponse {
            valid: true,
            format_valid: true,
            is_disposable: true,
            dns_valid: true,
            errors: vec![],
        };

        let result = validate_payload(payload);
        assert!(matches!(result, Err(EmailValidationError::Invalid(_))));
    }

    #[test]
    fn rejects_invalid_dns() {
        let payload = LiknEmailValidationResponse {
            valid: true,
            format_valid: true,
            is_disposable: false,
            dns_valid: false,
            errors: vec!["no mx record".to_owned()],
        };

        let result = validate_payload(payload);
        assert!(matches!(result, Err(EmailValidationError::Invalid(_))));
    }
}
