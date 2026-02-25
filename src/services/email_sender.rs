use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::config::AppConfig;

#[derive(Clone)]
pub struct EmailSenderService {
    provider: EmailProvider,
}

#[derive(Clone)]
enum EmailProvider {
    Resend {
        client: reqwest::Client,
        api_url: String,
        api_key: String,
        from: String,
    },
    Smtp {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    },
    Disabled,
}

#[derive(Debug, Error)]
pub enum EmailSenderError {
    #[error("configuração de e-mail inválida: {0}")]
    InvalidConfig(String),
    #[error("falha ao enviar e-mail: {0}")]
    Send(String),
}

#[derive(Debug, Serialize)]
struct ResendSendEmailRequest {
    from: String,
    to: Vec<String>,
    subject: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct ResendSendEmailResponse {
    id: Option<String>,
}

impl EmailSenderService {
    pub fn new(config: &AppConfig) -> Result<Self, EmailSenderError> {
        if let Some(api_key) = config.resend_api_key.as_ref() {
            let from = format!("{} <{}>", config.resend_from_name, config.resend_from_email);

            return Ok(Self {
                provider: EmailProvider::Resend {
                    client: reqwest::Client::new(),
                    api_url: config.resend_api_url.clone(),
                    api_key: api_key.clone(),
                    from,
                },
            });
        }

        let Some(host) = config.smtp_host.as_ref() else {
            return Ok(Self {
                provider: EmailProvider::Disabled,
            });
        };

        let from_email = config.smtp_from_email.as_ref().ok_or_else(|| {
            EmailSenderError::InvalidConfig("SMTP_FROM_EMAIL não configurado".to_owned())
        })?;

        let from = Mailbox::new(
            Some(config.smtp_from_name.clone()),
            parse_email(from_email)?,
        );

        let mut builder = if config.smtp_starttls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|err| EmailSenderError::InvalidConfig(err.to_string()))?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        };

        builder = builder.port(config.smtp_port);

        if let (Some(username), Some(password)) = (&config.smtp_username, &config.smtp_password) {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        }

        Ok(Self {
            provider: EmailProvider::Smtp {
                transport: builder.build(),
                from,
            },
        })
    }

    pub async fn send_verification_code(
        &self,
        to_email: &str,
        domain: &str,
        code: &str,
        ttl: Duration,
    ) -> Result<(), EmailSenderError> {
        let ttl_minutes = ttl.as_secs() / 60;
        let subject = format!("Certy: código de verificação para {domain}");
        let body = format!(
            "Seu código de verificação do Certy é: {code}\n\n\
             Esse código expira em {ttl_minutes} minuto(s).\n\
             Se você não solicitou esta emissão, ignore este e-mail."
        );

        match &self.provider {
            EmailProvider::Resend {
                client,
                api_url,
                api_key,
                from,
            } => {
                let request_payload = ResendSendEmailRequest {
                    from: from.clone(),
                    to: vec![to_email.to_owned()],
                    subject,
                    text: body,
                };

                let response = client
                    .post(api_url)
                    .bearer_auth(api_key)
                    .json(&request_payload)
                    .send()
                    .await
                    .map_err(|err| EmailSenderError::Send(err.to_string()))?;

                if !response.status().is_success() {
                    let status = response.status();
                    let response_body = response.text().await.unwrap_or_default();
                    return Err(EmailSenderError::Send(format!(
                        "Resend retornou HTTP {status}: {}",
                        compact_error_body(&response_body)
                    )));
                }

                let resend_response = response
                    .json::<ResendSendEmailResponse>()
                    .await
                    .unwrap_or(ResendSendEmailResponse { id: None });

                info!(
                    target: "certy_backend::email",
                    provider = "resend",
                    to = %to_email,
                    domain = %domain,
                    message_id = resend_response.id.unwrap_or_else(|| "unknown".to_owned()),
                    "código de verificação enviado"
                );

                Ok(())
            }
            EmailProvider::Smtp { transport, from } => {
                let to = Mailbox::new(None, parse_email(to_email)?);

                let message = Message::builder()
                    .from(from.clone())
                    .to(to)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body)
                    .map_err(|err| EmailSenderError::InvalidConfig(err.to_string()))?;

                transport
                    .send(message)
                    .await
                    .map_err(|err| EmailSenderError::Send(err.to_string()))?;

                info!(
                    target: "certy_backend::email",
                    provider = "smtp",
                    to = %to_email,
                    domain = %domain,
                    "código de verificação enviado"
                );

                Ok(())
            }
            EmailProvider::Disabled => {
                info!(
                    target: "certy_backend::email",
                    provider = "local",
                    to = %to_email,
                    domain = %domain,
                    code = %code,
                    "serviço de e-mail não configurado; código gerado (modo local)"
                );
                Ok(())
            }
        }
    }
}

fn parse_email(raw: &str) -> Result<lettre::Address, EmailSenderError> {
    raw.parse::<lettre::Address>()
        .map_err(|err| EmailSenderError::InvalidConfig(err.to_string()))
}

fn compact_error_body(body: &str) -> String {
    let cleaned = body.trim().replace('\n', " ");
    if cleaned.len() <= 240 {
        return cleaned;
    }

    format!("{}...", &cleaned[..240])
}
