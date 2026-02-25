use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
};
use thiserror::Error;
use tracing::info;

use crate::config::AppConfig;

#[derive(Clone)]
pub struct EmailSenderService {
    enabled: bool,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Option<Mailbox>,
}

#[derive(Debug, Error)]
pub enum EmailSenderError {
    #[error("configuração de e-mail inválida: {0}")]
    InvalidConfig(String),
    #[error("falha ao enviar e-mail: {0}")]
    Send(String),
}

impl EmailSenderService {
    pub fn new(config: &AppConfig) -> Result<Self, EmailSenderError> {
        let Some(host) = config.smtp_host.as_ref() else {
            return Ok(Self {
                enabled: false,
                transport: None,
                from: None,
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

        let transport = builder.build();

        Ok(Self {
            enabled: true,
            transport: Some(transport),
            from: Some(from),
        })
    }

    pub async fn send_verification_code(
        &self,
        to_email: &str,
        domain: &str,
        code: &str,
        ttl: Duration,
    ) -> Result<(), EmailSenderError> {
        if !self.enabled {
            info!(
                target: "certy_backend::email",
                to = %to_email,
                domain = %domain,
                code = %code,
                "SMTP não configurado; código de verificação gerado (modo local)"
            );
            return Ok(());
        }

        let from = self.from.as_ref().cloned().ok_or_else(|| {
            EmailSenderError::InvalidConfig("remetente de e-mail ausente".to_owned())
        })?;
        let to = Mailbox::new(None, parse_email(to_email)?);

        let ttl_minutes = ttl.as_secs() / 60;
        let subject = format!("Certy: código de verificação para {domain}");
        let body = format!(
            "Seu código de verificação do Certy é: {code}\n\n\
             Esse código expira em {ttl_minutes} minuto(s).\n\
             Se você não solicitou esta emissão, ignore este e-mail."
        );

        let message = Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|err| EmailSenderError::InvalidConfig(err.to_string()))?;

        let transport = self.transport.as_ref().ok_or_else(|| {
            EmailSenderError::InvalidConfig("transporte SMTP indisponível".to_owned())
        })?;

        transport
            .send(message)
            .await
            .map_err(|err| EmailSenderError::Send(err.to_string()))?;

        info!(
            target: "certy_backend::email",
            to = %to_email,
            domain = %domain,
            "código de verificação enviado"
        );

        Ok(())
    }
}

fn parse_email(raw: &str) -> Result<lettre::Address, EmailSenderError> {
    raw.parse::<lettre::Address>()
        .map_err(|err| EmailSenderError::InvalidConfig(err.to_string()))
}
