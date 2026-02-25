use crate::config::AppConfig;
use crate::repositories::session_repository::{RepositoryError, SessionRepository};
use crate::services::acme::AcmeService;
use crate::services::dns_precheck::DnsPrecheckService;
use crate::services::email_sender::{EmailSenderError, EmailSenderService};
use crate::services::email_validation::EmailValidationService;
use crate::services::email_verification::EmailVerificationService;

pub struct AppState {
    pub config: AppConfig,
    pub acme_service: AcmeService,
    pub email_validation_service: EmailValidationService,
    pub email_verification_service: EmailVerificationService,
    pub email_sender_service: EmailSenderService,
    pub dns_precheck_service: DnsPrecheckService,
    pub sessions: SessionRepository,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, RepositoryError> {
        let sessions = SessionRepository::connect(&config.database_url).await?;
        let email_sender_service = EmailSenderService::new(&config)
            .map_err(|err| RepositoryError::Decode(format_email_sender_error(err)))?;

        Ok(Self {
            acme_service: AcmeService::new(config.clone()),
            email_validation_service: EmailValidationService::new(&config),
            email_verification_service: EmailVerificationService::new(&config),
            email_sender_service,
            dns_precheck_service: DnsPrecheckService::new(&config),
            config,
            sessions,
        })
    }

    pub async fn prune_expired(&self) -> Result<(), RepositoryError> {
        self.sessions.prune_expired().await?;
        Ok(())
    }
}

fn format_email_sender_error(err: EmailSenderError) -> String {
    err.to_string()
}
