use crate::config::AppConfig;
use crate::repositories::session_repository::{RepositoryError, SessionRepository};
use crate::services::acme::AcmeService;
use crate::services::email_validation::EmailValidationService;

pub struct AppState {
    pub config: AppConfig,
    pub acme_service: AcmeService,
    pub email_validation_service: EmailValidationService,
    pub sessions: SessionRepository,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, RepositoryError> {
        let sessions = SessionRepository::connect(&config.database_url).await?;

        Ok(Self {
            acme_service: AcmeService::new(config.clone()),
            email_validation_service: EmailValidationService::new(&config),
            config,
            sessions,
        })
    }

    pub async fn prune_expired(&self) -> Result<(), RepositoryError> {
        self.sessions.prune_expired().await?;
        Ok(())
    }
}
