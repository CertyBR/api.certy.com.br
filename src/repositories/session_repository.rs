use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use thiserror::Error;

use crate::models::{CertificateSession, DnsRecord, SessionAuditEvent, SessionStatus};

#[derive(Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("{0}")]
    Decode(String),
}

impl SessionRepository {
    pub async fn connect(database_url: &str) -> Result<Self, RepositoryError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn prune_expired(&self) -> Result<u64, RepositoryError> {
        let result = sqlx::query("DELETE FROM certificate_sessions WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn insert(&self, session: &CertificateSession) -> Result<(), RepositoryError> {
        let dns_records_json = serde_json::to_value(&session.dns_records).map_err(|err| {
            RepositoryError::Decode(format!("falha serializando dns_records: {err}"))
        })?;

        sqlx::query(
            r#"
            INSERT INTO certificate_sessions (
                id,
                domain,
                email,
                status,
                dns_records_json,
                account_credentials_json,
                order_url,
                last_error,
                email_verification_code_hash,
                email_verification_expires_at,
                email_verification_last_sent_at,
                email_verification_attempts,
                email_verification_resend_count,
                email_verified_at,
                created_at,
                updated_at,
                expires_at
            )
            VALUES (
                $1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
            )
            "#,
        )
        .bind(&session.id)
        .bind(&session.domain)
        .bind(&session.email)
        .bind(session.status.as_db_str())
        .bind(dns_records_json)
        .bind(&session.account_credentials_json)
        .bind(&session.order_url)
        .bind(&session.last_error)
        .bind(&session.email_verification_code_hash)
        .bind(
            session
                .email_verification_expires_at
                .map(DateTime::<Utc>::from),
        )
        .bind(
            session
                .email_verification_last_sent_at
                .map(DateTime::<Utc>::from),
        )
        .bind(session.email_verification_attempts)
        .bind(session.email_verification_resend_count)
        .bind(session.email_verified_at.map(DateTime::<Utc>::from))
        .bind(DateTime::<Utc>::from(session.created_at))
        .bind(DateTime::<Utc>::from(session.updated_at))
        .bind(DateTime::<Utc>::from(session.expires_at))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<CertificateSession>, RepositoryError> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT
                id,
                domain,
                email,
                status,
                dns_records_json,
                account_credentials_json,
                order_url,
                last_error,
                email_verification_code_hash,
                email_verification_expires_at,
                email_verification_last_sent_at,
                email_verification_attempts,
                email_verification_resend_count,
                email_verified_at,
                created_at,
                updated_at,
                expires_at
            FROM certificate_sessions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    pub async fn update(&self, session: &CertificateSession) -> Result<(), RepositoryError> {
        let dns_records_json = serde_json::to_value(&session.dns_records).map_err(|err| {
            RepositoryError::Decode(format!("falha serializando dns_records: {err}"))
        })?;

        sqlx::query(
            r#"
            UPDATE certificate_sessions
            SET
                status = $2,
                dns_records_json = $3::jsonb,
                account_credentials_json = $4,
                order_url = $5,
                last_error = $6,
                email_verification_code_hash = $7,
                email_verification_expires_at = $8,
                email_verification_last_sent_at = $9,
                email_verification_attempts = $10,
                email_verification_resend_count = $11,
                email_verified_at = $12,
                updated_at = $13,
                expires_at = $14
            WHERE id = $1
            "#,
        )
        .bind(&session.id)
        .bind(session.status.as_db_str())
        .bind(dns_records_json)
        .bind(&session.account_credentials_json)
        .bind(&session.order_url)
        .bind(&session.last_error)
        .bind(&session.email_verification_code_hash)
        .bind(
            session
                .email_verification_expires_at
                .map(DateTime::<Utc>::from),
        )
        .bind(
            session
                .email_verification_last_sent_at
                .map(DateTime::<Utc>::from),
        )
        .bind(session.email_verification_attempts)
        .bind(session.email_verification_resend_count)
        .bind(session.email_verified_at.map(DateTime::<Utc>::from))
        .bind(DateTime::<Utc>::from(session.updated_at))
        .bind(DateTime::<Utc>::from(session.expires_at))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_by_id(&self, id: &str) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM certificate_sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn insert_event(&self, event: &SessionAuditEvent) -> Result<(), RepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO certificate_session_events (
                session_id,
                domain,
                email,
                action,
                details,
                ip_address,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&event.session_id)
        .bind(&event.domain)
        .bind(&event.email)
        .bind(event.action.as_db_str())
        .bind(&event.details)
        .bind(&event.ip_address)
        .bind(DateTime::<Utc>::from(event.occurred_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug, FromRow)]
struct SessionRow {
    id: String,
    domain: String,
    email: String,
    status: String,
    dns_records_json: Value,
    account_credentials_json: String,
    order_url: String,
    last_error: Option<String>,
    email_verification_code_hash: Option<String>,
    email_verification_expires_at: Option<DateTime<Utc>>,
    email_verification_last_sent_at: Option<DateTime<Utc>>,
    email_verification_attempts: i32,
    email_verification_resend_count: i32,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl TryFrom<SessionRow> for CertificateSession {
    type Error = RepositoryError;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        let status = SessionStatus::from_db_str(&row.status).ok_or_else(|| {
            RepositoryError::Decode(format!(
                "status de sessão inválido no banco: {}",
                row.status
            ))
        })?;

        let dns_records: Vec<DnsRecord> =
            serde_json::from_value(row.dns_records_json).map_err(|err| {
                RepositoryError::Decode(format!("falha desserializando dns_records: {err}"))
            })?;

        Ok(CertificateSession {
            id: row.id,
            domain: row.domain,
            email: row.email,
            status,
            dns_records,
            account_credentials_json: row.account_credentials_json,
            order_url: row.order_url,
            last_error: row.last_error,
            email_verification_code_hash: row.email_verification_code_hash,
            email_verification_expires_at: row.email_verification_expires_at.map(Into::into),
            email_verification_last_sent_at: row.email_verification_last_sent_at.map(Into::into),
            email_verification_attempts: row.email_verification_attempts,
            email_verification_resend_count: row.email_verification_resend_count,
            email_verified_at: row.email_verified_at.map(Into::into),
            created_at: row.created_at.into(),
            updated_at: row.updated_at.into(),
            expires_at: row.expires_at.into(),
        })
    }
}
