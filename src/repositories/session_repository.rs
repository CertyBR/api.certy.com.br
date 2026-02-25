use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::models::{CertificateSession, DnsRecord, SessionStatus};

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
                certificate_pem,
                private_key_pem,
                last_error,
                created_at,
                updated_at,
                expires_at
            )
            VALUES (
                $1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, $13
            )
            "#,
        )
        .bind(session.id)
        .bind(&session.domain)
        .bind(&session.email)
        .bind(session.status.as_db_str())
        .bind(dns_records_json)
        .bind(&session.account_credentials_json)
        .bind(&session.order_url)
        .bind(&session.certificate_pem)
        .bind(&session.private_key_pem)
        .bind(&session.last_error)
        .bind(DateTime::<Utc>::from(session.created_at))
        .bind(DateTime::<Utc>::from(session.updated_at))
        .bind(DateTime::<Utc>::from(session.expires_at))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<CertificateSession>, RepositoryError> {
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
                certificate_pem,
                private_key_pem,
                last_error,
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
                certificate_pem = $6,
                private_key_pem = $7,
                last_error = $8,
                updated_at = $9,
                expires_at = $10
            WHERE id = $1
            "#,
        )
        .bind(session.id)
        .bind(session.status.as_db_str())
        .bind(dns_records_json)
        .bind(&session.account_credentials_json)
        .bind(&session.order_url)
        .bind(&session.certificate_pem)
        .bind(&session.private_key_pem)
        .bind(&session.last_error)
        .bind(DateTime::<Utc>::from(session.updated_at))
        .bind(DateTime::<Utc>::from(session.expires_at))
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[derive(Debug, FromRow)]
struct SessionRow {
    id: Uuid,
    domain: String,
    email: String,
    status: String,
    dns_records_json: Value,
    account_credentials_json: String,
    order_url: String,
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
    last_error: Option<String>,
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
            certificate_pem: row.certificate_pem,
            private_key_pem: row.private_key_pem,
            last_error: row.last_error,
            created_at: row.created_at.into(),
            updated_at: row.updated_at.into(),
            expires_at: row.expires_at.into(),
        })
    }
}
