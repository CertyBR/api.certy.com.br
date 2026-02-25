use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    PendingDns,
    Validating,
    Issued,
    Failed,
    Expired,
}

impl SessionStatus {
    pub fn as_db_str(self) -> &'static str {
        match self {
            SessionStatus::PendingDns => "pending_dns",
            SessionStatus::Validating => "validating",
            SessionStatus::Issued => "issued",
            SessionStatus::Failed => "failed",
            SessionStatus::Expired => "expired",
        }
    }

    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "pending_dns" => Some(SessionStatus::PendingDns),
            "validating" => Some(SessionStatus::Validating),
            "issued" => Some(SessionStatus::Issued),
            "failed" => Some(SessionStatus::Failed),
            "expired" => Some(SessionStatus::Expired),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub domain: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionResponse {
    pub session_id: Uuid,
    pub status: SessionStatus,
    pub domain: String,
    pub email: String,
    pub dns_records: Vec<DnsRecord>,
    pub created_at: u64,
    pub expires_at: u64,
    pub message: String,
}

impl CreateSessionResponse {
    pub fn from_session(session: &CertificateSession) -> Self {
        Self {
            session_id: session.id,
            status: session.status,
            domain: session.domain.clone(),
            email: session.email.clone(),
            dns_records: session.dns_records.clone(),
            created_at: unix_timestamp(session.created_at),
            expires_at: unix_timestamp(session.expires_at),
            message: "Adicione o(s) registro(s) TXT e depois chame o endpoint de finalização."
                .to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_id: Uuid,
    pub status: SessionStatus,
    pub domain: String,
    pub email: String,
    pub dns_records: Vec<DnsRecord>,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub last_error: Option<String>,
    pub certificate_pem: Option<String>,
}

impl SessionResponse {
    pub fn from_session(session: &CertificateSession) -> Self {
        Self {
            session_id: session.id,
            status: session.status,
            domain: session.domain.clone(),
            email: session.email.clone(),
            dns_records: session.dns_records.clone(),
            created_at: unix_timestamp(session.created_at),
            updated_at: unix_timestamp(session.updated_at),
            expires_at: unix_timestamp(session.expires_at),
            last_error: session.last_error.clone(),
            certificate_pem: session.certificate_pem.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FinalizeSessionResponse {
    pub session_id: Uuid,
    pub status: SessionStatus,
    pub message: String,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
}

impl FinalizeSessionResponse {
    pub fn pending(session_id: Uuid, message: impl Into<String>) -> Self {
        Self {
            session_id,
            status: SessionStatus::PendingDns,
            message: message.into(),
            certificate_pem: None,
            private_key_pem: None,
        }
    }

    pub fn issued(session: &CertificateSession, message: impl Into<String>) -> Self {
        Self {
            session_id: session.id,
            status: SessionStatus::Issued,
            message: message.into(),
            certificate_pem: session.certificate_pem.clone(),
            private_key_pem: session.private_key_pem.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CertificateSession {
    pub id: Uuid,
    pub domain: String,
    pub email: String,
    pub status: SessionStatus,
    pub dns_records: Vec<DnsRecord>,
    pub account_credentials_json: String,
    pub order_url: String,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub last_error: Option<String>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub expires_at: SystemTime,
}

impl CertificateSession {
    pub fn new(
        id: Uuid,
        domain: String,
        email: String,
        dns_records: Vec<DnsRecord>,
        account_credentials_json: String,
        order_url: String,
        ttl: Duration,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            domain,
            email,
            status: SessionStatus::PendingDns,
            dns_records,
            account_credentials_json,
            order_url,
            certificate_pem: None,
            private_key_pem: None,
            last_error: None,
            created_at: now,
            updated_at: now,
            expires_at: now + ttl,
        }
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        now.duration_since(self.expires_at).is_ok()
    }
}

pub fn unix_timestamp(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
