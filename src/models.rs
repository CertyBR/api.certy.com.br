use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    AwaitingEmailVerification,
    PendingDns,
    Validating,
    Issued,
    Failed,
    Expired,
}

impl SessionStatus {
    pub fn as_db_str(self) -> &'static str {
        match self {
            SessionStatus::AwaitingEmailVerification => "awaiting_email_verification",
            SessionStatus::PendingDns => "pending_dns",
            SessionStatus::Validating => "validating",
            SessionStatus::Issued => "issued",
            SessionStatus::Failed => "failed",
            SessionStatus::Expired => "expired",
        }
    }

    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "awaiting_email_verification" => Some(SessionStatus::AwaitingEmailVerification),
            "pending_dns" => Some(SessionStatus::PendingDns),
            "validating" => Some(SessionStatus::Validating),
            "issued" => Some(SessionStatus::Issued),
            "failed" => Some(SessionStatus::Failed),
            "expired" => Some(SessionStatus::Expired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionEventAction {
    SessionCreated,
    SessionFetched,
    VerificationCodeSent,
    VerificationCodeVerified,
    VerificationCodeFailed,
    DnsPrecheckPassed,
    DnsPrecheckFailed,
    FinalizeRequested,
    ValidationPending,
    CertificateIssued,
    FinalizeFailed,
    SessionInvalidated,
}

impl SessionEventAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            SessionEventAction::SessionCreated => "session_created",
            SessionEventAction::SessionFetched => "session_fetched",
            SessionEventAction::VerificationCodeSent => "verification_code_sent",
            SessionEventAction::VerificationCodeVerified => "verification_code_verified",
            SessionEventAction::VerificationCodeFailed => "verification_code_failed",
            SessionEventAction::DnsPrecheckPassed => "dns_precheck_passed",
            SessionEventAction::DnsPrecheckFailed => "dns_precheck_failed",
            SessionEventAction::FinalizeRequested => "finalize_requested",
            SessionEventAction::ValidationPending => "validation_pending",
            SessionEventAction::CertificateIssued => "certificate_issued",
            SessionEventAction::FinalizeFailed => "finalize_failed",
            SessionEventAction::SessionInvalidated => "session_invalidated",
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

#[derive(Debug, Deserialize)]
pub struct VerifyEmailCodeRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub domain: String,
    pub email: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub message: String,
}

impl CreateSessionResponse {
    pub fn from_session(session: &CertificateSession) -> Self {
        Self {
            session_id: session.id.clone(),
            status: session.status,
            domain: session.domain.clone(),
            email: session.email.clone(),
            created_at: unix_timestamp(session.created_at),
            expires_at: unix_timestamp(session.expires_at),
            message: "Código de verificação enviado por e-mail. Valide para continuar a emissão."
                .to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailCodeResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub dns_records: Vec<DnsRecord>,
    pub message: String,
}

impl VerifyEmailCodeResponse {
    pub fn from_session(session: &CertificateSession, message: impl Into<String>) -> Self {
        Self {
            session_id: session.id.clone(),
            status: session.status,
            dns_records: session.dns_records.clone(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DnsPrecheckResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub dns_ready: bool,
    pub missing_records: Vec<DnsRecord>,
    pub message: String,
}

impl DnsPrecheckResponse {
    pub fn success(
        session_id: impl Into<String>,
        status: SessionStatus,
        message: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            status,
            dns_ready: true,
            missing_records: Vec::new(),
            message: message.into(),
        }
    }

    pub fn missing(
        session_id: impl Into<String>,
        status: SessionStatus,
        missing_records: Vec<DnsRecord>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            status,
            dns_ready: false,
            missing_records,
            message: message.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionActionResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub message: String,
}

impl SessionActionResponse {
    pub fn from_session(session: &CertificateSession, message: impl Into<String>) -> Self {
        Self {
            session_id: session.id.clone(),
            status: session.status,
            message: message.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub domain: String,
    pub email: String,
    pub dns_records: Vec<DnsRecord>,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub last_error: Option<String>,
    pub email_verified_at: Option<u64>,
    pub email_verification_expires_at: Option<u64>,
    pub email_verification_attempts: u32,
}

impl SessionResponse {
    pub fn from_session(session: &CertificateSession) -> Self {
        Self {
            session_id: session.id.clone(),
            status: session.status,
            domain: session.domain.clone(),
            email: session.email.clone(),
            dns_records: session.dns_records.clone(),
            created_at: unix_timestamp(session.created_at),
            updated_at: unix_timestamp(session.updated_at),
            expires_at: unix_timestamp(session.expires_at),
            last_error: session.last_error.clone(),
            email_verified_at: session.email_verified_at.map(unix_timestamp),
            email_verification_expires_at: session
                .email_verification_expires_at
                .map(unix_timestamp),
            email_verification_attempts: session.email_verification_attempts.max(0) as u32,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FinalizeSessionResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub message: String,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
}

impl FinalizeSessionResponse {
    pub fn pending(session_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            status: SessionStatus::PendingDns,
            message: message.into(),
            certificate_pem: None,
            private_key_pem: None,
        }
    }

    pub fn issued_ephemeral(
        session_id: impl Into<String>,
        certificate_pem: String,
        private_key_pem: String,
        message: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            status: SessionStatus::Issued,
            message: message.into(),
            certificate_pem: Some(certificate_pem),
            private_key_pem: Some(private_key_pem),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionAuditEvent {
    pub session_id: String,
    pub domain: String,
    pub email: String,
    pub action: SessionEventAction,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub occurred_at: SystemTime,
}

impl SessionAuditEvent {
    pub fn now(
        session_id: impl Into<String>,
        domain: impl Into<String>,
        email: impl Into<String>,
        action: SessionEventAction,
        details: Option<String>,
        ip_address: Option<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            domain: domain.into(),
            email: email.into(),
            action,
            details,
            ip_address,
            occurred_at: SystemTime::now(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CertificateSession {
    pub id: String,
    pub domain: String,
    pub email: String,
    pub status: SessionStatus,
    pub dns_records: Vec<DnsRecord>,
    pub account_credentials_json: String,
    pub order_url: String,
    pub last_error: Option<String>,
    pub email_verification_code_hash: Option<String>,
    pub email_verification_expires_at: Option<SystemTime>,
    pub email_verification_attempts: i32,
    pub email_verified_at: Option<SystemTime>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub expires_at: SystemTime,
}

impl CertificateSession {
    pub fn new_pending_email_verification(
        id: String,
        domain: String,
        email: String,
        ttl: Duration,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            domain,
            email,
            status: SessionStatus::AwaitingEmailVerification,
            dns_records: Vec::new(),
            account_credentials_json: String::new(),
            order_url: String::new(),
            last_error: None,
            email_verification_code_hash: None,
            email_verification_expires_at: None,
            email_verification_attempts: 0,
            email_verified_at: None,
            created_at: now,
            updated_at: now,
            expires_at: now + ttl,
        }
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        now.duration_since(self.expires_at).is_ok()
    }

    pub fn set_verification_code(&mut self, code_hash: String, ttl: Duration, now: SystemTime) {
        self.email_verification_code_hash = Some(code_hash);
        self.email_verification_expires_at = Some(now + ttl);
        self.email_verification_attempts = 0;
        self.email_verified_at = None;
        self.status = SessionStatus::AwaitingEmailVerification;
        self.last_error = None;
        self.updated_at = now;
    }

    pub fn verification_code_is_expired(&self, now: SystemTime) -> bool {
        match self.email_verification_expires_at {
            Some(expires_at) => now.duration_since(expires_at).is_ok(),
            None => true,
        }
    }

    pub fn mark_email_verified(&mut self, now: SystemTime) {
        self.email_verified_at = Some(now);
        self.email_verification_code_hash = None;
        self.email_verification_expires_at = None;
        self.email_verification_attempts = 0;
        self.last_error = None;
        self.updated_at = now;
    }
}

pub fn unix_timestamp(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
