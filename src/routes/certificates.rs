use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::models::{
    CertificateSession, CreateSessionRequest, CreateSessionResponse, FinalizeSessionResponse,
    SessionAuditEvent, SessionEventAction, SessionResponse, SessionStatus,
};
use crate::services::acme::FinalizeOutcome;
use crate::services::email_validation::EmailValidationError;
use crate::session_id::{generate_session_id, validate_session_id};
use crate::state::AppState;
use crate::validation::{normalize_domain, validate_email};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/{session_id}", get(get_session))
        .route("/sessions/{session_id}/finalize", post(finalize_session))
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateSessionRequest>,
) -> AppResult<Json<CreateSessionResponse>> {
    ensure_proxy_access(&state, &headers)?;
    let client_ip = extract_client_ip(&headers);
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;

    let domain = normalize_domain(&payload.domain)?;
    let email = validate_email(&payload.email)?;
    state
        .email_validation_service
        .validate_email(&email)
        .await
        .map_err(map_email_validation_error)?;
    let bootstrap = state
        .acme_service
        .create_order(&domain, &email)
        .await
        .map_err(AppError::acme)?;

    let session = CertificateSession::new(
        generate_session_id(),
        domain,
        email,
        bootstrap.dns_records,
        bootstrap.account_credentials_json,
        bootstrap.order_url,
        state.config.session_ttl,
    );

    let response = CreateSessionResponse::from_session(&session);
    state
        .sessions
        .insert(&session)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;
    log_event_best_effort(
        &state,
        SessionAuditEvent::now(
            session.id.clone(),
            session.domain.clone(),
            session.email.clone(),
            SessionEventAction::SessionCreated,
            Some("Sessão criada.".to_owned()),
            client_ip,
        ),
    )
    .await;

    Ok(Json(response))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> AppResult<Json<SessionResponse>> {
    ensure_proxy_access(&state, &headers)?;
    let client_ip = extract_client_ip(&headers);
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;
    let session_id = parse_session_id(&session_id)?;

    let session = state
        .sessions
        .get_by_id(&session_id)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?
        .ok_or_else(|| AppError::not_found("Sessão não encontrada."))?;

    log_event_best_effort(
        &state,
        SessionAuditEvent::now(
            session.id.clone(),
            session.domain.clone(),
            session.email.clone(),
            SessionEventAction::SessionFetched,
            Some(format!(
                "Sessão consultada. status={}",
                session.status.as_db_str()
            )),
            client_ip,
        ),
    )
    .await;

    Ok(Json(SessionResponse::from_session(&session)))
}

async fn finalize_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> AppResult<Json<FinalizeSessionResponse>> {
    ensure_proxy_access(&state, &headers)?;
    let client_ip = extract_client_ip(&headers);
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;
    let session_id = parse_session_id(&session_id)?;

    let mut session = state
        .sessions
        .get_by_id(&session_id)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?
        .ok_or_else(|| AppError::not_found("Sessão não encontrada."))?;

    let now = SystemTime::now();
    if session.is_expired(now) {
        return Err(AppError::conflict("Sessão expirada. Gere uma nova sessão."));
    }

    if session.status == SessionStatus::Issued {
        let _ = state.sessions.delete_by_id(&session.id).await;
        log_event_best_effort(
            &state,
            SessionAuditEvent::now(
                session.id.clone(),
                session.domain.clone(),
                session.email.clone(),
                SessionEventAction::SessionInvalidated,
                Some("Sessão já finalizada anteriormente e foi invalidada.".to_owned()),
                client_ip,
            ),
        )
        .await;
        return Err(AppError::conflict(
            "Sessão já finalizada. Gere uma nova emissão.",
        ));
    }

    log_event_best_effort(
        &state,
        SessionAuditEvent::now(
            session.id.clone(),
            session.domain.clone(),
            session.email.clone(),
            SessionEventAction::FinalizeRequested,
            Some("Finalização solicitada.".to_owned()),
            client_ip.clone(),
        ),
    )
    .await;

    session.status = SessionStatus::Validating;
    session.updated_at = now;
    session.last_error = None;
    state
        .sessions
        .update(&session)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;

    let account_credentials_json = session.account_credentials_json.clone();
    let order_url = session.order_url.clone();

    let outcome = match state
        .acme_service
        .finalize_order(&account_credentials_json, &order_url)
        .await
    {
        Ok(outcome) => outcome,
        Err(err_message) => {
            session.status = SessionStatus::Failed;
            session.updated_at = SystemTime::now();
            session.last_error = Some(err_message.clone());
            state
                .sessions
                .update(&session)
                .await
                .map_err(|err| AppError::storage(err.to_string()))?;
            log_event_best_effort(
                &state,
                SessionAuditEvent::now(
                    session.id.clone(),
                    session.domain.clone(),
                    session.email.clone(),
                    SessionEventAction::FinalizeFailed,
                    Some(err_message.clone()),
                    client_ip,
                ),
            )
            .await;
            return Err(AppError::acme(err_message));
        }
    };

    match outcome {
        FinalizeOutcome::PendingDns { reason } => {
            session.status = SessionStatus::PendingDns;
            session.updated_at = SystemTime::now();
            session.last_error = Some(reason.clone());
            state
                .sessions
                .update(&session)
                .await
                .map_err(|err| AppError::storage(err.to_string()))?;
            log_event_best_effort(
                &state,
                SessionAuditEvent::now(
                    session.id.clone(),
                    session.domain.clone(),
                    session.email.clone(),
                    SessionEventAction::ValidationPending,
                    Some(reason.clone()),
                    client_ip,
                ),
            )
            .await;
            Ok(Json(FinalizeSessionResponse::pending(
                session.id.clone(),
                reason,
            )))
        }
        FinalizeOutcome::Issued(issued) => {
            log_event_best_effort(
                &state,
                SessionAuditEvent::now(
                    session.id.clone(),
                    session.domain.clone(),
                    session.email.clone(),
                    SessionEventAction::CertificateIssued,
                    Some("Certificado emitido e entregue em resposta efêmera.".to_owned()),
                    client_ip.clone(),
                ),
            )
            .await;

            state
                .sessions
                .delete_by_id(&session.id)
                .await
                .map_err(|err| AppError::storage(err.to_string()))?;
            log_event_best_effort(
                &state,
                SessionAuditEvent::now(
                    session.id.clone(),
                    session.domain.clone(),
                    session.email.clone(),
                    SessionEventAction::SessionInvalidated,
                    Some("Sessão encerrada após emissão.".to_owned()),
                    client_ip,
                ),
            )
            .await;

            Ok(Json(FinalizeSessionResponse::issued_ephemeral(
                session.id.clone(),
                issued.certificate_pem,
                issued.private_key_pem,
                "Certificado emitido com sucesso. Esta sessão foi encerrada e nenhuma chave foi armazenada.",
            )))
        }
    }
}

fn parse_session_id(session_id: &str) -> AppResult<String> {
    validate_session_id(session_id)
}

fn ensure_proxy_access(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let Some(expected_token) = state.config.proxy_shared_token.as_ref() else {
        return Ok(());
    };

    let sent_token = headers
        .get("x-certy-proxy-token")
        .and_then(|value| value.to_str().ok());

    if sent_token == Some(expected_token.as_str()) {
        Ok(())
    } else {
        Err(AppError::unauthorized(
            "Acesso não autorizado. Utilize o proxy oficial.",
        ))
    }
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    if forwarded.is_some() {
        return forwarded;
    }

    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

async fn log_event_best_effort(state: &Arc<AppState>, event: SessionAuditEvent) {
    if let Err(err) = state.sessions.insert_event(&event).await {
        warn!(
            session_id = %event.session_id,
            action = event.action.as_db_str(),
            error = %err,
            "falha ao gravar evento de auditoria da sessão"
        );
    }
}

fn map_email_validation_error(err: EmailValidationError) -> AppError {
    match err {
        EmailValidationError::Invalid(message) => AppError::validation(message),
        EmailValidationError::Upstream(message) => AppError::upstream(message),
    }
}
