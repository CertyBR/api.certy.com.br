use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{
    CertificateSession, CreateSessionRequest, CreateSessionResponse, FinalizeSessionResponse,
    SessionResponse, SessionStatus,
};
use crate::services::acme::FinalizeOutcome;
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
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;

    let domain = normalize_domain(&payload.domain)?;
    let email = validate_email(&payload.email)?;
    let bootstrap = state
        .acme_service
        .create_order(&domain, &email)
        .await
        .map_err(AppError::acme)?;

    let session = CertificateSession::new(
        Uuid::new_v4(),
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

    Ok(Json(response))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> AppResult<Json<SessionResponse>> {
    ensure_proxy_access(&state, &headers)?;
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;
    let session_id = parse_session_id(&session_id)?;

    let session = state
        .sessions
        .get_by_id(session_id)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?
        .ok_or_else(|| AppError::not_found("Sessão não encontrada."))?;

    Ok(Json(SessionResponse::from_session(&session)))
}

async fn finalize_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> AppResult<Json<FinalizeSessionResponse>> {
    ensure_proxy_access(&state, &headers)?;
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;
    let session_id = parse_session_id(&session_id)?;

    let mut session = state
        .sessions
        .get_by_id(session_id)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?
        .ok_or_else(|| AppError::not_found("Sessão não encontrada."))?;

    let now = SystemTime::now();
    if session.is_expired(now) {
        return Err(AppError::conflict("Sessão expirada. Gere uma nova sessão."));
    }

    if session.status == SessionStatus::Issued {
        return Ok(Json(FinalizeSessionResponse::issued(
            &session,
            "Certificado já emitido para esta sessão.",
        )));
    }

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
            Ok(Json(FinalizeSessionResponse::pending(session.id, reason)))
        }
        FinalizeOutcome::Issued(issued) => {
            session.status = SessionStatus::Issued;
            session.updated_at = SystemTime::now();
            session.last_error = None;
            session.certificate_pem = Some(issued.certificate_pem);
            session.private_key_pem = Some(issued.private_key_pem);
            state
                .sessions
                .update(&session)
                .await
                .map_err(|err| AppError::storage(err.to_string()))?;

            Ok(Json(FinalizeSessionResponse::issued(
                &session,
                "Certificado emitido com sucesso.",
            )))
        }
    }
}

fn parse_session_id(session_id: &str) -> AppResult<Uuid> {
    Uuid::parse_str(session_id)
        .map_err(|_| AppError::validation("session_id inválido (esperado UUID)."))
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
