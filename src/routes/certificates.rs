use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::models::{
    CertificateSession, CreateSessionRequest, CreateSessionResponse, DnsPrecheckResponse,
    FinalizeSessionResponse, SessionActionResponse, SessionAuditEvent, SessionEventAction,
    SessionResponse, SessionStatus, VerifyEmailCodeRequest, VerifyEmailCodeResponse,
};
use crate::services::acme::FinalizeOutcome;
use crate::services::dns_precheck::DnsPrecheckError;
use crate::services::email_sender::EmailSenderError;
use crate::services::email_validation::EmailValidationError;
use crate::session_id::{generate_session_id, validate_session_id};
use crate::state::AppState;
use crate::validation::{normalize_domain, validate_email};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/{session_id}", get(get_session))
        .route(
            "/sessions/{session_id}/verification-code",
            post(resend_verification_code),
        )
        .route(
            "/sessions/{session_id}/verify-email",
            post(verify_email_code),
        )
        .route("/sessions/{session_id}/dns-check", post(check_dns_records))
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

    let now = SystemTime::now();
    let mut session = CertificateSession::new_pending_email_verification(
        generate_session_id(),
        domain,
        email,
        state.config.session_ttl,
    );

    let code = state.email_verification_service.generate_code();
    let code_hash = state
        .email_verification_service
        .hash_code(&session.id, &code);

    send_email_verification_code(&state, &session, &code)
        .await
        .map_err(map_email_sender_error)?;

    session.set_verification_code(code_hash, state.email_verification_service.ttl(), now);

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
            Some("Sessão criada e aguardando verificação de e-mail.".to_owned()),
            client_ip.clone(),
        ),
    )
    .await;

    log_event_best_effort(
        &state,
        SessionAuditEvent::now(
            session.id.clone(),
            session.domain.clone(),
            session.email.clone(),
            SessionEventAction::VerificationCodeSent,
            Some("Código de verificação enviado por e-mail.".to_owned()),
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

    let session = load_session_or_not_found(&state, &session_id).await?;

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

async fn resend_verification_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> AppResult<Json<SessionActionResponse>> {
    ensure_proxy_access(&state, &headers)?;
    let client_ip = extract_client_ip(&headers);
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;

    let session_id = parse_session_id(&session_id)?;
    let mut session = load_session_or_not_found(&state, &session_id).await?;
    ensure_active_session(&session)?;

    if session.email_verified_at.is_some()
        || session.status != SessionStatus::AwaitingEmailVerification
    {
        return Err(AppError::conflict(
            "Esta sessão já concluiu a verificação de e-mail.",
        ));
    }

    let now = SystemTime::now();
    let code = state.email_verification_service.generate_code();
    let code_hash = state
        .email_verification_service
        .hash_code(&session.id, &code);

    send_email_verification_code(&state, &session, &code)
        .await
        .map_err(map_email_sender_error)?;

    session.set_verification_code(code_hash, state.email_verification_service.ttl(), now);

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
            SessionEventAction::VerificationCodeSent,
            Some("Novo código de verificação enviado por e-mail.".to_owned()),
            client_ip,
        ),
    )
    .await;

    Ok(Json(SessionActionResponse::from_session(
        &session,
        "Novo código enviado para seu e-mail.",
    )))
}

async fn verify_email_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(payload): Json<VerifyEmailCodeRequest>,
) -> AppResult<Json<VerifyEmailCodeResponse>> {
    ensure_proxy_access(&state, &headers)?;
    let client_ip = extract_client_ip(&headers);
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;

    let session_id = parse_session_id(&session_id)?;
    let mut session = load_session_or_not_found(&state, &session_id).await?;
    ensure_active_session(&session)?;

    if session.email_verified_at.is_some() || session.status == SessionStatus::PendingDns {
        return Ok(Json(VerifyEmailCodeResponse::from_session(
            &session,
            "E-mail já verificado nesta sessão.",
        )));
    }

    if session.status != SessionStatus::AwaitingEmailVerification {
        return Err(AppError::conflict(
            "Esta sessão não está em etapa de verificação de e-mail.",
        ));
    }

    let now = SystemTime::now();
    let submitted_code = state
        .email_verification_service
        .validate_code_format(&payload.code)
        .map_err(AppError::validation)?;

    let Some(stored_hash) = session.email_verification_code_hash.clone() else {
        return Err(AppError::conflict(
            "Código indisponível. Solicite um novo código.",
        ));
    };

    if session.verification_code_is_expired(now) {
        session.last_error = Some("Código expirado. Solicite um novo código.".to_owned());
        session.updated_at = now;
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
                SessionEventAction::VerificationCodeFailed,
                Some("Tentativa com código expirado.".to_owned()),
                client_ip,
            ),
        )
        .await;

        return Err(AppError::conflict(
            "Código expirado. Solicite um novo código.",
        ));
    }

    let max_attempts = state.email_verification_service.max_attempts() as i32;
    if session.email_verification_attempts >= max_attempts {
        session.status = SessionStatus::Failed;
        session.last_error = Some(
            "Limite de tentativas de verificação atingido. Inicie uma nova sessão.".to_owned(),
        );
        session.updated_at = now;
        state
            .sessions
            .update(&session)
            .await
            .map_err(|err| AppError::storage(err.to_string()))?;

        return Err(AppError::conflict(
            "Limite de tentativas de verificação atingido. Inicie uma nova sessão.",
        ));
    }

    let is_valid =
        state
            .email_verification_service
            .verify_code(&session.id, &submitted_code, &stored_hash);

    if !is_valid {
        session.email_verification_attempts += 1;
        session.updated_at = now;

        let remaining = (max_attempts - session.email_verification_attempts).max(0);
        session.last_error = Some(format!(
            "Código inválido. Tentativas restantes: {remaining}."
        ));

        if session.email_verification_attempts >= max_attempts {
            session.status = SessionStatus::Failed;
            session.last_error = Some(
                "Limite de tentativas de verificação atingido. Inicie uma nova sessão.".to_owned(),
            );
        }

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
                SessionEventAction::VerificationCodeFailed,
                session.last_error.clone(),
                client_ip,
            ),
        )
        .await;

        return Err(AppError::validation(
            session
                .last_error
                .clone()
                .unwrap_or_else(|| "Código inválido.".to_owned()),
        ));
    }

    let bootstrap = state
        .acme_service
        .create_order(&session.domain, &session.email)
        .await
        .map_err(AppError::acme)?;

    session.mark_email_verified(now);
    session.status = SessionStatus::PendingDns;
    session.updated_at = SystemTime::now();
    session.last_error = None;
    session.dns_records = bootstrap.dns_records;
    session.account_credentials_json = bootstrap.account_credentials_json;
    session.order_url = bootstrap.order_url;

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
            SessionEventAction::VerificationCodeVerified,
            Some("E-mail validado e registros DNS gerados.".to_owned()),
            client_ip,
        ),
    )
    .await;

    Ok(Json(VerifyEmailCodeResponse::from_session(
        &session,
        "E-mail verificado com sucesso. Configure os registros DNS para continuar.",
    )))
}

async fn check_dns_records(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> AppResult<Json<DnsPrecheckResponse>> {
    ensure_proxy_access(&state, &headers)?;
    let client_ip = extract_client_ip(&headers);
    state
        .prune_expired()
        .await
        .map_err(|err| AppError::storage(err.to_string()))?;

    let session_id = parse_session_id(&session_id)?;
    let mut session = load_session_or_not_found(&state, &session_id).await?;
    ensure_active_session(&session)?;

    if session.email_verified_at.is_none() {
        return Err(AppError::conflict(
            "Verifique o e-mail antes de validar os registros DNS.",
        ));
    }

    if session.status != SessionStatus::PendingDns && session.status != SessionStatus::Failed {
        return Err(AppError::conflict(
            "A sessão não está em etapa de validação DNS.",
        ));
    }

    if session.dns_records.is_empty() {
        return Err(AppError::conflict(
            "Sessão sem registros DNS. Verifique a etapa anterior.",
        ));
    }

    let precheck = state
        .dns_precheck_service
        .check_dns_records(&session.dns_records)
        .await
        .map_err(map_dns_precheck_error)?;

    session.updated_at = SystemTime::now();

    if precheck.is_ready() {
        session.last_error = None;
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
                SessionEventAction::DnsPrecheckPassed,
                Some("Pré-checagem DNS concluída com sucesso.".to_owned()),
                client_ip,
            ),
        )
        .await;

        return Ok(Json(DnsPrecheckResponse::success(
            session.id.clone(),
            session.status,
            "DNS propagado. Você já pode emitir o certificado.",
        )));
    }

    session.last_error = Some(
        "Registro DNS ainda não encontrado com o valor esperado. Aguarde propagação.".to_owned(),
    );

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
            SessionEventAction::DnsPrecheckFailed,
            Some(format!(
                "Pré-checagem DNS falhou. missing_records={}",
                precheck.missing_records.len()
            )),
            client_ip,
        ),
    )
    .await;

    Ok(Json(DnsPrecheckResponse::missing(
        session.id.clone(),
        session.status,
        precheck.missing_records,
        "DNS ainda não propagou totalmente. Aguarde e tente novamente.",
    )))
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

    let mut session = load_session_or_not_found(&state, &session_id).await?;
    ensure_active_session(&session)?;

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

    if session.email_verified_at.is_none() {
        return Err(AppError::conflict(
            "Verifique o e-mail antes de prosseguir com a emissão.",
        ));
    }

    if session.status == SessionStatus::AwaitingEmailVerification {
        return Err(AppError::conflict(
            "Sessão aguardando verificação de e-mail.",
        ));
    }

    if session.dns_records.is_empty()
        || session.account_credentials_json.trim().is_empty()
        || session.order_url.trim().is_empty()
    {
        return Err(AppError::conflict(
            "Sessão incompleta para emissão. Refaça a verificação de e-mail.",
        ));
    }

    let precheck = state
        .dns_precheck_service
        .check_dns_records(&session.dns_records)
        .await
        .map_err(map_dns_precheck_error)?;

    if !precheck.is_ready() {
        session.status = SessionStatus::PendingDns;
        session.updated_at = SystemTime::now();
        session.last_error = Some(
            "DNS ainda não propagou completamente. Ajuste os registros e tente novamente."
                .to_owned(),
        );
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
                SessionEventAction::DnsPrecheckFailed,
                Some(format!(
                    "Pré-checagem DNS bloqueou finalização. missing_records={}",
                    precheck.missing_records.len()
                )),
                client_ip,
            ),
        )
        .await;

        return Ok(Json(FinalizeSessionResponse::pending(
            session.id.clone(),
            "DNS ainda não propagou totalmente. Tente novamente em alguns minutos.",
        )));
    }

    log_event_best_effort(
        &state,
        SessionAuditEvent::now(
            session.id.clone(),
            session.domain.clone(),
            session.email.clone(),
            SessionEventAction::DnsPrecheckPassed,
            Some("Pré-checagem DNS aprovada antes da CA.".to_owned()),
            client_ip.clone(),
        ),
    )
    .await;

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
    session.updated_at = SystemTime::now();
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
                "Certificado emitido com sucesso. Este conteúdo é exibido apenas uma vez e nenhuma chave foi armazenada.",
            )))
        }
    }
}

fn parse_session_id(session_id: &str) -> AppResult<String> {
    validate_session_id(session_id)
}

async fn load_session_or_not_found(
    state: &Arc<AppState>,
    session_id: &str,
) -> AppResult<CertificateSession> {
    state
        .sessions
        .get_by_id(session_id)
        .await
        .map_err(|err| AppError::storage(err.to_string()))?
        .ok_or_else(|| AppError::not_found("Sessão não encontrada."))
}

fn ensure_active_session(session: &CertificateSession) -> AppResult<()> {
    let now = SystemTime::now();
    if session.is_expired(now) {
        return Err(AppError::conflict("Sessão expirada. Gere uma nova sessão."));
    }
    Ok(())
}

async fn send_email_verification_code(
    state: &Arc<AppState>,
    session: &CertificateSession,
    code: &str,
) -> Result<(), EmailSenderError> {
    state
        .email_sender_service
        .send_verification_code(
            &session.email,
            &session.domain,
            code,
            state.email_verification_service.ttl(),
        )
        .await
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

fn map_email_sender_error(err: EmailSenderError) -> AppError {
    match err {
        EmailSenderError::InvalidConfig(message) => AppError::storage(message),
        EmailSenderError::Send(message) => AppError::upstream(message),
    }
}

fn map_dns_precheck_error(err: DnsPrecheckError) -> AppError {
    match err {
        DnsPrecheckError::Upstream(message) => AppError::upstream(message),
    }
}
