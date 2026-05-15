use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{TimeZone, Utc};
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::validation::normalize_domain;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/check", get(check_certificate))
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CertCheckQuery {
    host: Option<String>,
}

#[derive(Serialize)]
pub struct CertInfo {
    pub serial: String,
    pub issuer: String,
    pub issuer_o: String,
    pub issuer_cn: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub is_wildcard: bool,
    pub ct_id: i64,
}

#[derive(Serialize)]
pub struct CertCheckResponse {
    pub host: String,
    pub site_ok: bool,
    pub site_error: Option<String>,
    pub redirects_to: Option<String>,
    pub cert: Option<CertInfo>,
    pub total_ct_certs: usize,
    pub active_ct_certs: usize,
}

// ── Accept-any TLS verifier (to inspect even expired / untrusted certs) ───────

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_private_host(host: &str) -> bool {
    matches!(host, "localhost" | "0.0.0.0")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".localhost")
        || host
            .strip_prefix("172.")
            .and_then(|rest| rest.split('.').next())
            .and_then(|seg| seg.parse::<u8>().ok())
            .is_some_and(|n| (16..=31).contains(&n))
}

fn ensure_proxy_access(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let Some(expected) = state.config.proxy_shared_token.as_ref() else {
        return Ok(());
    };
    let sent = headers
        .get("x-certy-proxy-token")
        .and_then(|v| v.to_str().ok());
    if sent == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(AppError::unauthorized(
            "Acesso não autorizado. Utilize o proxy oficial.",
        ))
    }
}

fn parse_cert_der(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let tbs = &cert.tbs_certificate;

    let now = Utc::now();

    let not_before = Utc
        .timestamp_opt(tbs.validity.not_before.timestamp(), 0)
        .single()?;
    let not_after = Utc
        .timestamp_opt(tbs.validity.not_after.timestamp(), 0)
        .single()?;

    let days_remaining = (not_after - now).num_days();
    let is_expired = not_after <= now;

    let common_name = tbs
        .subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_owned();

    let issuer = tbs.issuer.to_string();
    let issuer_o = tbs
        .issuer
        .iter_organization()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_owned();
    let issuer_cn = tbs
        .issuer
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_owned();

    // SANs from SubjectAlternativeName extension
    let mut sans: Vec<String> = Vec::new();
    for ext in cert.extensions().iter() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(dns) = gn {
                    sans.push((*dns).to_owned());
                }
            }
            break;
        }
    }
    if sans.is_empty() && !common_name.is_empty() {
        sans.push(common_name.clone());
    }

    let is_wildcard = sans.iter().any(|s| s.starts_with("*."));

    // Serial → colon-separated hex (strip leading zero padding)
    let raw = tbs.serial.to_bytes_be();
    let serial_bytes: &[u8] = if raw.first() == Some(&0) && raw.len() > 1 {
        &raw[1..]
    } else {
        &raw
    };
    let serial = serial_bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    Some(CertInfo {
        serial,
        issuer,
        issuer_o,
        issuer_cn,
        common_name,
        sans,
        not_before: not_before.format("%Y-%m-%dT%H:%M:%S").to_string(),
        not_after: not_after.format("%Y-%m-%dT%H:%M:%S").to_string(),
        days_remaining,
        is_expired,
        is_wildcard,
        ct_id: 0,
    })
}

// ── Async tasks ───────────────────────────────────────────────────────────────

async fn probe_https(
    client: &reqwest::Client,
    host: &str,
) -> (bool, Option<String>, Option<String>) {
    let url = format!("https://{host}/");
    match client
        .head(&url)
        .timeout(Duration::from_secs(8))
        .send()
        .await
    {
        Ok(res) => {
            let final_url = res.url().to_string();
            let redirect = (final_url != url && final_url != format!("https://{host}"))
                .then_some(final_url);
            (true, None, redirect)
        }
        Err(err) => {
            let msg = if err.is_connect() || err.is_timeout() {
                "Não foi possível conectar via HTTPS."
            } else {
                "Erro ao verificar acesso HTTPS."
            };
            (false, Some(msg.to_owned()), None)
        }
    }
}

async fn fetch_tls_cert(host: &str) -> Option<CertInfo> {
    // Build a client config that skips validation so we can inspect any cert.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::time::timeout(
        Duration::from_secs(8),
        TcpStream::connect(format!("{host}:443")),
    )
    .await
    .ok()?
    .ok()?;

    let server_name = ServerName::try_from(host.to_owned()).ok()?;

    let tls = tokio::time::timeout(
        Duration::from_secs(8),
        connector.connect(server_name, tcp),
    )
    .await
    .ok()?
    .ok()?;

    let (_, conn) = tls.get_ref();
    let leaf_der = conn.peer_certificates()?.first()?.as_ref().to_vec();

    parse_cert_der(&leaf_der)
}

// ── Route handler ─────────────────────────────────────────────────────────────

async fn check_certificate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CertCheckQuery>,
) -> AppResult<Json<CertCheckResponse>> {
    ensure_proxy_access(&state, &headers)?;

    let raw_host = query.host.unwrap_or_default();
    let normalized = normalize_domain(&raw_host)
        .map_err(|_| AppError::validation("Informe um domínio válido (ex: example.com)."))?;
    let host = normalized
        .strip_prefix("*.")
        .unwrap_or(&normalized)
        .to_owned();

    if is_private_host(&host) {
        return Err(AppError::validation("Hosts internos não são suportados."));
    }

    let client = reqwest::Client::builder()
        .user_agent("certy/1.0")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| AppError::upstream(e.to_string()))?;

    // HTTPS probe (real TLS validation) and TLS cert fetch run concurrently.
    let (probe_result, cert) = tokio::join!(probe_https(&client, &host), fetch_tls_cert(&host));
    let (site_ok, site_error, redirects_to) = probe_result;

    if cert.is_none() && !site_ok {
        return Err(AppError::upstream(
            "Não foi possível conectar ao host. Verifique se o domínio existe e suporta HTTPS.",
        ));
    }

    Ok(Json(CertCheckResponse {
        host,
        site_ok,
        site_error,
        redirects_to,
        cert,
        total_ct_certs: 0,
        active_ct_certs: 0,
    }))
}
