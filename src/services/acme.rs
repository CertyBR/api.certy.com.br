use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Error as AcmeError,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};

use crate::config::AppConfig;
use crate::models::DnsRecord;

#[derive(Clone)]
pub struct AcmeService {
    config: AppConfig,
}

#[derive(Debug, Clone)]
pub struct AcmeOrderBootstrap {
    pub account_credentials_json: String,
    pub order_url: String,
    pub dns_records: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Clone)]
pub enum FinalizeOutcome {
    Issued(IssuedCertificate),
    PendingDns { reason: String },
}

impl AcmeService {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub async fn create_order(
        &self,
        domain: &str,
        fallback_contact_email: &str,
        shared_account_credentials_json: Option<&str>,
    ) -> Result<AcmeOrderBootstrap, String> {
        let (account, account_credentials_json) = self
            .load_or_create_account(fallback_contact_email, shared_account_credentials_json)
            .await?;

        let identifiers = vec![Identifier::Dns(domain.to_owned())];
        let mut order = account
            .new_order(&NewOrder::new(identifiers.as_slice()))
            .await
            .map_err(acme_error_to_string)?;

        let order_url = order.url().to_owned();

        let mut dns_records = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(acme_error_to_string)?;
            match authz.status {
                AuthorizationStatus::Pending => {
                    let challenge = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| "desafio DNS-01 não encontrado para o domínio".to_owned())?;

                    let identifier = challenge.identifier().to_string();
                    let dns_name =
                        format!("_acme-challenge.{}", identifier.trim_start_matches("*."));
                    let dns_value = challenge.key_authorization().dns_value();

                    dns_records.push(DnsRecord {
                        record_type: "TXT".to_owned(),
                        name: dns_name,
                        value: dns_value,
                    });
                }
                AuthorizationStatus::Valid => {}
                status => {
                    return Err(format!(
                        "autorização em estado inesperado durante criação do pedido: {status:?}"
                    ));
                }
            }
        }

        Ok(AcmeOrderBootstrap {
            account_credentials_json,
            order_url,
            dns_records,
        })
    }

    async fn load_or_create_account(
        &self,
        fallback_contact_email: &str,
        shared_account_credentials_json: Option<&str>,
    ) -> Result<(Account, String), String> {
        if let Some(credentials_json) = shared_account_credentials_json {
            let credentials_json = credentials_json.trim();
            if !credentials_json.is_empty() {
                let account_credentials: AccountCredentials =
                    serde_json::from_str(credentials_json).map_err(|err| {
                        format!("credenciais ACME compartilhadas inválidas: {err}")
                    })?;
                let account = Account::builder()
                    .map_err(acme_error_to_string)?
                    .from_credentials(account_credentials)
                    .await
                    .map_err(acme_error_to_string)?;
                return Ok((account, credentials_json.to_owned()));
            }
        }

        let contact_email = self
            .config
            .acme_account_contact_email
            .clone()
            .unwrap_or_else(|| fallback_contact_email.to_owned());
        let contact_mailto = format!("mailto:{contact_email}");
        let contacts = vec![contact_mailto.as_str()];

        let (account, credentials) = Account::builder()
            .map_err(acme_error_to_string)?
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.config.acme_directory_url.clone(),
                None,
            )
            .await
            .map_err(acme_error_to_string)?;

        let account_credentials_json = serde_json::to_string(&credentials)
            .map_err(|err| format!("erro ao serializar credenciais da conta ACME: {err}"))?;

        Ok((account, account_credentials_json))
    }

    pub async fn finalize_order(
        &self,
        account_credentials_json: &str,
        order_url: &str,
    ) -> Result<FinalizeOutcome, String> {
        let account_credentials: AccountCredentials =
            serde_json::from_str(account_credentials_json)
                .map_err(|err| format!("credenciais ACME inválidas: {err}"))?;

        let account = Account::builder()
            .map_err(acme_error_to_string)?
            .from_credentials(account_credentials)
            .await
            .map_err(acme_error_to_string)?;

        let mut order = account
            .order(order_url.to_owned())
            .await
            .map_err(acme_error_to_string)?;

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(acme_error_to_string)?;
            match authz.status {
                AuthorizationStatus::Pending => {
                    let mut challenge = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| "desafio DNS-01 não encontrado para finalizar".to_owned())?;
                    challenge.set_ready().await.map_err(acme_error_to_string)?;
                }
                AuthorizationStatus::Valid => {}
                AuthorizationStatus::Invalid => {
                    return Err(
                        "autorização inválida no Let's Encrypt. Gere uma nova sessão.".to_owned(),
                    );
                }
                status => {
                    return Err(format!(
                        "autorização em estado não suportado para finalização: {status:?}"
                    ));
                }
            }
        }

        let retry_policy = RetryPolicy::new()
            .initial_delay(self.config.poll_initial_delay)
            .backoff(self.config.poll_backoff)
            .timeout(self.config.poll_timeout);

        match order.poll_ready(&retry_policy).await {
            Ok(OrderStatus::Ready) => {}
            Ok(OrderStatus::Invalid) => {
                return Err(
                    "pedido ACME inválido. Verifique o DNS e gere uma nova sessão.".to_owned(),
                );
            }
            Ok(status) => {
                return Err(format!("status inesperado do pedido ACME: {status:?}"));
            }
            Err(AcmeError::Timeout(_)) => {
                return Ok(FinalizeOutcome::PendingDns {
                    reason:
                        "DNS ainda não propagou completamente. Tente novamente em alguns minutos."
                            .to_owned(),
                });
            }
            Err(err) => return Err(acme_error_to_string(err)),
        }

        let private_key_pem = order.finalize().await.map_err(acme_error_to_string)?;
        let certificate_pem = match order.poll_certificate(&retry_policy).await {
            Ok(cert_chain) => cert_chain,
            Err(AcmeError::Timeout(_)) => {
                return Ok(FinalizeOutcome::PendingDns {
                    reason: "Let's Encrypt ainda está processando o certificado. Tente novamente."
                        .to_owned(),
                });
            }
            Err(err) => return Err(acme_error_to_string(err)),
        };

        Ok(FinalizeOutcome::Issued(IssuedCertificate {
            certificate_pem,
            private_key_pem,
        }))
    }
}

fn acme_error_to_string(err: AcmeError) -> String {
    match err {
        AcmeError::Api(problem) => {
            let detail = problem
                .detail
                .unwrap_or_else(|| "erro retornado pela ACME CA".to_owned());
            format!("ACME API: {detail}")
        }
        AcmeError::Timeout(_) => "timeout aguardando atualização do pedido ACME".to_owned(),
        other => other.to_string(),
    }
}
