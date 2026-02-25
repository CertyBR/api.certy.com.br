use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::config::AppConfig;
use crate::models::DnsRecord;

#[derive(Clone)]
pub struct DnsPrecheckService {
    client: reqwest::Client,
    resolver_url: String,
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct DnsPrecheckResult {
    pub missing_records: Vec<DnsRecord>,
}

impl DnsPrecheckResult {
    pub fn is_ready(&self) -> bool {
        self.missing_records.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum DnsPrecheckError {
    #[error("falha ao consultar DNS: {0}")]
    Upstream(String),
}

#[derive(Debug, Deserialize)]
struct DnsResolveResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DnsAnswer {
    data: String,
}

impl DnsPrecheckService {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            resolver_url: config.dns_check_resolver_url.clone(),
            timeout: config.dns_check_timeout,
        }
    }

    pub async fn check_dns_records(
        &self,
        records: &[DnsRecord],
    ) -> Result<DnsPrecheckResult, DnsPrecheckError> {
        let mut missing = Vec::new();

        for record in records {
            let values = self.query_txt_values(&record.name).await?;
            let expected = normalize_txt_data(&record.value);
            let found = values
                .iter()
                .map(|value| normalize_txt_data(value))
                .any(|value| value == expected);

            if !found {
                missing.push(record.clone());
            }
        }

        Ok(DnsPrecheckResult {
            missing_records: missing,
        })
    }

    async fn query_txt_values(&self, name: &str) -> Result<Vec<String>, DnsPrecheckError> {
        let response = self
            .client
            .get(&self.resolver_url)
            .query(&[("name", name), ("type", "TXT")])
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|err| DnsPrecheckError::Upstream(err.to_string()))?;

        if !response.status().is_success() {
            return Err(DnsPrecheckError::Upstream(format!(
                "resolver DNS retornou HTTP {}",
                response.status()
            )));
        }

        let payload = response
            .json::<DnsResolveResponse>()
            .await
            .map_err(|err| DnsPrecheckError::Upstream(err.to_string()))?;

        if payload.status != 0 {
            return Ok(Vec::new());
        }

        let values = payload
            .answer
            .unwrap_or_default()
            .into_iter()
            .map(|answer| answer.data)
            .collect::<Vec<_>>();

        Ok(values)
    }
}

fn normalize_txt_data(raw: &str) -> String {
    let value = raw.trim();
    if !value.contains('"') {
        return value.to_owned();
    }

    let mut output = String::new();
    let mut escaped = false;

    for ch in value.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == '"' {
            continue;
        }

        if ch.is_whitespace() {
            continue;
        }

        output.push(ch);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::normalize_txt_data;

    #[test]
    fn strips_txt_quotes_and_spaces() {
        assert_eq!(normalize_txt_data("\"abc\""), "abc");
        assert_eq!(normalize_txt_data("\"abc\" \"def\""), "abcdef");
        assert_eq!(normalize_txt_data("abc"), "abc");
    }
}
