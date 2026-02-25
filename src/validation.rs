use crate::error::AppError;

pub fn normalize_domain(raw: &str) -> Result<String, AppError> {
    let mut domain = raw.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err(AppError::validation("Domínio é obrigatório."));
    }

    if let Some(stripped) = domain.strip_prefix("https://") {
        domain = stripped.to_owned();
    } else if let Some(stripped) = domain.strip_prefix("http://") {
        domain = stripped.to_owned();
    }

    if let Some((host, _)) = domain.split_once('/') {
        domain = host.to_owned();
    }
    domain = domain.trim_end_matches('.').to_owned();

    let wildcard = domain.starts_with("*.");
    let hostname = if wildcard {
        domain.trim_start_matches("*.")
    } else {
        domain.as_str()
    };

    if hostname.is_empty() || hostname.len() > 253 || !hostname.contains('.') {
        return Err(AppError::validation("Domínio inválido."));
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(AppError::validation("Domínio inválido."));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AppError::validation("Domínio inválido."));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(AppError::validation("Domínio inválido."));
        }
    }

    Ok(if wildcard {
        format!("*.{hostname}")
    } else {
        hostname.to_owned()
    })
}

pub fn validate_email(raw: &str) -> Result<String, AppError> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 254 || email.contains(' ') {
        return Err(AppError::validation("Email inválido."));
    }

    let mut split = email.split('@');
    let local = split.next().unwrap_or_default();
    let domain = split.next().unwrap_or_default();
    let extra = split.next();

    if local.is_empty() || domain.is_empty() || extra.is_some() || !domain.contains('.') {
        return Err(AppError::validation("Email inválido."));
    }

    Ok(email)
}
