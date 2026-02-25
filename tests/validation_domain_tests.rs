use certy_backend::validation::normalize_domain;

#[test]
fn domain_normalization_works() {
    let normalized = normalize_domain("https://Example.COM/path").unwrap();
    assert_eq!(normalized, "example.com");
}

#[test]
fn wildcard_domain_is_allowed() {
    let normalized = normalize_domain("*.example.com").unwrap();
    assert_eq!(normalized, "*.example.com");
}

#[test]
fn invalid_domain_is_rejected() {
    let result = normalize_domain("http://-broken_domain");
    assert!(result.is_err());
}
