use certy_backend::validation::validate_email;

#[test]
fn email_validation_works() {
    let email = validate_email("Ops@Example.com").unwrap();
    assert_eq!(email, "ops@example.com");
}

#[test]
fn invalid_email_is_rejected() {
    let result = validate_email("invalid-email");
    assert!(result.is_err());
}

#[test]
fn whitespace_email_is_rejected() {
    let result = validate_email("  user @example.com  ");
    assert!(result.is_err());
}
