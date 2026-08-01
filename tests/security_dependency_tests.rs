use std::cmp::Ordering;

#[test]
fn lettre_version_is_not_vulnerable_to_boring_tls_hostname_verification_bypass() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");
    let version =
        find_locked_package_version(&lockfile, "lettre").expect("lettre must be present in Cargo.lock");

    assert!(
        compare_semver(version, "0.11.22") != Ordering::Less,
        "lettre {version} is vulnerable to RUSTSEC-2026-0141; update to >= 0.11.22"
    );
}

#[test]
fn lettre_boring_tls_feature_is_not_enabled() {
    let manifest = std::fs::read_to_string(manifest_path()).expect("Cargo.toml must exist");
    let dependency_line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("lettre ="))
        .expect("lettre must be declared in Cargo.toml");

    assert!(
        !dependency_line.contains("boring-tls"),
        "the backend must keep using Rustls instead of the vulnerable boring-tls backend"
    );
}

#[test]
fn quinn_proto_version_is_not_vulnerable_to_out_of_order_stream_reassembly_exhaustion() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");
    let version =
        find_locked_package_version(&lockfile, "quinn-proto").expect("quinn-proto must be present in Cargo.lock");

    assert!(
        compare_semver(version, "0.11.15") != Ordering::Less,
        "quinn-proto {version} is vulnerable to RUSTSEC-2026-0185; update to >= 0.11.15"
    );
}

#[test]
fn aws_lc_sys_version_is_not_vulnerable_to_certificate_or_signature_validation_bypasses() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");
    let version =
        find_locked_package_version(&lockfile, "aws-lc-sys").expect("aws-lc-sys must be present in Cargo.lock");

    assert!(
        compare_semver(version, "0.39.0") != Ordering::Less,
        "aws-lc-sys {version} is vulnerable to AWS-LC validation bypasses and AES-CCM timing issues; update to >= 0.39.0"
    );
}

#[test]
fn rustls_webpki_version_is_not_vulnerable_to_crl_parsing_or_distribution_point_bugs() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");
    let version =
        find_locked_package_version(&lockfile, "rustls-webpki").expect("rustls-webpki must be present in Cargo.lock");

    assert!(
        compare_semver(version, "0.103.13") != Ordering::Less,
        "rustls-webpki {version} is vulnerable to CRL parsing and distribution point validation issues; update to >= 0.103.13"
    );
}

#[test]
fn event_listener_version_is_not_vulnerable_to_stack_slot_send_unsoundness() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");
    let version = find_locked_package_version(&lockfile, "event-listener")
        .expect("event-listener must be present in Cargo.lock");

    assert!(
        compare_semver(version, "5.4.2") != Ordering::Less,
        "event-listener {version} is vulnerable to RUSTSEC-2026-0221; update to >= 5.4.2"
    );
}

#[test]
fn rand_0_9_2_is_not_present_in_the_dependency_lockfile() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");

    assert!(
        !find_locked_package_versions(&lockfile, "rand").contains(&"0.9.2"),
        "rand 0.9.2 must not be present in Cargo.lock because it is affected by RUSTSEC-2026-0097"
    );
}

#[test]
fn spin_version_is_not_yanked() {
    let lockfile = std::fs::read_to_string(lockfile_path()).expect("Cargo.lock must exist");

    assert!(
        !find_locked_package_versions(&lockfile, "spin").contains(&"0.9.8"),
        "spin 0.9.8 must not be present in Cargo.lock because it is yanked"
    );
}

fn manifest_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

fn lockfile_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")
}

fn find_locked_package_version<'a>(lockfile: &'a str, package_name: &str) -> Option<&'a str> {
    find_locked_package_versions(lockfile, package_name)
        .into_iter()
        .next()
}

fn find_locked_package_versions<'a>(lockfile: &'a str, package_name: &str) -> Vec<&'a str> {
    lockfile.split("[[package]]").filter_map(|package| {
        let name = find_quoted_value(package, "name")?;
        (name == package_name).then(|| find_quoted_value(package, "version"))?
    }).collect()
}

fn find_quoted_value<'a>(package: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key} = ");
    package.lines().find_map(|line| {
        let value = line.trim().strip_prefix(&prefix)?;
        value.strip_prefix('"')?.strip_suffix('"')
    })
}

fn compare_semver(left: &str, right: &str) -> Ordering {
    let left_parts = parse_semver(left);
    let right_parts = parse_semver(right);
    left_parts.cmp(&right_parts)
}

fn parse_semver(version: &str) -> [u64; 3] {
    let mut parts = version.split('.').map(|part| {
        part
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("invalid semver version: {version}"))
    });

    let major = parts
        .next()
        .unwrap_or_else(|| panic!("semver version is missing a major component: {version}"));
    let minor = parts
        .next()
        .unwrap_or_else(|| panic!("semver version is missing a minor component: {version}"));
    let patch = parts
        .next()
        .unwrap_or_else(|| panic!("semver version is missing a patch component: {version}"));

    assert!(
        parts.next().is_none(),
        "semver version has extra components: {version}"
    );

    [major, minor, patch]
}
