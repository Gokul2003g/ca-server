use ssh_key::Certificate;
use ssh_key::{certificate, rand_core::OsRng, PrivateKey, PublicKey};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sign_key(
    encoded_key: &str,
    is_host: bool,
    email: &String,
    principals_permitted: Vec<String>,
    validity: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let public_key: PublicKey = PublicKey::from_openssh(encoded_key)?;

    println!("{} {:?} {}", email, principals_permitted, validity);

    let user_key_file_path: String =
        env::var("ROCKET_USER_SIGN_KEY_FILE").expect("ROCKET_USER_SIGN_KEY_FILE must be set");
    let host_key_file_path: String =
        env::var("ROCKET_HOST_SIGN_KEY_FILE").expect("ROCKET_HOST_SIGN_KEY_FILE must be set");

    let ca_user_signing_key: String =
        fs::read_to_string(user_key_file_path).expect("Failed to read user private key file");
    let ca_host_signing_key: String =
        fs::read_to_string(host_key_file_path).expect("Failed to read host private key file");

    let ca_host_key: PrivateKey = PrivateKey::from_openssh(ca_host_signing_key)?;
    let ca_user_key: PrivateKey = PrivateKey::from_openssh(ca_user_signing_key)?;

    let ca_key: &PrivateKey = if is_host { &ca_host_key } else { &ca_user_key };

    let valid_after: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_before: u64 = valid_after + (15 * 60);

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        public_key,
        valid_after,
        valid_before,
    )?;

    // TODO: Identity from access list
    // TODO: Permitted Host and Users from access list
    // TODO: Expiry time from access list

    cert_builder.serial(42)?;
    cert_builder.key_id("nobody-cert-02")?;

    if is_host {
        cert_builder.cert_type(certificate::CertType::Host)?;
    } else {
        cert_builder.cert_type(certificate::CertType::User)?;
    }

    cert_builder.valid_principal("nobody")?;
    cert_builder.comment("nobody@example.com")?;

    let cert: Certificate = cert_builder.sign(ca_key)?;
    Ok(cert.to_string())
}
