use ssh_key::Certificate;
use ssh_key::{certificate, rand_core::OsRng, PrivateKey, PublicKey};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn sign_key(
    encoded_key: &str,
    is_host: bool,
    email: &String,
    principals_permitted: Vec<String>,
    validity: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let public_key: PublicKey = PublicKey::from_openssh(encoded_key)?;

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
    let valid_before: u64 = valid_after
        + validity
            .parse::<u64>()
            .expect("Unable to parse validity time.\n");

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        public_key,
        valid_after,
        valid_before,
    )?;

    // Optional serial number assigned by CA.
    // May use later
    // cert_builder.serial(42)?;

    let key_id = Uuid::new_v4().to_string();
    cert_builder.key_id(key_id)?;

    if is_host {
        cert_builder.cert_type(certificate::CertType::Host)?;
    } else {
        cert_builder.cert_type(certificate::CertType::User)?;
    }

    for principal in principals_permitted.iter() {
        cert_builder.valid_principal(principal)?;
    }

    cert_builder.comment(email.to_string())?;

    let cert: Certificate = cert_builder.sign(ca_key)?;
    Ok(cert.to_string())
}
