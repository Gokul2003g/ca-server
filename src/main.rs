use dotenv::dotenv;
use rocket::fs::FileServer;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use ssh_key::{certificate, rand_core::OsRng, Algorithm, PrivateKey, PublicKey};
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> String {
    String::from("Hello World")
}

fn sign_key(encoded_key: &str, is_host: bool) -> Result<String, Box<dyn std::error::Error>> {
    dotenv().ok();

    let public_key = PublicKey::from_openssh(encoded_key)?;

    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;

    // let ca_user_signing_key = env::var("USER_SIGNING_KEY").expect("Not set");
    // let ca_user_sign_key = PrivateKey::from_openssh(&ca_user_signing_key)?;

    let valid_after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_before = valid_after + (365 * 86400);

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        public_key,
        valid_after,
        valid_before,
    )?;
    cert_builder.serial(42)?; // Setting serial number
    cert_builder.key_id("nobody-cert-02")?; // Setting key identifier
    if is_host {
        cert_builder.cert_type(certificate::CertType::Host)?; // Setting certificate type
    } else {
        cert_builder.cert_type(certificate::CertType::User)?; // Setting certificate type
    }
    cert_builder.valid_principal("nobody")?; // Setting valid principal
    cert_builder.comment("nobody@example.com")?; // Setting comment

    let cert = cert_builder.sign(&ca_key)?;
    println!("{}", cert.to_string());
    Ok(cert.to_string())
}

#[derive(Serialize, Deserialize, Debug)]
struct SignRequest {
    identity: String,
    host: bool,
    validity: String,
    public_key: String,
}

#[post("/handle-post", data = "<data>")]
fn handle_post(data: Json<SignRequest>) -> String {
    match sign_key(data.public_key.as_str(), data.host) {
        Ok(cert) => cert.to_string(),
        Err(err) => err.to_string(),
    }
}

// #[post("/user-cert", format = "json")]
// #[get("/host-sign-key")]
// fn host_sign_key_api() -> Result<Vec<u8>, String> {
//     // Define a secure path to the key file (avoid relative paths)
//     let key_path = Path::new("/home/gokul/dev/rust/practice_server/keys/host-sign-key.pub"); // Replace with actual path
//
//     // Read the file contents with error handling
//     let contents = fs::read(key_path).map_err(|err| format!("Error reading key file: {}", err))?;
//
//     // Return the file contents with appropriate content type
//     Ok(contents.into_owned())
// }

// #[post("/get-user-cert", format = "plain", data = "<file>")]
// async fn get_user_certificate(mut file: TempFile<'_>) -> Result<Value, String> {
//     let fileContent = file
//         .persist_to("/home/gokul/dev/rust/practice_server/signed_keys/")
//         .await;
//
//     Ok(json!({"message": "done"}))
// }

// #[get("/host-sign-key", format = "json")]
// fn host_sign_key_api() -> Result<Value, String> {
//     // Define a secure path to the key file (avoid relative paths)
//     let key_path = "/home/gokul/dev/rust/practice_server/keys/host-sign-key.pub"; // Replace with actual path
//
//     // Read the file contents with error handling
//     let contents =
//         fs::read_to_string(key_path).map_err(|err| format!("Error reading key file: {}", err))?;
//
//     // Return the JSON response
//     Ok(json!({ "Host-Signing-Key": contents }))
// }

// #[get("/user-sign-key", format = "json")]
// fn user_sign_key_api() -> Result<Value, String> {
//     // Define a secure path to the key file (avoid relative paths)
//     let key_path = "/home/gokul/dev/rust/practice_server/keys/user-sign-key.pub"; // Replace with actual path
//
//     // Read the file contents with error handling
//     let contents =
//         fs::read_to_string(key_path).map_err(|err| format!("Error reading key file: {}", err))?;
//
//     // Return the JSON response
//     Ok(json!({ "User-Signing-Key": contents }))
// }

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index, handle_post])
        // .mount("/", routes![user_sign_key_api])
        // .mount("/", routes![host_sign_key_api])
        .mount(
            "/public",
            FileServer::from("/home/gokul/dev/rust/practice_server/keys/"),
        )
}
