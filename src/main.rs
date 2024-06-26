use dotenv::dotenv;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::fs::FileServer;
use rocket::http::{Header, Status};
use rocket::serde::json::Json;
use rocket::{Request, Response};
use serde::{Deserialize, Serialize};
use ssh_key::Certificate;
use ssh_key::{certificate, rand_core::OsRng, PrivateKey, PublicKey};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> String {
    String::from("Hello World")
}

fn sign_key(encoded_key: &str, is_host: bool) -> Result<String, Box<dyn std::error::Error>> {
    dotenv().ok();

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

    let ca_key = if is_host { &ca_host_key } else { &ca_user_key };

    let valid_after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_before = valid_after + (365 * 86400);

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        public_key,
        valid_after,
        valid_before,
    )?;

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
    println!("{}", cert.to_string());
    Ok(cert.to_string())
}

#[derive(Serialize, Deserialize, Debug)]
struct SignRequest {
    public_key: String,
    is_host: bool,
    identity: String,
}

#[post("/handle-post", data = "<data>")]
fn handle_post(data: Json<SignRequest>) -> String {
    match sign_key(data.public_key.as_str(), data.is_host) {
        Ok(cert) => cert.to_string(),
        Err(err) => err.to_string(),
    }
}

#[options("/handle-post")]
fn options() -> Status {
    Status::Ok
}

#[launch]
fn rocket() -> _ {
    dotenv().ok(); // Load environment variables from .env file

    rocket::build()
        .attach(Cors)
        .mount("/", routes![index, handle_post, options])
        .mount(
            "/public",
            FileServer::from("/home/gokul/dev/ca-server/keys/"),
        )
}

pub struct Cors;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cross-Origin-Resource-Sharing Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, PATCH, PUT, DELETE, HEAD, OPTIONS, GET",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
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
