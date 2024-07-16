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
    let valid_before = valid_after + (4);

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        public_key,
        valid_after,
        valid_before,
    )?;

    // TODO: Identity from access list
    // TODO: Permitted Host and Users from accesss list
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
    // println!("{}", cert.to_string());
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
