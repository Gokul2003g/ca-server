use crate::key_signer::sign_key;
use crate::models::SignRequest;
use rocket::http::Status;
use rocket::serde::json::Json;

#[get("/")]
pub fn index() -> String {
    String::from("Hello World")
}

#[post("/handle-post", data = "<data>")]
pub fn handle_post(data: Json<SignRequest>) -> String {
    match sign_key(data.public_key.as_str(), data.is_host) {
        Ok(cert) => cert,
        Err(err) => err.to_string(),
    }
}

#[options("/handle-post")]
pub fn options() -> Status {
    Status::Ok
}
