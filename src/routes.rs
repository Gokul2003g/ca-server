use crate::key_signer::sign_key;
use crate::models::{BearerToken, SignRequest};
use rocket::http::Status;
use rocket::serde::json::Json;

#[post("/handle-post", data = "<data>")]
pub fn handle_post(token: Result<BearerToken, Status>, data: Json<SignRequest>) -> String {
    match token {
        Ok(token) => {
            println!("Extracted Token: {}", token.0); // Logging the extracted token

            match sign_key(data.public_key.as_str(), data.is_host) {
                Ok(cert) => cert,
                Err(err) => err.to_string(),
            }
        }
        Err(status) => {
            // If token extraction failed, return the corresponding status code
            status.to_string()
        }
    }
}

#[options("/handle-post")]
pub fn options() -> Status {
    Status::Ok
}
