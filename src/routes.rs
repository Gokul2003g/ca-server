use crate::functions::get_email_from_provider;
use crate::key_signer::sign_key;
use crate::models::{BearerToken, SignRequest};
use rocket::http::Status;
use rocket::serde::json::Json;

#[post("/handle-post", data = "<data>")]
pub async fn handle_post(token: Result<BearerToken, Status>, data: Json<SignRequest>) -> String {
    match token {
        Ok(token) => {
            println!("Extracted Token: {}", token.0); // Logging the extracted token

            // call the provider and print email
            let email = get_email_from_provider(token.0, "google")
                .await
                .expect("error");

            println!("{email}");

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

// NOTE: Github email URL : https://api.github.com/user/emails
// NOTE: Google email URL : https://www.googleapis.com/oauth2/v2/userinfo
