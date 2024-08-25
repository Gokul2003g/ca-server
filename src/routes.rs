use crate::key_signer::sign_key;
use crate::models::{BearerToken, SignRequest};
use crate::oauth_provider::get_email_from_provider;
use rocket::http::Status;
use rocket::serde::json::Json;

#[post("/handle-post", data = "<data>")]
pub async fn handle_post(token: Result<BearerToken, Status>, data: Json<SignRequest>) -> String {
    match token {
        Ok(token) => {
            // call the provider and get email
            let email = get_email_from_provider(token.0, data.provider.as_str())
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
