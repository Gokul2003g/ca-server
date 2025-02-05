use crate::acl::get_host_and_validity;
use crate::key_signer::sign_key;
use crate::models::{BearerToken, SignRequest};
use crate::oauth_provider::get_email_from_provider;
use rocket::http::Status;
use rocket::serde::json::Json;

#[post("/handle-post", data = "<data>")]
pub async fn handle_post(token: Result<BearerToken, Status>, data: Json<SignRequest>) -> String {
    match token {
        // NOTE: Remove the hardcodedToken
        Ok(token) => {
            println!("{}", token.0);
            println!("Reached line 14");
            let email: String = if token.0 == "hardcodedToken" {
                data.identity.clone()
            } else {
                // call the provider and get email
                get_email_from_provider(token.0, data.provider.as_str())
                    .await
                    .expect("error")
            };

            if data.identity != email {
                "Invalid Email".to_string();
                return "Inavlid Email".to_string();
            }

            let (principals_permitted, validity) = match get_host_and_validity(&email) {
                Ok((hosts, validity)) => (hosts, validity),
                Err(err) => {
                    println!("{err}");
                    return "Invalid email address".to_string();
                }
            };

            println!("{principals_permitted:?}");
            println!("{validity}");

            match sign_key(
                data.public_key.as_str(),
                data.is_host,
                &data.identity,
                principals_permitted,
                validity,
            ) {
                Ok(cert) => cert,
                Err(err) => {
                    println!("{}", err);
                    "Invalid Public Key".to_string()
                }
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
