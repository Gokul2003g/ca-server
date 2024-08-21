use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignRequest {
    pub public_key: String,
    pub is_host: bool,
    pub identity: String,
}

#[derive(Debug)]
pub struct BearerToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerToken {
    type Error = Status;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Extract the Authorization header
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            // Check if the header starts with "Bearer "
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                return Outcome::Success(BearerToken(token.to_string()));
            }
        }
        // Return a 401 Unauthorized status if the header is missing or invalid
        Outcome::Error((Status::Unauthorized, Status::Unauthorized))
    }
}
