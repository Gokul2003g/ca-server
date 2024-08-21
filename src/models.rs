use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignRequest {
    pub public_key: String,
    pub is_host: bool,
    pub identity: String,
}
