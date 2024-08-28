use crate::models::Acl;
use std::env;
use std::fs;

pub fn get_host_and_validity(email: &str) -> Result<(Vec<String>, String), String> {
    let project_location: String =
        env::var("PROJECT_LOCATION").expect("Environment variable for public keys not set!");
    let acl_content: String =
        fs::read_to_string(format!("{project_location}/ca-server/acl/acl.toml"))
            .expect("Failed to read Access List here location invalid");

    let acl: Acl = toml::from_str(&acl_content).expect("Failed to parse acl.toml");

    if let Some(user) = acl.users.iter().find(|user| user.email == email) {
        Ok((user.hosts_allowed.clone(), user.validity.clone()))
    } else {
        Err("Invalid email".to_string())
    }
}
