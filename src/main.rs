mod acl;
mod config;
mod cors;
mod key_signer;
mod models;
mod oauth_provider;
mod routes;

use std::env;

use rocket::fs::FileServer;

#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    config::load_env(); // Load environment variables

    let project_location =
        env::var("PROJECT_LOCATION").expect("Environment variable for public keys not set!");

    rocket::build()
        .attach(cors::Cors)
        .mount("/", routes![routes::handle_post, routes::options])
        .mount(
            "/public",
            FileServer::from(format!("{project_location}/ca-server/keys/")),
        )
}
