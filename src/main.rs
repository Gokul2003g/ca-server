mod config;
mod cors;
mod functions;
mod key_signer;
mod models;
mod routes;

use std::env;

use rocket::fs::FileServer;

#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    config::load_env(); // Load environment variables

    let public_keys_location =
        env::var("PUBLIC_KEY_LOCATION").expect("Environment variable for public keys not set!");

    rocket::build()
        .attach(cors::Cors)
        .mount("/", routes![routes::handle_post, routes::options])
        .mount(
            "/public",
            FileServer::from(format!("{public_keys_location}/ca-server/keys/")),
        )
}
