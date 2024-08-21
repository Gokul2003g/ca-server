mod config;
mod cors;
mod key_signer;
mod models;
mod routes;

use rocket::fs::FileServer;

#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    config::load_env(); // Load environment variables

    rocket::build()
        .attach(cors::Cors)
        .mount(
            "/",
            routes![routes::handle_post, routes::options],
        )
        .mount(
            "/public",
            FileServer::from("/home/nitin/Github/ca-server/keys/"),
        )
}
