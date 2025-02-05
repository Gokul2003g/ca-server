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

use fern::Dispatch;
use log::LevelFilter;
use chrono::Local;

#[launch]
fn rocket() -> _ {
    setup_logger().expect("Failed to initialize logger");
    
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

fn setup_logger() -> Result<(), fern::InitError> {
    // Create a log file handler
    let log_file = fern::log_file("certificates.log").expect("Failed to create log file");

    // Set up the logger with both console and file logging
    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(LevelFilter::Info) // set desired logging level
        .chain(std::io::stdout())  // log to console
        .chain(log_file)           // log to file
        .apply()?;                 // apply the logger setup
    Ok(())
}