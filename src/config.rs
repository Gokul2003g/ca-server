use dotenv::dotenv;

pub fn load_env() {
    dotenv().ok(); // Load environment variables from .env file
}
