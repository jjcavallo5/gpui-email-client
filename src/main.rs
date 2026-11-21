mod auth;
use crate::auth::crypto;

fn main() {
    let verifier = crypto::generate_pkce_verifier().expect("Failed to create verifier");
    let challenge = crypto::create_code_challenge(&verifier);
    let oauth_env = auth::env::get_oauth_env().expect("Env variables not set");

    println!("Verifier: {}", verifier);
    println!("Challenge: {}", challenge);

    let url = crypto::create_oauth_url(&challenge, "http://127.0.0.1:8080", &oauth_env).unwrap();

    println!("OAuth URL: {}", url);
}
