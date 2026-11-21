mod auth;
use crate::auth::crypto;

fn main() {
    let verifier = crypto::generate_pkce_verifier().expect("Failed to create verifier");
    let challenge = crypto::create_code_challenge(&verifier);

    println!("Verifier: {}", verifier);
    println!("Challenge: {}", challenge);

    let url = crypto::create_oauth_url(&challenge, "http://127.0.0.1:8080").unwrap();

    println!("OAuth URL: {}", url);
}
