mod auth;
use crate::auth::crypto;

fn main() {
    let verifier = crypto::generate_random_url_safe_token().expect("Failed to create verifier");
    let state_token =
        crypto::generate_random_url_safe_token().expect("Failed to create state token");
    let challenge = crypto::create_code_challenge(&verifier);
    let oauth_env = auth::env::get_oauth_env().expect("Env variables not set");

    println!("Verifier: {}", verifier);
    println!("Challenge: {}", challenge);

    let url = crypto::create_oauth_url(
        &oauth_env,
        &challenge,
        "http://127.0.0.1:8080",
        &state_token,
    )
    .unwrap();

    println!("OAuth URL: {}", url);
}
