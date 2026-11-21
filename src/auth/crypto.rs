use crate::auth::env;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRng;
use rand::rngs::SysRng;
use reqwest::Client;
use sha2::{Digest, Sha256};

pub fn generate_pkce_verifier() -> Result<String, <SysRng as TryRng>::Error> {
    let mut bytes = [0u8; 64];
    SysRng.try_fill_bytes(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn create_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))
}

pub fn create_oauth_url(challenge: &str, redirect_uri: &str) -> anyhow::Result<String> {
    let oauth_env = env::get_oauth_env()?;
    let client = Client::new();
    let request = client
        .get("https://accounts.google.com/o/oauth2/v2/auth")
        .query(&[
            ("client_id", oauth_env.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "https://www.googleapis.com/auth/gmail.readonly"),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .build()?;

    Ok(request.url().to_string())
}
