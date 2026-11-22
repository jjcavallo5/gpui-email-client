use crate::auth::schemas::GoogleOAuthTokenResult;
use crate::auth::{env::OAuthEnv, schemas::GoogleOAuthRefreshTokenResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRng;
use rand::rngs::SysRng;
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

pub fn generate_random_url_safe_token() -> Result<String, <SysRng as TryRng>::Error> {
    let mut bytes = [0u8; 64];
    SysRng.try_fill_bytes(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn create_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))
}

pub fn create_oauth_url(
    oauth_env: &OAuthEnv,
    challenge: &str,
    redirect_uri: &str,
    state: &str,
) -> anyhow::Result<String> {
    let client = Client::new();
    let request = client
        .get("https://accounts.google.com/o/oauth2/v2/auth")
        .query(&[
            ("client_id", oauth_env.client_id.as_str()),
            ("state", state),
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

pub async fn exchange_token(
    oauth_env: &OAuthEnv,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> anyhow::Result<GoogleOAuthTokenResult> {
    let client = Client::new();
    let response = client
        .post("https://oauth2.googleapis.com/token")
        .json(&json!({
            "client_id": oauth_env.client_id,
            "client_secret": oauth_env.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "grant_type": "authorization_code"
        }))
        .send()
        .await?
        .text()
        .await?;
    println!("Response: {}", response);
    let valid: GoogleOAuthTokenResult = serde_json::from_str(response.as_str())?;
    return Ok(valid);
}

pub async fn refresh_token(
    oauth_env: &OAuthEnv,
    refresh_token: &str,
) -> anyhow::Result<GoogleOAuthRefreshTokenResult> {
    let client = Client::new();
    let response = client
        .get("https://oauth2.googleapis.com/token")
        .query(&[
            ("client_id", oauth_env.client_id.as_str()),
            ("client_secret", oauth_env.client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?
        .text()
        .await?;
    let valid: GoogleOAuthRefreshTokenResult = serde_json::from_str(response.as_str())?;
    return Ok(valid);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_random_url_save_token() {
        generate_random_url_safe_token().expect("Token failed");
    }

    #[test]
    fn test_create_code_challenge() {
        let token = generate_random_url_safe_token().expect("Token failed");
        create_code_challenge(&token);
    }

    #[test]
    fn test_create_oauth_url() {
        let oauth_env = OAuthEnv {
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
        };
        let res = create_oauth_url(
            &oauth_env,
            "test-challenge",
            "http://redirect:8080",
            "test-state",
        )
        .expect("Failed to create url");

        assert!(res.contains("client_id=test-client-id"));
        assert!(res.contains("redirect_uri=http"));
        assert!(res.contains("state=test-state"));
        assert!(res.contains("https://accounts.google.com/o/oauth2/v2/auth"));
    }
}
