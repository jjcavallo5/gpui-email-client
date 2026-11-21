use std::env;

pub struct OAuthEnv {
    pub client_id: String,
    pub client_secret: String,
}

pub fn get_oauth_env() -> Result<OAuthEnv, std::env::VarError> {
    dotenvy::dotenv().ok(); // Ignore errors in prod
    return Ok(OAuthEnv {
        client_id: env::var("CLIENT_ID")?,
        client_secret: env::var("CLIENT_SECRET")?,
    });
}
