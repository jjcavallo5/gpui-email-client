use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GoogleOAuthCode {
    pub code: String,
    pub state: String,
}

#[derive(Serialize, Deserialize)]
pub struct GoogleOAuthTokenResult {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_token_expires_in: u64,
}

#[derive(Serialize, Deserialize)]
pub struct GoogleOAuthRefreshTokenResult {
    pub access_token: String,
    pub expires_in: u8,
}
