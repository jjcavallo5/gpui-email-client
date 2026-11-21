use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GoogleOAuthTokenResult {
    access_token: String,
    expires_in: u8,
    refresh_token: String,
    refresh_token_expires_in: u8,
}
