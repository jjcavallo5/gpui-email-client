mod auth;
use crate::auth::server;

#[tokio::main]
async fn main() {
    match server::google_oauth_flow().await {
        Ok(_) => println!("Successfully authenticated."),
        Err(e) => match &e {
            server::GoogleOAuthError::EnvironmentError(err) => eprintln!("{e}: {err}"),
            server::GoogleOAuthError::TokenExchangeError(err) => eprintln!("{e}: {err}"),
            server::GoogleOAuthError::TokenCreationError(err) => eprintln!("{e}: {err}"),
            server::GoogleOAuthError::TcpListenerError(err) => eprintln!("{e}: {err}"),
            server::GoogleOAuthError::UrlEncodingError(err) => eprintln!("{e}: {err}"),
        },
    }
}
