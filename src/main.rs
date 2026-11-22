mod auth;
use crate::auth::server;

#[tokio::main]
async fn main() {
    match server::google_oauth_flow().await {
        Ok(_) => (),
        Err(err) => match err {
            server::GoogleOAuthError::EnvironmentError => {
                println!("Failed to load environment variables")
            }
            server::GoogleOAuthError::TokenExchangeError => {
                println!("Failed to exchange OAuth token with Google")
            }
            server::GoogleOAuthError::TokenCreationError => {
                println!("Failed to create OAuth token")
            }
            server::GoogleOAuthError::TcpListenerError => println!("Failed to create TCP listener"),
            server::GoogleOAuthError::UrlEncodingError => {
                println!("Failed to encode URL parameters")
            }
            server::GoogleOAuthError::SocketAcceptError => println!("Socket connection failed"),
        },
    }
}
