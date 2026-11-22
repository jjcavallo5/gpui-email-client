mod auth;
use crate::auth::server;

#[tokio::main]
async fn main() {
    server::google_oauth_flow().await.expect("FAILED!");
}
