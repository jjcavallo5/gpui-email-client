use crate::auth::schemas::GoogleOAuthCode;
use crate::auth::{crypto, env};
use open;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub async fn get_tcp_listener() -> Result<TcpListener, std::io::Error> {
    Ok(TcpListener::bind("127.0.0.1:0").await?)
}

async fn handle_oauth_request(
    stream: &mut TcpStream,
    state: &str,
    redirect_uri: &str,
) -> anyhow::Result<GoogleOAuthCode> {
    // 1. Read line from socket
    let mut reader = BufReader::new(&mut *stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    // 2. Ensure the method is a GET request
    let method = request_line.split_whitespace().nth(0).unwrap_or("");
    if method != "GET" {
        anyhow::bail!("Incorrect method")
    }

    // 3. Parse query parameters from request
    let (path, params) = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split_once("?")
        .unwrap_or(("", ""));

    // 4. Ensure the path matches our redirect path
    let expected_path = redirect_uri
        .strip_prefix("http://")
        .or_else(|| redirect_uri.strip_prefix("https://"))
        .and_then(|rest| rest.find('/').map(|idx| &rest[idx..]))
        .unwrap_or(redirect_uri);

    if expected_path != path {
        anyhow::bail!("Incorrect path");
    }

    // 5. Ensure we can decode the params, and state matches
    let decoded_params: GoogleOAuthCode = serde_urlencoded::from_str(&params)?;

    if decoded_params.state != state {
        anyhow::bail!("Incorrect state");
    }

    // 6. Clear request buffer
    let mut line = String::new();
    while reader.read_line(&mut line).await? > 0 {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    // 7. Send resp back to browser
    let body = "Authentication successful! You can close this tab.";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    Ok(decoded_params)
}

pub async fn google_oauth_flow() -> anyhow::Result<()> {
    let tcp_listener = get_tcp_listener().await?;
    let port = tcp_listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let verifier = crypto::generate_random_url_safe_token().expect("Failed to create verifier");
    let state_token =
        crypto::generate_random_url_safe_token().expect("Failed to create state token");
    let challenge = crypto::create_code_challenge(&verifier);
    let oauth_env = env::get_oauth_env().expect("Env variables not set");

    let url =
        crypto::create_oauth_url(&oauth_env, &challenge, &redirect_uri, &state_token).unwrap();

    println!("If your web browser doesn't open, navigate to the folowing URL:");
    println!("{url}");
    open::that_detached(url)?;

    let code: GoogleOAuthCode = loop {
        // Accept connection
        let (mut stream, _) = tcp_listener.accept().await?;

        // Parse request
        if let Ok(c) = handle_oauth_request(&mut stream, &state_token, &redirect_uri).await {
            break c;
        }
    };

    let endgame = crypto::exchange_token(&oauth_env, &code.code, &redirect_uri, &verifier).await?;

    println!("Access Token: {}", endgame.access_token);

    Ok(())
}
