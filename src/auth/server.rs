use crate::auth::schemas::GoogleOAuthCode;
use crate::auth::{crypto, env};
use open;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub async fn get_tcp_listener() -> Result<(TcpListener, u16), std::io::Error> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(tcpl) => tcpl,
        Err(err) => return Err(err),
    };
    let local_addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(err) => return Err(err),
    };
    Ok((listener, local_addr.port()))
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

pub enum GoogleOAuthError {
    TcpListenerError,
    TokenCreationError,
    EnvironmentError,
    UrlEncodingError,
    SocketAcceptError,
    TokenExchangeError,
}

pub async fn google_oauth_flow() -> Result<(), GoogleOAuthError> {
    let (tcp_listener, port) = match get_tcp_listener().await {
        Ok(tcpl) => tcpl,
        Err(_) => return Err(GoogleOAuthError::TcpListenerError),
    };
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let verifier = match crypto::generate_random_url_safe_token() {
        Ok(token) => token,
        Err(_) => return Err(GoogleOAuthError::TokenCreationError),
    };
    let state_token = match crypto::generate_random_url_safe_token() {
        Ok(token) => token,
        Err(_) => return Err(GoogleOAuthError::TokenCreationError),
    };

    let challenge = crypto::create_code_challenge(&verifier);

    let oauth_env = match env::get_oauth_env() {
        Ok(oa_env) => oa_env,
        Err(_) => return Err(GoogleOAuthError::EnvironmentError),
    };

    let url = match crypto::create_oauth_url(&oauth_env, &challenge, &redirect_uri, &state_token) {
        Ok(url) => url,
        Err(_) => return Err(GoogleOAuthError::UrlEncodingError),
    };

    println!("If your web browser doesn't open, navigate to the folowing URL:");
    println!("{url}");
    open::that_detached(url).ok();

    let code: GoogleOAuthCode = loop {
        // Accept connection
        let (mut stream, _) = match tcp_listener.accept().await {
            Ok(connection) => connection,
            Err(_) => return Err(GoogleOAuthError::SocketAcceptError),
        };

        // Parse request
        if let Ok(c) = handle_oauth_request(&mut stream, &state_token, &redirect_uri).await {
            break c;
        }
    };

    let access_token =
        match crypto::exchange_token(&oauth_env, &code.code, &redirect_uri, &verifier).await {
            Ok(tokens) => tokens,
            Err(_) => return Err(GoogleOAuthError::TokenExchangeError),
        };

    println!("Access Token: {}", access_token.access_token);

    Ok(())
}
