use crate::auth::server;
use gpui_kit::component::{button::Button, label::Label, ActiveTheme};
use gpui_kit::*;

fn handle_click(cx: &mut App) {
    cx.spawn(async |cx| {
        let callback = |url: String| cx.update(|cx| cx.open_url(&url));
        match server::google_oauth_flow(callback).await {
            Ok(_) => println!("Successfully authenticated."),
            Err(e) => match &e {
                server::GoogleOAuthError::EnvironmentError(err) => {
                    eprintln!("{e}: {err}")
                }
                server::GoogleOAuthError::TokenExchangeError(err) => {
                    eprintln!("{e}: {err}")
                }
                server::GoogleOAuthError::TokenCreationError(err) => {
                    eprintln!("{e}: {err}")
                }
                server::GoogleOAuthError::TcpListenerError(err) => {
                    eprintln!("{e}: {err}")
                }
                server::GoogleOAuthError::UrlEncodingError(err) => {
                    eprintln!("{e}: {err}")
                }
            },
        };
    })
    .detach();
}

pub struct Home;

impl Render for Home {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .bg(cx.theme().background)
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_2()
            .child(Label::new("Hello"))
            .child(
                Button::new("hello")
                    .label("Click Me!")
                    .on_click(|_, _, cx| handle_click(cx)),
            )
    }
}
