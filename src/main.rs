mod auth;
use crate::auth::server;
use gpui_kit::component::ThemeRegistry;
use gpui_kit::component::{button::Button, label::Label, ActiveTheme, Theme};
use gpui_kit::*;

struct Home;

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
                    .on_click(|_, _, cx| {
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
                    }),
            )
    }
}

#[tokio::main]
async fn main() {
    // match server::google_oauth_flow().await {
    //     Ok(_) => println!("Successfully authenticated."),
    //     Err(e) => match &e {
    //         server::GoogleOAuthError::EnvironmentError(err) => eprintln!("{e}: {err}"),
    //         server::GoogleOAuthError::TokenExchangeError(err) => eprintln!("{e}: {err}"),
    //         server::GoogleOAuthError::TokenCreationError(err) => eprintln!("{e}: {err}"),
    //         server::GoogleOAuthError::TcpListenerError(err) => eprintln!("{e}: {err}"),
    //         server::GoogleOAuthError::UrlEncodingError(err) => eprintln!("{e}: {err}"),
    //     },
    // }
    application().with_assets(assets::Assets).run(|cx| {
        init(cx);

        ThemeRegistry::global_mut(cx)
            .load_themes_from_str(include_str!("../themes/tokyo.json"))
            .expect("Failed to parse theme");

        let theme_cfg = ThemeRegistry::global(cx)
            .themes()
            .get("Tokyo Night")
            .cloned()
            .expect("Failed to load theme");

        Theme::update(cx, |current| current.apply_config(&theme_cfg));
        open_window(WindowOptions::default(), cx, |_, cx| cx.new(|_| Home))
            .expect("Failed to open app");
    });
}
