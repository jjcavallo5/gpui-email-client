mod app;
mod auth;

use app::home::Home;
use gpui_kit::component::{Theme, ThemeRegistry};
use gpui_kit::*;

#[tokio::main]
async fn main() {
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
