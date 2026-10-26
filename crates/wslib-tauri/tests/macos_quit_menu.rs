//! On the main thread, which macOS menus need, so outside libtest's harness.

#[cfg(target_os = "macos")]
fn main() {
    use tauri::menu::{Menu, MenuItem, MenuItemKind, PredefinedMenuItem, Submenu};
    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
    use tauri::{App, AppHandle};
    use wslib_tauri::quit_guard::{QUIT_MENU_ID, init};

    fn build(
        menu: impl FnOnce(&AppHandle<MockRuntime>) -> tauri::Result<Menu<MockRuntime>> + Send + 'static,
    ) -> tauri::Result<App<MockRuntime>> {
        let mut context = mock_context(noop_assets());
        context.package_info_mut().name = "Example".into();
        mock_builder()
            .menu(menu)
            .plugin(init(|_| false))
            .build(context)
    }

    fn last_app_menu_item(app: &App<MockRuntime>) -> MenuItemKind<MockRuntime> {
        let Some(MenuItemKind::Submenu(app_menu)) =
            app.menu().unwrap().items().unwrap().into_iter().next()
        else {
            panic!("no app submenu");
        };
        app_menu.items().unwrap().pop().unwrap()
    }

    let app = build(Menu::default).unwrap();
    let MenuItemKind::MenuItem(quit) = last_app_menu_item(&app) else {
        panic!("the default menu's predefined Quit is still last");
    };
    assert_eq!(quit.id(), QUIT_MENU_ID);
    assert_eq!(quit.text().unwrap(), "Quit Example");

    let app = build(|app| {
        let quit = MenuItem::with_id(app, QUIT_MENU_ID, "Leave", true, None::<&str>)?;
        let hide = PredefinedMenuItem::hide(app, None)?;
        Menu::with_items(
            app,
            &[&Submenu::with_items(app, "App", true, &[&quit, &hide])?],
        )
    })
    .unwrap();
    assert!(matches!(
        last_app_menu_item(&app),
        MenuItemKind::Predefined(_)
    ));

    let Err(error) = build(|app| {
        let about = MenuItem::new(app, "About", true, None::<&str>)?;
        Menu::with_items(app, &[&Submenu::with_items(app, "App", true, &[&about])?])
    }) else {
        panic!("a menu with no Quit to replace was accepted");
    };
    assert!(error.to_string().contains(QUIT_MENU_ID), "{error}");

    println!("macos_quit_menu: ok");
}

#[cfg(not(target_os = "macos"))]
fn main() {}
