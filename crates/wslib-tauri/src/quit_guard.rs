//! Hold a quit until the app's in-flight work has finished.
//!
//! Quitting part-way through a write once truncated a database, so a quit that
//! arrives while the app is busy waits for it to go idle and then exits on its
//! own.
//!
//! ```
//! # use tauri::{AppHandle, Builder, Runtime};
//! # fn build<R: Runtime>(builder: Builder<R>, busy: fn(&AppHandle<R>) -> bool) -> Builder<R> {
//! builder.plugin(wslib_tauri::quit_guard::init(busy))
//! # }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{AppHandle, Emitter, Manager, RunEvent, Runtime, WindowEvent};

/// Emitted to the frontend, once, when a quit starts waiting for work to finish.
pub const QUIT_PENDING_EVENT: &str = "quit-pending";

/// The id of the menu item routed to [`request_quit`].
pub const QUIT_MENU_ID: &str = "wslib-quit";

const POLL: Duration = Duration::from_millis(250);

type Busy<R> = Box<dyn Fn(&AppHandle<R>) -> bool + Send + Sync>;

struct Guard<R: Runtime> {
    busy: Busy<R>,
    exit: fn(&AppHandle<R>),
    pending: AtomicBool,
}

/// The plugin, holding a quit while `busy` says work is in flight.
pub fn init<R: Runtime>(
    busy: impl Fn(&AppHandle<R>) -> bool + Send + Sync + 'static,
) -> TauriPlugin<R> {
    plugin(Box::new(busy), |app| app.exit(0))
}

fn plugin<R: Runtime>(busy: Busy<R>, exit: fn(&AppHandle<R>)) -> TauriPlugin<R> {
    Builder::new("quit-guard")
        .setup(move |app, _| {
            app.manage(Guard {
                busy,
                exit,
                pending: AtomicBool::new(false),
            });
            app.on_menu_event(|app, event| {
                if event.id() == QUIT_MENU_ID {
                    request_quit(app);
                }
            });
            #[cfg(target_os = "macos")]
            ensure_macos_quit(app)?;
            Ok(())
        })
        .on_event(|app, event| match event {
            RunEvent::ExitRequested { api, .. } if is_busy(app) => {
                api.prevent_exit();
                request_quit(app);
            }
            RunEvent::WindowEvent {
                event: WindowEvent::CloseRequested { api, .. },
                ..
            } if is_busy(app) => {
                api.prevent_close();
                request_quit(app);
            }
            _ => {}
        })
        .build()
}

fn is_busy<R: Runtime>(app: &AppHandle<R>) -> bool {
    (app.state::<Guard<R>>().busy)(app)
}

/// Exit now if idle; otherwise tell the frontend and exit once idle.
pub fn request_quit<R: Runtime>(app: &AppHandle<R>) {
    let guard = app.state::<Guard<R>>();
    if !(guard.busy)(app) {
        (guard.exit)(app);
        return;
    }
    if guard.pending.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = app.emit(QUIT_PENDING_EVENT, ());

    let app = app.clone();
    std::thread::spawn(move || {
        let guard = app.state::<Guard<R>>();
        loop {
            // `exit` is itself held, and retried here, if new work started meanwhile.
            if !(guard.busy)(&app) {
                (guard.exit)(&app);
            }
            std::thread::sleep(POLL);
        }
    });
}

/// macOS's predefined Quit terminates without an `ExitRequested` that could be
/// held, so the app submenu must end up with a [`QUIT_MENU_ID`] item: the app's
/// own, or one swapped in for a predefined last item.
#[cfg(target_os = "macos")]
fn ensure_macos_quit<R: Runtime>(app: &AppHandle<R>) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{MenuItem, MenuItemKind};

    let Some(menu) = app.menu() else {
        return Ok(());
    };
    let Some(MenuItemKind::Submenu(app_menu)) = menu.items()?.into_iter().next() else {
        return Err("quit_guard: the menu's first item is not the app submenu".into());
    };
    let mut items = app_menu.items()?;
    if items.iter().any(|item| item.id() == QUIT_MENU_ID) {
        return Ok(());
    }
    let Some(MenuItemKind::Predefined(quit)) = items.pop() else {
        return Err(format!(
            "quit_guard: the app submenu has no `{QUIT_MENU_ID}` item and does not end in a predefined Quit to replace"
        )
        .into());
    };
    let label = format!("Quit {}", app.package_info().name);
    app_menu.remove(&quit)?;
    app_menu.append(&MenuItem::with_id(
        app,
        QUIT_MENU_ID,
        label,
        true,
        Some("CmdOrCtrl+Q"),
    )?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
    use tauri::{App, Listener, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use super::*;

    #[derive(Default)]
    struct Probe {
        busy: AtomicBool,
        exits: AtomicUsize,
        quit_pending: AtomicUsize,
        exit_requests: AtomicUsize,
        loop_ended: AtomicBool,
    }

    impl Probe {
        fn count(counter: &AtomicUsize) -> usize {
            counter.load(Ordering::SeqCst)
        }
    }

    fn probe_of(app: &AppHandle<MockRuntime>) -> Arc<Probe> {
        app.state::<Arc<Probe>>().inner().clone()
    }

    struct Harness {
        app: App<MockRuntime>,
        window: WebviewWindow<MockRuntime>,
    }

    struct View {
        app: AppHandle<MockRuntime>,
        window: WebviewWindow<MockRuntime>,
        probe: Arc<Probe>,
    }

    impl Harness {
        fn new(busy: bool) -> Self {
            let probe = Arc::new(Probe {
                busy: AtomicBool::new(busy),
                ..Probe::default()
            });
            let app = mock_builder()
                .manage(probe.clone())
                .plugin(plugin(
                    Box::new(|app| probe_of(app).busy.load(Ordering::SeqCst)),
                    |app| {
                        probe_of(app).exits.fetch_add(1, Ordering::SeqCst);
                    },
                ))
                .build(mock_context(noop_assets()))
                .unwrap();
            let window = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
                .build()
                .unwrap();
            app.listen_any(QUIT_PENDING_EVENT, move |_| {
                probe.quit_pending.fetch_add(1, Ordering::SeqCst);
            });
            Self { app, window }
        }

        fn view(&self) -> View {
            View {
                app: self.app.handle().clone(),
                window: self.window.clone(),
                probe: probe_of(self.app.handle()),
            }
        }

        /// Runs the event loop while `drive` works it from another thread.
        /// `drive` must end the loop, so it observes rather than asserts.
        fn run<T: Send + 'static>(self, drive: impl FnOnce(View) -> T + Send + 'static) -> T {
            let driver = std::thread::spawn({
                let view = self.view();
                move || drive(view)
            });
            self.app.run(|app, event| match event {
                RunEvent::ExitRequested { .. } => {
                    probe_of(app).exit_requests.fetch_add(1, Ordering::SeqCst);
                }
                RunEvent::Exit => probe_of(app).loop_ended.store(true, Ordering::SeqCst),
                _ => {}
            });
            driver.join().unwrap()
        }
    }

    impl View {
        /// Destroys every window, so an idle `ExitRequested` ends the loop.
        fn end_loop(&self) {
            let app = self.app.clone();
            let _ = self.app.run_on_main_thread(move || {
                WebviewWindowBuilder::new(&app, "last", WebviewUrl::default())
                    .build()
                    .unwrap();
                for window in app.webview_windows().into_values() {
                    window.destroy().unwrap();
                }
            });
        }
    }

    fn eventually(condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn an_idle_quit_exits_at_once() {
        let view = Harness::new(false).view();

        request_quit(&view.app);

        assert_eq!(Probe::count(&view.probe.exits), 1);
        assert_eq!(Probe::count(&view.probe.quit_pending), 0);
    }

    #[test]
    fn a_busy_quit_tells_the_frontend_once_and_exits_when_idle() {
        let view = Harness::new(true).view();
        let probe = &view.probe;

        request_quit(&view.app);
        request_quit(&view.app);
        std::thread::sleep(POLL * 2);
        assert_eq!(Probe::count(&probe.exits), 0);
        assert_eq!(Probe::count(&probe.quit_pending), 1);

        probe.busy.store(false, Ordering::SeqCst);
        assert!(eventually(|| Probe::count(&probe.exits) > 0));
        assert_eq!(Probe::count(&probe.quit_pending), 1);
    }

    #[test]
    fn an_idle_exit_request_passes() {
        let harness = Harness::new(false);
        let probe = probe_of(harness.app.handle());

        harness.run(|view| view.window.destroy().unwrap());

        assert!(probe.loop_ended.load(Ordering::SeqCst));
        assert_eq!(Probe::count(&probe.quit_pending), 0);
        assert_eq!(Probe::count(&probe.exits), 0);
    }

    #[test]
    fn a_busy_exit_request_is_held_until_idle() {
        let (quit_pending, held, exited) = Harness::new(true).run(|view| {
            let probe = &view.probe;
            view.window.destroy().unwrap();
            let quit_pending = eventually(|| Probe::count(&probe.quit_pending) == 1);
            let held = !probe.loop_ended.load(Ordering::SeqCst) && Probe::count(&probe.exits) == 0;
            probe.busy.store(false, Ordering::SeqCst);
            let exited = eventually(|| Probe::count(&probe.exits) > 0);
            view.end_loop();
            (quit_pending, held, exited)
        });

        assert!(quit_pending);
        assert!(held);
        assert!(exited);
    }

    #[test]
    fn a_close_while_busy_is_held_until_idle() {
        let (quit_pending, held, exited) = Harness::new(true).run(|view| {
            let probe = &view.probe;
            view.window.close().unwrap();
            let quit_pending = eventually(|| Probe::count(&probe.quit_pending) == 1);
            let held = Probe::count(&probe.exit_requests) == 0 && Probe::count(&probe.exits) == 0;
            probe.busy.store(false, Ordering::SeqCst);
            let exited = eventually(|| Probe::count(&probe.exits) > 0);
            view.end_loop();
            (quit_pending, held, exited)
        });

        assert!(quit_pending);
        assert!(held);
        assert!(exited);
    }
}
