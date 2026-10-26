# wslib-tauri

Pieces for Tauri 2 desktop apps. So far one: `quit_guard`, a plugin that
holds a quit until the app's in-flight work has finished and then exits on
its own, because quitting part-way through a write can leave a file
truncated.

```rust
tauri::Builder::default()
    .plugin(wslib_tauri::quit_guard::init(|app| app.state::<AppState>().is_busy()))
```

## What's here

- **`quit_guard::init(busy)`**: the plugin. `busy` says whether work is in
  flight; it runs on the event loop and on a poll thread, so keep it cheap
  and non-blocking (a `try_lock`, an atomic).
  - An `ExitRequested` (the last window closing, `app.exit`) while busy is
    prevented, and so is a window's `CloseRequested`. Either starts a quit.
  - **`request_quit(app)`** starts one directly, from a command or a tray
    item. Idle, it exits at once. Busy, it emits `QUIT_PENDING_EVENT`
    (`"quit-pending"`) to the frontend once, then polls every 250 ms and
    exits once idle. That exit is held and retried in turn if new work
    started meanwhile.
  - A menu item with the id **`QUIT_MENU_ID`** is routed to `request_quit`.
- **On macOS** the predefined Quit terminates without an `ExitRequested`
  that could be held, so when the app has a menu, its app submenu must end
  up with a `QUIT_MENU_ID` item. The app can supply its own; otherwise the
  plugin swaps the submenu's last item, when it is predefined, for one
  labelled `Quit <productName>` on CmdOrCtrl+Q. If neither is possible,
  plugin setup fails with an error saying so, rather than leave a Cmd+Q
  that kills the process mid-write. No menu at all is fine: there's no Cmd+Q
  then. The check runs on the menu set on the builder, the default one
  included, which is installed before plugins are set up; a menu the app
  sets later, in its own `setup`, needs a `QUIT_MENU_ID` item of its own.

The frontend can say why the window has not gone:

```ts
import { listen } from "@tauri-apps/api/event";
await listen("quit-pending", () => showBanner("Finishing up, then quitting…"));
```

A restart (`app.restart`) can't be held.
