# Changelog

## 0.1.1

- Rust 1.99 floor.
- tauri 2.12.1 floor.

## 0.1.0

- `quit_guard::init(busy)`: a plugin that prevents `ExitRequested` and a
  window's `CloseRequested` while the app's `busy` predicate holds, emits
  `quit-pending` to the frontend once, and exits once idle, polling every
  250 ms. `request_quit` starts the same from a command or tray item, and a
  menu item with id `QUIT_MENU_ID` is routed to it.
- On macOS, an app menu must end up with a `QUIT_MENU_ID` item, since the
  predefined Quit can't be held: the app's own, or one labelled
  `Quit <productName>` on CmdOrCtrl+Q swapped in for a predefined last item.
  Otherwise plugin setup fails. No menu at all is fine.
- tauri 2.10 without default features; generic over the runtime.
