# wslib-tasks

Long-lived tasks, one per row of a desired set (a device, a link, a feed),
kept in step with the rows: started for a new row, stopped for a departed
one, restarted when a row's value changes or its task has ended.

```rust
use wslib_tasks::TaskTable;

let links = Arc::new(TaskTable::<DeviceId, LinkConfig>::named("device links"));

tokio::spawn({
    let links = links.clone();
    async move {
        links
            .run(stop, || db.enabled_links(), |id, config, cancel| {
                Some(run_link(id.clone(), config.clone(), cancel))
            })
            .await
    }
});

// After a write that changes which links should run:
links.notify();
```

## What's here

- **`run(stop, desired, start)`** reads the whole desired set and reconciles
  against it now, on each `notify()`, and 60 s after the last pass when
  nothing notifies, for writes it wasn't told of (another process's, say).
  When `stop` fires it stops every task and waits for each. A failed read is
  logged and leaves the running tasks alone. Dropping `run` stops every task
  without waiting.
- **`notify()`** asks for a pass soon. The caller says only that something
  changed, never what.
- **`reconcile(desired, start)`** is one pass, returning `Reconciled`:
  how many tasks were started, stopped and restarted. All zeros is the
  steady state.
- **`start`** gets the row's key, its value and a `CancellationToken`, and
  returns the task's future, or `None` for a row that can't run now, which
  is tried again next pass.
- **A row's task has ended before its replacement starts**, so two tasks
  never hold one row's resource. A pass waits for every task it stops, so a
  task must end promptly once its token is cancelled.
- **`named(name)`** puts `name` in the `table` field of its log lines;
  `Default` names it `unnamed`.
