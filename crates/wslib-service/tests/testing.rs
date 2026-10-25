use std::time::Duration;

use wslib_service::Manager;
use wslib_service::testing::{self, Told};

#[tokio::test]
async fn a_test_stop_records_ready_and_its_statuses_and_stops_when_its_manager_asks() {
    let (stop, recorder) = testing::stop();
    assert_eq!(stop.manager(), Manager::Detached);
    let ready = stop.ready();
    ready.status("starting");
    ready.send(Some("serving"));
    ready.send(Some("busy"));
    ready.status("draining");

    let stopped = tokio::spawn(stop);
    tokio::task::yield_now().await;
    assert!(!stopped.is_finished());
    recorder.stop();
    tokio::time::timeout(Duration::from_secs(5), stopped)
        .await
        .expect("stopped")
        .unwrap();

    let told = recorder.told();
    assert_eq!(told.ready, Some(Some("serving".to_string())));
    assert_eq!(told.statuses, ["starting", "busy", "draining"]);
    assert!(!told.stopped_itself);
}

#[tokio::test]
async fn a_recorder_can_await_ready_and_its_status() {
    let (stop, recorder) = testing::stop();
    let ready = stop.ready();
    let awaited = tokio::spawn({
        let recorder = recorder.clone();
        async move { recorder.ready().await }
    });
    tokio::task::yield_now().await;
    assert!(!awaited.is_finished(), "not ready yet");
    ready.send(Some("serving"));
    let status = tokio::time::timeout(Duration::from_secs(5), awaited)
        .await
        .expect("ready was sent")
        .unwrap();
    assert_eq!(status.as_deref(), Some("serving"));
    assert_eq!(
        recorder.ready().await.as_deref(),
        Some("serving"),
        "and stays so"
    );
}

#[test]
fn a_ready_from_a_dropped_test_stop_tells_nobody() {
    let ready = testing::stop().0.ready();
    ready.send(Some("serving"));
    ready.status("still");
}

#[tokio::test]
async fn the_first_poll_says_ready_and_a_cancelled_token_is_a_stop_of_its_own() {
    let (stop, recorder) = testing::stop();
    assert_eq!(recorder.told(), Told::default());
    stop.token().cancel();
    stop.await;
    let told = recorder.told();
    assert_eq!(told.ready, Some(None));
    assert!(told.stopped_itself);
}
