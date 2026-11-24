use std::time::Duration;

use tokio::time::{sleep, timeout};
use wslib_can::{CanEvent, CanFrame, CanOptions, CanTask, Direction, loopback::LoopbackBus};
use wslib_isotp::testing::Responder;
use wslib_isotp::{
    Addressing, FdLength, FrameFormat, Framing, IsoTpLink, LinkConfig, MAX_MESSAGE, StMin,
};

const BUS: u8 = 0;
const TESTER: u32 = 0x7E0;
const ECU: u32 = 0x7E8;
const SIZES: [usize; 6] = [1, 7, 8, 62, 1200, MAX_MESSAGE];
const PATIENCE: Duration = Duration::from_secs(60);

fn reversed(request: &[u8]) -> Vec<Vec<u8>> {
    vec![request.iter().rev().copied().collect()]
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + len) as u8).collect()
}

async fn serve<A: FnMut(&[u8]) -> Vec<Vec<u8>>>(mut task: CanTask, mut responder: Responder<A>) {
    let writer = task.writer();
    let fd = responder.framing().is_fd();
    while let Some(event) = task.next_event().await {
        let CanEvent::Read(reads) = event else {
            continue;
        };
        for read in reads {
            if read.direction != Direction::Rx || read.frame.arb_id != TESTER {
                continue;
            }
            for frame in responder.on_frame(&read.frame.data) {
                sleep(frame.delay).await;
                let out = CanFrame::data(BUS, ECU, false, fd, false, frame.data);
                writer.send(out).await.unwrap().unwrap();
            }
        }
    }
}

async fn tester_against<A>(config: LinkConfig, responder: Responder<A>)
where
    A: FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
{
    let bus = LoopbackBus::default();
    let mut options = CanOptions::default();
    options.own_frames = true;
    let ecu = bus.port().open(options.clone()).await.unwrap();
    tokio::spawn(serve(ecu, responder));
    let tester = bus.port().open(options).await.unwrap();
    let (link, mut messages) = IsoTpLink::over(tester, config);
    for len in SIZES {
        let request = message(len);
        timeout(PATIENCE, link.send(&request))
            .await
            .unwrap()
            .unwrap();
        let reply = timeout(PATIENCE, messages.recv()).await.unwrap();
        assert_eq!(reply, reversed(&request).pop(), "{len}");
    }
}

fn tester(framing: Framing) -> LinkConfig {
    let mut config = LinkConfig::new(BUS, TESTER, ECU);
    config.extended = false;
    config.framing = framing;
    config.block_size = 4;
    config
}

#[tokio::test(start_paused = true)]
async fn the_link_talks_to_the_responder_through_waits_blocks_and_st_min() {
    let ecu = Framing::default();
    let responder = Responder::new(ecu, reversed)
        .flow_control(2, StMin(0x05))
        .waits(3, Duration::from_millis(10));
    tester_against(tester(ecu.peer()), responder).await;
}

#[tokio::test(start_paused = true)]
async fn a_can_fd_link_with_extended_addressing_talks_to_the_responder() {
    let mut ecu = Framing::new(
        Addressing::Extended { tx: 0xF1, rx: 0x10 },
        FrameFormat::Fd(FdLength::MAX),
    );
    ecu.padding = Some(0x00);
    let responder = Responder::new(ecu, reversed).flow_control(8, StMin(0xF2));
    tester_against(tester(ecu.peer()), responder).await;
}
