//! A Modbus TCP device on loopback for tests, answering each request with a
//! closure, or from register banks that keep what is written.

use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};

use crate::{
    RegisterType,
    protocol::{bytes_to_coils, bytes_to_registers, coils_to_bytes, registers_to_bytes},
};

/// One request as the device saw it. `connection` counts accepted sockets from 1.
#[derive(Debug, Clone)]
pub struct Request {
    pub connection: usize,
    pub unit: u8,
    pub pdu: Vec<u8>,
}

impl Request {
    pub fn function(&self) -> u8 {
        self.pdu[0]
    }

    pub fn start(&self) -> u16 {
        u16::from_be_bytes([self.pdu[1], self.pdu[2]])
    }

    pub fn count(&self) -> u16 {
        u16::from_be_bytes([self.pdu[3], self.pdu[4]])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Pdu(Vec<u8>),
    Exception(u8),
    /// Answer nothing, and read the next request.
    Silent,
    /// Close this connection without answering.
    Drop,
    /// Close this connection and refuse every later one.
    Vanish,
}

pub struct Device {
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Device {
    /// Every request so far, in the order they arrived.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

/// Listens on `127.0.0.1` at once and answers each request with `answer`.
/// Panics outside a tokio runtime.
pub async fn device(answer: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Device {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let answer = Arc::new(answer);
    let gone = Arc::new(Notify::new());
    let seen = requests.clone();
    tokio::spawn(async move {
        let mut connection = 0;
        loop {
            let mut socket = tokio::select! {
                accepted = listener.accept() => accepted.unwrap().0,
                () = gone.notified() => return,
            };
            connection += 1;
            let (seen, answer, gone) = (seen.clone(), answer.clone(), gone.clone());
            tokio::spawn(async move {
                let mut header = [0u8; 7];
                while socket.read_exact(&mut header).await.is_ok() {
                    let length = u16::from_be_bytes([header[4], header[5]]) as usize;
                    let mut pdu = vec![0u8; length - 1];
                    if socket.read_exact(&mut pdu).await.is_err() {
                        return;
                    }
                    let request = Request {
                        connection,
                        unit: header[6],
                        pdu,
                    };
                    seen.lock().unwrap().push(request.clone());
                    let reply = match answer(&request) {
                        Reply::Pdu(pdu) => pdu,
                        Reply::Exception(code) => vec![request.function() | 0x80, code],
                        Reply::Silent => continue,
                        Reply::Drop => return,
                        Reply::Vanish => {
                            gone.notify_one();
                            return;
                        }
                    };
                    let mut adu = header[..4].to_vec();
                    adu.extend((reply.len() as u16 + 1).to_be_bytes());
                    adu.push(header[6]);
                    adu.extend(reply);
                    if socket.write_all(&adu).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Device { port, requests }
}

/// FC03/FC04 answered with each register holding its own address; FC06/FC16
/// acknowledged; anything else is exception 0x01.
pub fn registers(request: &Request) -> Reply {
    let pdu = &request.pdu;
    match request.function() {
        0x03 | 0x04 => {
            let mut reply = vec![pdu[0], (request.count() * 2) as u8];
            for register in request.start()..request.start() + request.count() {
                reply.extend(register.to_be_bytes());
            }
            Reply::Pdu(reply)
        }
        0x06 | 0x10 => Reply::Pdu(pdu[..5].to_vec()),
        _ => Reply::Exception(0x01),
    }
}

/// A device's four banks, every address zero until seeded or written, for
/// [`device`] to answer from with [`RegisterBanks::answer`]. Clones share the
/// banks.
#[derive(Clone)]
pub struct RegisterBanks {
    state: Arc<Mutex<BankState>>,
}

struct BankState {
    banks: [Vec<u16>; 4],
    applying_writes: bool,
}

impl Default for RegisterBanks {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(BankState {
                banks: std::array::from_fn(|_| vec![0; 1 << 16]),
                applying_writes: true,
            })),
        }
    }
}

impl RegisterBanks {
    /// `count` addresses of `bank` from `start`; a coil or discrete input is 0 or 1.
    pub fn get(&self, bank: RegisterType, start: u16, count: u16) -> Vec<u16> {
        let start = usize::from(start);
        self.state.lock().unwrap().banks[bank as usize][start..start + usize::from(count)].to_vec()
    }

    pub fn set(&self, bank: RegisterType, start: u16, values: &[u16]) {
        let start = usize::from(start);
        self.state.lock().unwrap().banks[bank as usize][start..start + values.len()]
            .copy_from_slice(values);
    }

    /// While `false`, a write is acknowledged but leaves the banks as they were.
    pub fn apply_writes(&self, applying: bool) {
        self.state.lock().unwrap().applying_writes = applying;
    }

    /// FC01 to FC06, FC15 and FC16 against the banks; a range past the last
    /// address is exception 0x02, any other function 0x01.
    pub fn answer(&self, request: &Request) -> Reply {
        let function = request.function();
        let Some(bank) = RegisterType::from_function_code(function) else {
            return Reply::Exception(0x01);
        };
        let (start, pdu, word) = (request.start(), &request.pdu, request.count());
        let count = if matches!(function, 0x05 | 0x06) {
            1
        } else {
            word
        };
        if usize::from(start) + usize::from(count) > 1 << 16 {
            return Reply::Exception(0x02);
        }
        if function <= 0x04 {
            let values = self.get(bank, start, count);
            let data = if bank.is_register_bank() {
                registers_to_bytes(&values)
            } else {
                coils_to_bytes(&values.iter().map(|&v| v != 0).collect::<Vec<_>>())
            };
            let mut reply = vec![function, data.len() as u8];
            reply.extend(data);
            return Reply::Pdu(reply);
        }
        let values: Vec<u16> = match function {
            0x05 => vec![u16::from(word == 0xFF00)],
            0x06 => vec![word],
            0x0F => bytes_to_coils(&pdu[6..], count.into())
                .into_iter()
                .map(u16::from)
                .collect(),
            _ => bytes_to_registers(&pdu[6..]),
        };
        if self.state.lock().unwrap().applying_writes {
            self.set(bank, start, &values);
        }
        Reply::Pdu(pdu[..5].to_vec())
    }
}
