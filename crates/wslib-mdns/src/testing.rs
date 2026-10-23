//! An in-process fake avahi, served over a socket pair.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use wslib_mdns::avahi::Avahi;
//! use wslib_mdns::testing::FakeAvahi;
//! use wslib_mdns::{AdvertState, Service};
//!
//! let fake = FakeAvahi::new().colliding("Widget");
//! let (bus, _served) = fake.connect().await?;
//! let service = Service::new("_http._tcp".parse()?, "Widget".parse()?, 8080);
//! let advert = Avahi::new(&bus).advertise(&service).await?;
//! let mut state = advert.state();
//! state.wait_for(|s| *s == AdvertState::Collided).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{Notify, watch};
use zbus::connection::Builder;
use zbus::message::{Header, Message};
use zbus::names::ErrorName;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Guid};

use crate::avahi::{AVAHI, ServerState};

const ESTABLISHED: i32 = 2;
const COLLISION: i32 = 3;

/// A fake avahi: it records each call, holds a host name, and collides as told.
#[derive(Debug, Clone)]
pub struct FakeAvahi(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    host_name: String,
    running: bool,
    instance: u32,
    made: u32,
    groups: BTreeMap<u32, Group>,
    colliding: BTreeSet<String>,
    taken: BTreeSet<String>,
    refusing: BTreeSet<String>,
    refuse_next: HashMap<String, usize>,
    holds: HashMap<String, Hold>,
    heard: Vec<String>,
}

#[derive(Debug, Default)]
struct Group {
    names: BTreeSet<String>,
    state: i32,
}

impl State {
    fn refuses(&mut self, method: &str) -> bool {
        let counted = self.refuse_next.get_mut(method).filter(|n| **n > 0);
        counted.map(|n| *n -= 1).is_some() || self.refusing.contains(method)
    }

    fn group(&mut self, n: u32) -> Result<&mut Group, Refusal> {
        self.groups
            .get_mut(&n)
            .ok_or_else(|| Refusal::new(BAD_STATE, format!("group {n} is freed")))
    }

    fn add(&mut self, n: u32, name: &str) -> Result<(), Refusal> {
        if self.taken.contains(name) {
            return Err(Refusal::new(COLLISION_ERROR, format!("{name} is taken")));
        }
        self.group(n)?.names.insert(name.to_string());
        Ok(())
    }
}

impl Default for FakeAvahi {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeAvahi {
    /// A running avahi calling the machine `box`.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            host_name: "box".to_string(),
            running: true,
            instance: 1,
            made: 0,
            groups: BTreeMap::new(),
            colliding: BTreeSet::new(),
            taken: BTreeSet::new(),
            refusing: BTreeSet::new(),
            refuse_next: HashMap::new(),
            holds: HashMap::new(),
            heard: Vec::new(),
        })))
    }

    pub fn called(self, host_name: &str) -> Self {
        self.state().host_name = host_name.to_string();
        self
    }

    /// A group holding `name`, a service instance or an address's host, collides once committed.
    pub fn colliding(self, name: &str) -> Self {
        self.state().colliding.insert(name.to_string());
        self
    }

    /// Adding a record for `name` is refused as held by another client here.
    pub fn taken(self, name: &str) -> Self {
        self.state().taken.insert(name.to_string());
        self
    }

    /// Refuses every call of `method`, such as `SetHostName`, as not permitted.
    pub fn refusing(self, method: &str) -> Self {
        self.state().refusing.insert(method.to_string());
        self
    }

    /// Refuses the next `n` calls of `method` as not permitted.
    pub fn refuse_next(&self, method: &str, n: usize) {
        self.state().refuse_next.insert(method.to_string(), n);
    }

    /// Drops every scripted collision and refusal, so what failed now succeeds.
    pub fn forgive(&self) {
        let mut state = self.state();
        state.colliding.clear();
        state.taken.clear();
        state.refusing.clear();
        state.refuse_next.clear();
    }

    /// Holds each call of `method` open, after it is heard, until released.
    pub fn hold(&self, method: &str) -> Hold {
        let hold = Hold {
            entered: Arc::new(Notify::new()),
            released: Arc::new(watch::channel(false).0),
        };
        self.state().holds.insert(method.to_string(), hold.clone());
        hold
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    /// Hears `method`, waits while it is held, then refuses it if avahi is
    /// stopped or it is scripted to.
    async fn call(&self, method: &str, what: String) -> Result<(), Refusal> {
        let hold = {
            let mut state = self.state();
            state
                .heard
                .push(format!("{method} {what}").trim_end().to_string());
            state.holds.get(method).cloned()
        };
        if let Some(hold) = hold {
            hold.wait().await;
        }
        let mut state = self.state();
        if !state.running {
            return Err(Refusal::new(
                SERVICE_UNKNOWN,
                format!("nobody owns {AVAHI}"),
            ));
        }
        if state.refuses(method) {
            return Err(Refusal::new(NOT_PERMITTED, format!("{method} refused")));
        }
        Ok(())
    }

    /// Each call, in order, such as `AddService 1 -1 -1 0 Widget _http._tcp 8080 product=widget`.
    pub fn heard(&self) -> Vec<String> {
        self.state().heard.clone()
    }

    pub fn host_name(&self) -> String {
        self.state().host_name.clone()
    }

    /// The names in each group established now.
    pub fn established(&self) -> Vec<String> {
        self.state()
            .groups
            .values()
            .filter(|g| g.state == ESTABLISHED)
            .flat_map(|g| g.names.iter().cloned())
            .collect()
    }

    /// `(client, served)`: a peer-to-peer connection to the fake, and the
    /// fake's own end, which must be kept alive as long as the client is used
    /// and is what the signalling calls take.
    pub async fn connect(&self) -> zbus::Result<(Connection, Connection)> {
        let (ours, theirs) = tokio::net::UnixStream::pair()?;
        let served = Builder::unix_stream(theirs)
            .server(Guid::generate())?
            .p2p()
            .serve_at("/", Server(self.clone()))?
            .serve_at("/org/freedesktop/DBus", Bus(self.clone()))?
            .build();
        let client = Builder::unix_stream(ours).p2p().build();
        let (served, client) = tokio::try_join!(served, client)?;
        Ok((client, served))
    }

    /// Another host answers for `name`: every established group holding it collides.
    pub async fn collide(&self, served: &Connection, name: &str) -> zbus::Result<()> {
        let hit: Vec<u32> = self
            .state()
            .groups
            .iter_mut()
            .filter(|(_, g)| g.state == ESTABLISHED && g.names.contains(name))
            .map(|(n, g)| {
                g.state = COLLISION;
                *n
            })
            .collect();
        for n in hit {
            let group = served
                .object_server()
                .interface::<_, GroupObject>(group_path(n))
                .await?;
            GroupObject::state_changed(group.signal_emitter(), COLLISION, "").await?;
        }
        Ok(())
    }

    /// avahi's own name collides and it renames itself to `host_name`.
    pub async fn rename(&self, served: &Connection, host_name: &str) -> zbus::Result<()> {
        self.server_state(served, ServerState::Collision).await?;
        self.state().host_name = host_name.to_string();
        self.server_state(served, ServerState::Registering).await?;
        self.server_state(served, ServerState::Running).await
    }

    /// `StateChanged` from the server.
    pub async fn server_state(&self, served: &Connection, state: ServerState) -> zbus::Result<()> {
        let code = match state {
            ServerState::Registering => 1,
            ServerState::Running => 2,
            ServerState::Collision => 3,
            ServerState::Failure => 4,
            ServerState::Invalid => 0,
        };
        let server = served.object_server().interface::<_, Server>("/").await?;
        Server::state_changed(server.signal_emitter(), code, "").await
    }

    /// A new avahi takes the name, holding none of the old one's groups.
    pub async fn restart(&self, served: &Connection) -> zbus::Result<()> {
        self.owner_changed(served, true).await
    }

    /// avahi stops: nothing owns its name, and every call fails as
    /// `org.freedesktop.DBus.Error.ServiceUnknown`.
    pub async fn stop(&self, served: &Connection) -> zbus::Result<()> {
        self.owner_changed(served, false).await
    }

    async fn owner_changed(&self, served: &Connection, running: bool) -> zbus::Result<()> {
        let (old, new) = {
            let mut state = self.state();
            let old = state.running.then(|| format!(":1.{}", state.instance));
            state.groups.clear();
            state.running = running;
            state.instance += 1;
            (old, running.then(|| format!(":1.{}", state.instance)))
        };
        let signal = zbus::Message::signal(
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameOwnerChanged",
        )?
        .sender("org.freedesktop.DBus")?
        .build(&(AVAHI, old.unwrap_or_default(), new.unwrap_or_default()))?;
        served.send(&signal).await
    }
}

/// A call held open by [`FakeAvahi::hold`].
#[derive(Debug, Clone)]
pub struct Hold {
    entered: Arc<Notify>,
    released: Arc<watch::Sender<bool>>,
}

impl Hold {
    /// Waits until a held call has arrived.
    pub async fn entered(&self) {
        self.entered.notified().await;
    }

    /// Lets each held call go on, and every later one through.
    pub fn release(&self) {
        self.released.send_replace(true);
    }

    async fn wait(&self) {
        self.entered.notify_one();
        self.released.subscribe().wait_for(|r| *r).await.ok();
    }
}

const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const COLLISION_ERROR: &str = "org.freedesktop.Avahi.CollisionError";
const NOT_PERMITTED: &str = "org.freedesktop.Avahi.NotPermittedError";
const BAD_STATE: &str = "org.freedesktop.Avahi.BadStateError";
const IS_EMPTY: &str = "org.freedesktop.Avahi.IsEmptyError";
const NO_CHANGE: &str = "org.freedesktop.Avahi.NoChangeError";

/// An error reply under its full D-Bus name, which zbus's derive would prefix.
#[derive(Debug)]
struct Refusal {
    name: &'static str,
    message: String,
}

impl Refusal {
    fn new(name: &'static str, message: String) -> Self {
        Self { name, message }
    }
}

impl From<zbus::Error> for Refusal {
    fn from(e: zbus::Error) -> Self {
        Self::new("org.freedesktop.zbus.Error", e.to_string())
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

impl std::error::Error for Refusal {}

impl zbus::DBusError for Refusal {
    fn create_reply(&self, call: &Header<'_>) -> zbus::Result<Message> {
        Message::error(call, self.name())?.build(&(self.message.as_str(),))
    }

    fn name(&self) -> ErrorName<'_> {
        ErrorName::from_static_str_unchecked(self.name)
    }

    fn description(&self) -> Option<&str> {
        Some(&self.message)
    }
}

fn group_path(n: u32) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("/Client1/EntryGroup{n}")).unwrap()
}

struct Server(FakeAvahi);

#[zbus::interface(name = "org.freedesktop.Avahi.Server")]
impl Server {
    #[zbus(name = "EntryGroupNew")]
    async fn entry_group_new(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<OwnedObjectPath, Refusal> {
        let n = {
            let mut state = self.0.state();
            state.made += 1;
            state.made
        };
        self.0.call("EntryGroupNew", n.to_string()).await?;
        self.0.state().groups.insert(n, Group::default());
        server
            .at(group_path(n), GroupObject(self.0.clone(), n))
            .await?;
        Ok(group_path(n))
    }

    #[zbus(name = "GetHostName")]
    async fn get_host_name(&self) -> Result<String, Refusal> {
        self.0.call("GetHostName", String::new()).await?;
        Ok(self.0.state().host_name.clone())
    }

    #[zbus(name = "SetHostName")]
    async fn set_host_name(
        &self,
        name: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(), Refusal> {
        self.0.call("SetHostName", name.clone()).await?;
        let unchanged = std::mem::replace(&mut self.0.state().host_name, name.clone()) == name;
        if unchanged {
            return Err(Refusal::new(
                NO_CHANGE,
                "the name is already the host's".into(),
            ));
        }
        Self::state_changed(&emitter, 1, "").await?;
        Self::state_changed(&emitter, 2, "").await?;
        Ok(())
    }

    #[zbus(signal)]
    async fn state_changed(
        emitter: &SignalEmitter<'_>,
        state: i32,
        error: &str,
    ) -> zbus::Result<()>;
}

struct GroupObject(FakeAvahi, u32);

#[zbus::interface(name = "org.freedesktop.Avahi.EntryGroup")]
impl GroupObject {
    #[allow(clippy::too_many_arguments)]
    #[zbus(name = "AddService")]
    async fn add_service(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: String,
        kind: String,
        _domain: String,
        _host: String,
        port: u16,
        txt: Vec<Vec<u8>>,
    ) -> Result<(), Refusal> {
        let txt: Vec<_> = txt.iter().map(|t| String::from_utf8_lossy(t)).collect();
        let n = self.1;
        let what = format!(
            "{n} {interface} {protocol} {flags} {name} {kind} {port} {}",
            txt.join(" ")
        );
        self.0.call("AddService", what).await?;
        self.0.state().add(n, &name)
    }

    #[allow(clippy::too_many_arguments)]
    #[zbus(name = "AddServiceSubtype")]
    async fn add_service_subtype(
        &self,
        _interface: i32,
        _protocol: i32,
        _flags: u32,
        name: String,
        _kind: String,
        _domain: String,
        subtype: String,
    ) -> Result<(), Refusal> {
        let what = format!("{} {name} {subtype}", self.1);
        self.0.call("AddServiceSubtype", what).await?;
        self.0.state().group(self.1).map(drop)
    }

    #[zbus(name = "AddAddress")]
    async fn add_address(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: String,
        address: String,
    ) -> Result<(), Refusal> {
        let what = format!("{} {interface} {protocol} {flags} {name} {address}", self.1);
        self.0.call("AddAddress", what).await?;
        self.0.state().add(self.1, &name)
    }

    #[zbus(name = "Commit")]
    async fn commit(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(), Refusal> {
        self.0.call("Commit", self.1.to_string()).await?;
        let settled = {
            let mut state = self.0.state();
            let colliding = state.colliding.clone();
            let group = state.group(self.1)?;
            if group.names.is_empty() {
                return Err(Refusal::new(IS_EMPTY, "nothing to commit".into()));
            }
            let collides = group
                .names
                .iter()
                .any(|n| colliding.contains(n) || colliding.contains(n.trim_end_matches(".local")));
            group.state = if collides { COLLISION } else { ESTABLISHED };
            group.state
        };
        Self::state_changed(&emitter, 1, "").await?;
        Self::state_changed(&emitter, settled, "").await?;
        Ok(())
    }

    #[zbus(name = "Free")]
    async fn free(&self) -> Result<(), Refusal> {
        self.0.call("Free", self.1.to_string()).await?;
        self.0.state().groups.remove(&self.1);
        Ok(())
    }

    #[zbus(signal)]
    async fn state_changed(
        emitter: &SignalEmitter<'_>,
        state: i32,
        error: &str,
    ) -> zbus::Result<()>;
}

struct Bus(FakeAvahi);

#[zbus::interface(name = "org.freedesktop.DBus")]
impl Bus {
    #[zbus(name = "NameHasOwner")]
    fn name_has_owner(&self, name: String) -> bool {
        name == AVAHI && self.0.state().running
    }
}
