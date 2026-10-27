//! What every handler is handed: a bag of cheap-to-clone handles, cloned per request.
//! A hidden public field is for the family's own crates, not a product's to read.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::write::GzEncoder;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wslib_appliance_store::Store;
use wslib_appliance_types::branding::BrandingView;

#[derive(Clone, Debug)]
pub struct ApplianceState {
    pub store: Store,
    #[cfg_attr(not(feature = "sessions"), allow(dead_code))]
    pub(crate) sessions: SessionRows,
    #[doc(hidden)]
    pub passkeys: wslib_appliance_auth::Passkeys,
    pub(crate) codes: wslib_appliance_auth::CodeAttempts,
    pub(crate) pending: wslib_appliance_auth::PendingSignIns,
    /// A host's or the console's, in place of `sessions`.
    pub(crate) resolver: Option<crate::extract::Resolver>,
    pub(crate) vouches: crate::extract::Vouches,

    #[doc(hidden)]
    pub tls: Arc<crate::tls::Tls>,
    /// What this appliance trusts when it dials out, and the client configuration
    /// a product builds its HTTP client on.
    pub outbound: Arc<crate::tls::Outbound>,
    pub(crate) logs: crate::Logs,
    pub(crate) about: Arc<crate::about::Source>,
    pub(crate) hooks: Arc<crate::hooks::Hooks>,
    pub(crate) assets: Arc<Assets>,
    pub(crate) onboarding: bool,
    pub(crate) above_admin: crate::AboveAdmin,
    pub(crate) base_path: wslib_appliance_config::BasePath,
    pub(crate) stop: CancellationToken,
    pub(crate) listening: Option<Arc<dyn Listening>>,
    pub(crate) unfinished: Unfinished,
}

/// Work a caller that gives up must not cut short; shutdown waits for it before the audit queue closes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Unfinished(Arc<watch::Sender<usize>>);

impl Unfinished {
    pub(crate) fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        self.0.send_modify(|running| *running += 1);
        let held = Held(self.0.clone());
        tokio::spawn(async move {
            let _held = held;
            work.await
        })
    }

    pub(crate) async fn finished(&self) {
        self.0
            .subscribe()
            .wait_for(|running| *running == 0)
            .await
            .ok();
    }
}

struct Held(Arc<watch::Sender<usize>>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.send_modify(|running| *running -= 1);
    }
}

#[cfg(feature = "sessions")]
type Rows = wslib_appliance_auth::Sessions;
#[cfg(not(feature = "sessions"))]
type Rows = std::convert::Infallible;

/// `None` for a backend with no sign-in, where only local authority or a resolver lets a caller in.
#[derive(Clone, Debug, Default)]
pub(crate) struct SessionRows(pub(crate) Option<Rows>);

#[cfg(feature = "sessions")]
impl SessionRows {
    pub(crate) fn get(&self) -> Option<&Rows> {
        self.0.as_ref()
    }
}

#[doc(hidden)]
pub trait Listening: std::fmt::Debug + Send + Sync {
    fn https_port(&self) -> watch::Receiver<u16>;
}

impl ApplianceState {
    /// The TLS listener's port, updated when it binds; `0` on a backend that serves none.
    pub fn https_port(&self) -> watch::Receiver<u16> {
        match &self.listening {
            Some(listening) => listening.https_port(),
            None => watch::channel(0).1,
        }
    }

    /// `Server::shutdown`, from inside a handler: a response that holds its
    /// connection open must end on it, or it holds the drain open.
    pub fn shutdown(&self) -> CancellationToken {
        self.stop.child_token()
    }
}

#[derive(Debug)]
pub(crate) struct Assets {
    pub branding: BrandingBody,
    pub names_the_box: bool,
    pub logo: Option<Logo>,
}

/// Made again only when the hostname is not the last one served.
#[derive(Debug)]
pub(crate) struct BrandingBody(Mutex<(BrandingView, Arc<Tagged>)>);

impl BrandingBody {
    pub(crate) fn new(view: BrandingView) -> Self {
        let tagged = Arc::new(Tagged::of(&view));
        Self(Mutex::new((view, tagged)))
    }

    pub(crate) fn naming(&self, hostname: Option<String>) -> Arc<Tagged> {
        let mut served = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if served.0.hostname != hostname {
            let view = BrandingView {
                hostname,
                ..served.0.clone()
            };
            let tagged = Arc::new(Tagged::of(&view));
            *served = (view, tagged);
        }
        served.1.clone()
    }
}

#[derive(Debug)]
pub(crate) struct Tagged {
    pub body: Bytes,
    /// Weak, because the compression layer sends the same tag with the gzipped bytes.
    pub etag: HeaderValue,
}

impl Tagged {
    fn of(view: &BrandingView) -> Self {
        use sha2::{Digest, Sha256};
        let body =
            serde_json::to_vec(view).expect("Branding is plain data and cannot fail to serialise");
        let etag = format!("W/\"{}\"", crate::hex(&Sha256::digest(&body)[..8]));
        Self {
            etag: HeaderValue::from_str(&etag).expect("hex in quotes is a legal header value"),
            body: body.into(),
        }
    }
}

/// An image served at `/api/branding/logo`.
#[doc(hidden)]
pub struct Logo {
    pub bytes: Bytes,
    pub content_type: HeaderValue,
    /// Kept for any type but a raster image, and only when smaller than `bytes`.
    pub gzipped: Option<Bytes>,
}

impl Logo {
    pub fn new(bytes: Bytes, content_type: HeaderValue) -> Self {
        let kind = content_type.as_bytes();
        let raster = kind.starts_with(b"image/") && !kind.starts_with(b"image/svg+xml");
        let gzipped = (!raster)
            .then(|| {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(&bytes).expect("gzip into a Vec");
                encoder.finish().expect("gzip into a Vec")
            })
            .filter(|gzipped| gzipped.len() < bytes.len())
            .map(Bytes::from);
        Self {
            gzipped,
            bytes,
            content_type,
        }
    }

    /// `asked` is the request's headers, with what the encoder cap set aside put back.
    pub(crate) fn respond(&self, asked: &HeaderMap) -> Response {
        let content_type = (header::CONTENT_TYPE, self.content_type.clone());
        let response = match &self.gzipped {
            Some(gzipped) if wslib_http_scaffold::accepts_gzip(asked) => {
                let encoding = (header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                ([content_type, encoding], gzipped.clone()).into_response()
            }
            _ => ([content_type], self.bytes.clone()).into_response(),
        };
        crate::compress::negotiated(response)
    }
}

/// A derived `Debug` would put the whole file into any log line that formats the state.
impl std::fmt::Debug for Logo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logo")
            .field("content_type", &self.content_type)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_appliance_types::Branding;

    #[test]
    fn the_branding_body_is_made_again_only_when_the_hostname_changes() {
        let body = BrandingBody::new(BrandingView {
            branding: Branding::unbranded(),
            build: "b1".to_string(),
            hostname: None,
        });
        let unnamed = body.naming(None);
        let named = body.naming(Some("widget-1234".to_string()));
        assert!(Arc::ptr_eq(
            &named,
            &body.naming(Some("widget-1234".to_string()))
        ));
        assert_ne!(named.etag, unnamed.etag);

        let view: BrandingView = serde_json::from_slice(&named.body).expect("a view");
        assert_eq!(view.hostname.as_deref(), Some("widget-1234"));
        assert_eq!(view.build, "b1");
        let view: BrandingView = serde_json::from_slice(&body.naming(None).body).expect("a view");
        assert_eq!(view.hostname, None);
    }
}
