use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wslib_auth_oidc::{Error, Verifier};

const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "the-client";
const KEY_A: &[u8] = include_bytes!("keys/a.pem");
const KEY_B: &[u8] = include_bytes!("keys/b.pem");
const JWK_A: &str = include_str!("keys/a.jwk.json");
const JWK_B: &str = include_str!("keys/b.jwk.json");

#[derive(Debug, serde::Deserialize, PartialEq)]
struct Claims {
    sub: String,
    email: Option<String>,
}

struct Issuer {
    url: String,
    state: Arc<Mutex<Answer>>,
}

struct Answer {
    status: u16,
    body: String,
    hits: usize,
    delay: Duration,
}

impl Issuer {
    async fn serving(jwks: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks.json", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Answer {
            status: 200,
            body: jwks_of(jwks),
            hits: 0,
            delay: Duration::ZERO,
        }));
        let shared = state.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let shared = shared.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0; 1024];
                    while !request.ends_with(b"\r\n\r\n") {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                    }
                    let (status, body, delay) = {
                        let mut answer = shared.lock().unwrap();
                        answer.hits += 1;
                        (answer.status, answer.body.clone(), answer.delay)
                    };
                    tokio::time::sleep(delay).await;
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        Self { url, state }
    }

    fn verifier(&self) -> Verifier {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Verifier::new(reqwest::Client::new(), ISSUER, AUDIENCE).with_jwks_url(&self.url)
    }

    fn hits(&self) -> usize {
        self.state.lock().unwrap().hits
    }

    fn serve(&self, jwks: &[&str]) {
        self.state.lock().unwrap().body = jwks_of(jwks);
    }

    fn fail(&self, status: u16) {
        self.state.lock().unwrap().status = status;
    }

    fn delay(&self, delay: Duration) {
        self.state.lock().unwrap().delay = delay;
    }
}

fn jwks_of(keys: &[&str]) -> String {
    format!("{{\"keys\":[{}]}}", keys.join(","))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims() -> Value {
    json!({
        "sub": "user-1",
        "email": "user@example.com",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now() + 600,
        "token_use": "id",
    })
}

fn signed(kid: &str, pem: &[u8], claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
}

fn with(changes: Value) -> Value {
    let mut claims = claims();
    for (name, value) in changes.as_object().unwrap() {
        match value {
            Value::Null => claims.as_object_mut().unwrap().remove(name),
            _ => claims
                .as_object_mut()
                .unwrap()
                .insert(name.clone(), value.clone()),
        };
    }
    claims
}

fn is_rejected<T: std::fmt::Debug>(result: Result<T, Error>) -> bool {
    matches!(result, Err(Error::Rejected(_)))
}

#[tokio::test]
async fn a_good_token_gives_its_claims() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let claims: Claims = issuer
        .verifier()
        .verify(&signed("a", KEY_A, &claims()))
        .await
        .unwrap();
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.email.as_deref(), Some("user@example.com"));
}

#[tokio::test]
async fn keys_are_fetched_once_and_reused() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let verifier = issuer.verifier();
    for _ in 0..3 {
        verifier
            .verify::<Claims>(&signed("a", KEY_A, &claims()))
            .await
            .unwrap();
    }
    assert_eq!(issuer.hits(), 1);
}

#[tokio::test]
async fn wrong_issuer_audience_or_expiry_is_rejected() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let verifier = issuer.verifier();
    for changes in [
        json!({"iss": "https://elsewhere.example"}),
        json!({"aud": "another-client"}),
        json!({"exp": now() - 3600}),
        json!({"nbf": now() + 3600}),
        json!({"aud": null}),
        json!({"iss": null}),
        json!({"exp": null}),
    ] {
        let token = signed("a", KEY_A, &with(changes.clone()));
        assert!(
            is_rejected(verifier.verify::<Claims>(&token).await),
            "{changes}"
        );
    }
}

#[tokio::test]
async fn a_token_signed_by_another_key_under_a_known_kid_is_rejected() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let token = signed("a", KEY_B, &claims());
    assert!(is_rejected(
        issuer.verifier().verify::<Claims>(&token).await
    ));
}

#[tokio::test]
async fn an_hmac_token_is_rejected() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("a".into());
    let token = jsonwebtoken::encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(JWK_A.as_bytes()),
    )
    .unwrap();
    assert!(is_rejected(
        issuer.verifier().verify::<Claims>(&token).await
    ));
}

#[tokio::test]
async fn a_token_without_a_kid_is_rejected_without_a_fetch() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::RS256),
        &claims(),
        &EncodingKey::from_rsa_pem(KEY_A).unwrap(),
    )
    .unwrap();
    assert!(is_rejected(
        issuer.verifier().verify::<Claims>(&token).await
    ));
    assert_eq!(issuer.hits(), 0);
}

#[tokio::test]
async fn token_use_is_required_when_asked_for() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let verifier = issuer.verifier().with_token_use("id");
    let access = signed("a", KEY_A, &with(json!({"token_use": "access"})));
    let unmarked = signed("a", KEY_A, &with(json!({"token_use": null})));
    assert!(is_rejected(verifier.verify::<Claims>(&access).await));
    assert!(is_rejected(verifier.verify::<Claims>(&unmarked).await));
    verifier
        .verify::<Claims>(&signed("a", KEY_A, &claims()))
        .await
        .unwrap();
}

#[tokio::test]
async fn claims_that_dont_fit_the_type_are_rejected() {
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct NeedsTenant {
        tenant: String,
    }
    let issuer = Issuer::serving(&[JWK_A]).await;
    let token = signed("a", KEY_A, &claims());
    assert!(is_rejected(
        issuer.verifier().verify::<NeedsTenant>(&token).await
    ));
}

#[tokio::test]
async fn a_rotated_key_is_picked_up() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let verifier = issuer.verifier().with_refetch_after(Duration::ZERO);
    verifier
        .verify::<Claims>(&signed("a", KEY_A, &claims()))
        .await
        .unwrap();
    issuer.serve(&[JWK_A, JWK_B]);
    verifier
        .verify::<Claims>(&signed("b", KEY_B, &claims()))
        .await
        .unwrap();
    assert_eq!(issuer.hits(), 2);
}

#[tokio::test]
async fn unknown_kids_refetch_at_most_once_per_window() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let verifier = issuer.verifier();
    for _ in 0..5 {
        let token = signed("b", KEY_B, &claims());
        assert!(is_rejected(verifier.verify::<Claims>(&token).await));
    }
    assert_eq!(issuer.hits(), 1);
}

#[tokio::test]
async fn a_failing_issuer_is_unavailable_and_not_hammered() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    issuer.fail(500);
    let verifier = issuer.verifier();
    for _ in 0..5 {
        let token = signed("a", KEY_A, &claims());
        assert!(matches!(
            verifier.verify::<Claims>(&token).await,
            Err(Error::Unavailable(_))
        ));
    }
    assert_eq!(issuer.hits(), 1);
}

#[tokio::test]
async fn a_failed_refetch_keeps_the_keys_held() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    let verifier = issuer.verifier().with_max_key_age(Duration::ZERO);
    verifier.refresh().await.unwrap();
    issuer.fail(503);
    assert!(verifier.refresh().await.is_err());
    verifier
        .verify::<Claims>(&signed("a", KEY_A, &claims()))
        .await
        .unwrap();
}

#[tokio::test]
async fn old_keys_are_refetched_so_a_withdrawn_key_stops_verifying() {
    let issuer = Issuer::serving(&[JWK_A, JWK_B]).await;
    let verifier = issuer
        .verifier()
        .with_max_key_age(Duration::from_millis(50))
        .with_refetch_after(Duration::ZERO);
    let token = signed("b", KEY_B, &claims());
    verifier.verify::<Claims>(&token).await.unwrap();
    issuer.serve(&[JWK_A]);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(is_rejected(verifier.verify::<Claims>(&token).await));
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_misses_share_one_fetch() {
    let issuer = Issuer::serving(&[JWK_A]).await;
    issuer.delay(Duration::from_millis(100));
    let verifier = Arc::new(issuer.verifier());
    let token = signed("a", KEY_A, &claims());
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let (verifier, token) = (verifier.clone(), token.clone());
            tokio::spawn(async move { verifier.verify::<Claims>(&token).await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(issuer.hits(), 1);
}

#[tokio::test]
async fn keys_of_other_types_and_uses_are_skipped() {
    let encryption_key = JWK_B.replace("\"sig\"", "\"enc\"");
    let ec_key = r#"{"kty":"EC","kid":"ec","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tw4rL7d3o9eo","y":"x_FEzRjAa1PHs1rmYBlFCWkP3zQCX8xQX-VWZkVtF0g"}"#;
    let issuer = Issuer::serving(&[ec_key, "{\"kty\":\"OKP-ish\"}", &encryption_key, JWK_A]).await;
    let verifier = issuer.verifier();
    verifier
        .verify::<Claims>(&signed("a", KEY_A, &claims()))
        .await
        .unwrap();
    assert!(is_rejected(
        verifier
            .verify::<Claims>(&signed("b", KEY_B, &claims()))
            .await
    ));
}

#[tokio::test]
async fn a_jwks_without_a_usable_key_is_unavailable() {
    let issuer = Issuer::serving(&[]).await;
    let result = issuer.verifier().refresh().await;
    assert!(matches!(result, Err(Error::Unavailable(_))), "{result:?}");
}

#[tokio::test]
async fn the_cognito_issuer_and_token_use() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let issuer = Issuer::serving(&[JWK_A]).await;
    let pool = "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_TEST";
    let verifier = Verifier::cognito(
        reqwest::Client::new(),
        "ap-southeast-2",
        "ap-southeast-2_TEST",
        AUDIENCE,
    )
    .with_jwks_url(&issuer.url);
    let id = signed("a", KEY_A, &with(json!({"iss": pool})));
    let access = signed(
        "a",
        KEY_A,
        &with(json!({"iss": pool, "token_use": "access"})),
    );
    verifier.verify::<Claims>(&id).await.unwrap();
    assert!(is_rejected(verifier.verify::<Claims>(&access).await));
}
