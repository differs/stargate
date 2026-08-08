//! Portal — commercial user-facing API (Rust port): register, login,
//! API key management, recharge & pay. Serves the P0 "can take money"
//! loop on a separate port.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{AuthService, CachedKeyStore};
use crate::payment::PaymentService;
use openidconnect::core::{
    CoreClient, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};

pub struct PortalState {
    pub auth: AuthService,
    pub keys: std::sync::Arc<CachedKeyStore>,
    pub pay: PaymentService,
    pub admin_key: String,
    /// Session JWT manager (optional).
    pub jwt: Option<crate::jwt::JwtManager>,
    /// OIDC client (optional).
    pub oidc: Option<std::sync::Arc<OidcClient>>,
    /// Merchant portal static directory (optional).
    pub web_dir: Option<String>,
}

/// OIDC authorization-code client (discovery + exchange + verify).
pub struct OidcClient {
    client: CoreClient,
    redirect: String,
}

impl OidcClient {
    pub async fn new(
        provider_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect: &str,
    ) -> Result<Self, String> {
        let meta = CoreProviderMetadata::discover_async(
            IssuerUrl::new(provider_url.to_string()).map_err(|e| e.to_string())?,
            openidconnect::reqwest::async_http_client,
        )
        .await
        .map_err(|e| e.to_string())?;
        let client = openidconnect::Client::from_provider_metadata(
            meta,
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
        )
        .set_redirect_uri(RedirectUrl::new(redirect.to_string()).map_err(|e| e.to_string())?);
        Ok(Self {
            client,
            redirect: redirect.to_string(),
        })
    }

    /// Build the IdP authorization URL (state = CSRF).
    pub fn auth_url(&self, state: String) -> String {
        use openidconnect::{AuthenticationFlow, Nonce, Scope};
        let auth = self.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            move || openidconnect::CsrfToken::new(state),
            || Nonce::new("".into()),
        );
        let (url, _, _) = auth
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .url();
        url.to_string()
    }

    /// Exchange the code, verify id_token, return (subject, email).
    pub async fn exchange(&self, code: &str) -> Result<(String, String), String> {
        use openidconnect::AuthorizationCode;
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(openidconnect::reqwest::async_http_client)
            .await
            .map_err(|e| e.to_string())?;
        let id_token = token.extra_fields().id_token().ok_or("no id_token")?;
        let verifier = self.client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &openidconnect::Nonce::new("".into()))
            .map_err(|e| e.to_string())?;
        let subject = claims.subject().as_str().to_string();
        let email = claims
            .email()
            .map(|e| e.as_str().to_string())
            .unwrap_or_else(|| subject.clone());
        Ok((subject, email))
    }
}

/// Build the portal router; serves static merchant portal files at /
/// when web_dir is set.
pub fn router(state: Arc<PortalState>) -> Router {
    let mut app = Router::new()
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/keys", post(create_key).get(list_keys))
        .route("/api/recharge", post(recharge))
        .route("/api/recharge/pay", post(pay))
        .route("/api/recharge/status", axum::routing::get(recharge_status))
        .route("/api/oidc/login", axum::routing::get(oidc_login))
        .route("/api/oidc/callback", axum::routing::get(oidc_callback))
        .route("/api/balance", axum::routing::get(balance))
        .route(
            "/api/admin/users/{id}/limits",
            axum::routing::put(set_user_limits),
        )
        .route(
            "/api/admin/users/{id}/project",
            axum::routing::put(set_user_project),
        )
        .route("/api/admin/projects", axum::routing::post(create_project))
        .route(
            "/api/admin/projects/{id}/limits",
            axum::routing::put(set_project_limits),
        )
        .route(
            "/api/admin/projects/{id}/team",
            axum::routing::put(set_project_team),
        )
        .route("/api/admin/orgs", axum::routing::post(create_org))
        .route(
            "/api/admin/orgs/{id}/limits",
            axum::routing::put(set_org_limits),
        )
        .route("/api/admin/teams", axum::routing::post(create_team))
        .route(
            "/api/admin/teams/{id}/limits",
            axum::routing::put(set_team_limits),
        );
    if let Some(dir) = &state.web_dir {
        app = app.fallback_service(tower_http::services::ServeDir::new(dir));
    }
    app.with_state(state)
}

/// Auth: admin key OR valid session JWT.
async fn admin_auth(state: &PortalState, headers: &axum::http::HeaderMap) -> bool {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let token = auth.strip_prefix("Bearer ").unwrap_or("");
        if state.admin_key.is_empty() || token == state.admin_key {
            return true;
        }
        if let Some(jwt) = &state.jwt {
            if jwt.verify(token).is_ok() {
                return true;
            }
        }
    }
    false
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn user_id_from(headers: &axum::http::HeaderMap, q: &axum::http::Uri) -> Result<i64, Response> {
    let raw = q.query().and_then(|s| {
        s.split('&')
            .find(|kv| kv.starts_with("user_id="))
            .map(|kv| kv[8..].to_string())
    });
    let raw = raw.or_else(|| {
        headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });
    raw.and_then(|s| s.parse::<i64>().ok()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "user_id required"})),
        )
            .into_response()
    })
}

async fn oidc_login(State(st): State<Arc<PortalState>>) -> Response {
    let Some(oidc) = &st.oidc else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "oidc disabled"})),
        )
            .into_response();
    };
    let state_str = format!("{:x}", rand::random::<u64>());
    let url = oidc.auth_url(state_str);
    axum::response::Redirect::temporary(&url).into_response()
}

async fn oidc_callback(
    State(st): State<Arc<PortalState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(oidc) = &st.oidc else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "oidc disabled"})),
        )
            .into_response();
    };
    let code = match params.get("code") {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing code"})),
            )
                .into_response();
        }
    };
    match oidc.exchange(&code).await {
        Ok((subject, email)) => {
            // auto-register / resolve local account (idempotent by email)
            let uid = match st.auth.login(&email, "").await {
                Ok(id) => id,
                Err(_) => match st.auth.register(&email, "oidc-auto-password").await {
                    Ok(id) => id,
                    Err(_) => st.auth.login(&email, "").await.unwrap_or(0),
                },
            };
            let mut resp = json!({"user_id": uid, "oidc_subject": subject});
            if let Some(jwt) = &st.jwt {
                if let Ok(token) = jwt.sign(uid, &email) {
                    resp["token"] = json!(token);
                }
            }
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            tracing::warn!("oidc callback failed: {e:?}");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": format!("oidc failed: {e}")})),
            )
                .into_response()
        }
    }
}

/// GET /api/balance — authenticated user's Redis balance (JWT context).
async fn balance(State(st): State<Arc<PortalState>>, headers: axum::http::HeaderMap) -> Response {
    let Some(jwt) = &st.jwt else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "jwt disabled"})),
        )
            .into_response();
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    match jwt.verify(token) {
        Ok(claims) => {
            let redis_addr = std::env::var("STARGATE_REDIS_ADDR").unwrap_or_default();
            match redis::Client::open(format!("redis://{redis_addr}"))
                .and_then(|c| c.get_connection())
            {
                Ok(mut conn) => {
                    let bal: i64 = redis::cmd("GET")
                        .arg(format!("balance:user-{}", claims.uid))
                        .query(&mut conn)
                        .unwrap_or(0);
                    (
                        StatusCode::OK,
                        Json(json!({"user_id": claims.uid, "balance_micros": bal})),
                    )
                        .into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("redis: {e}")})),
                )
                    .into_response(),
            }
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CredReq {
    username: String,
    password: String,
}

/// Admin-only: update a user's aggregate quota (layer 2 of the
/// six-layer budget model). The admin key is required — session JWTs
/// are NOT accepted for platform policy changes.
async fn set_user_limits(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
    Json(req): Json<SetLimitsReq>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    match st
        .auth
        .set_user_limits(user_id, req.rpm_limit, req.tpm_limit)
        .await
    {
        Ok(()) => Json(serde_json::json!({
            "user_id": user_id,
            "rpm_limit": req.rpm_limit,
            "tpm_limit": req.tpm_limit,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("update failed: {e}")}})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct SetLimitsReq {
    rpm_limit: u64,
    tpm_limit: u64,
}

/// Attach a project to a team (layer 4).
async fn set_project_team(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(project_id): axum::extract::Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    let team_id = req.get("team_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if team_id <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"message": "team_id required"}})),
        )
            .into_response();
    }
    match st.auth.set_project_team(project_id, team_id).await {
        Ok(()) => {
            Json(serde_json::json!({"project_id": project_id, "team_id": team_id})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("update failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Create an org with an aggregate quota (layer 5).
async fn create_org(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let rpm = req.get("rpm_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    let tpm = req.get("tpm_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"message": "name required"}})),
        )
            .into_response();
    }
    match st.auth.create_org(&name, rpm, tpm).await {
        Ok(id) => {
            Json(serde_json::json!({"id": id, "name": name, "rpm_limit": rpm, "tpm_limit": tpm}))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("create failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Update an org's aggregate quota.
async fn set_org_limits(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(org_id): axum::extract::Path<i64>,
    Json(req): Json<SetLimitsReq>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    match st
        .auth
        .set_org_limits(org_id, req.rpm_limit, req.tpm_limit)
        .await
    {
        Ok(()) => Json(serde_json::json!({
            "org_id": org_id,
            "rpm_limit": req.rpm_limit,
            "tpm_limit": req.tpm_limit,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("update failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Create a team inside an org (layer 4).
async fn create_team(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let org_id = req.get("org_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let rpm = req.get("rpm_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    let tpm = req.get("tpm_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    if name.is_empty() || org_id <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"message": "name and org_id required"}})),
        )
            .into_response();
    }
    match st.auth.create_team(&name, org_id, rpm, tpm).await {
        Ok(id) => Json(serde_json::json!({"id": id, "name": name, "org_id": org_id, "rpm_limit": rpm, "tpm_limit": tpm})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("create failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Update a team's aggregate quota.
async fn set_team_limits(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(team_id): axum::extract::Path<i64>,
    Json(req): Json<SetLimitsReq>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    match st
        .auth
        .set_team_limits(team_id, req.rpm_limit, req.tpm_limit)
        .await
    {
        Ok(()) => Json(serde_json::json!({
            "team_id": team_id,
            "rpm_limit": req.rpm_limit,
            "tpm_limit": req.tpm_limit,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("update failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Platform policy endpoints require the admin key — session JWTs are
/// NOT accepted (a stolen session must not change quotas).
fn admin_key_only(state: &PortalState, headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|auth| auth.strip_prefix("Bearer ").unwrap_or("") == state.admin_key)
        .unwrap_or(false)
}

/// Assign a user to a project (shares its budget).
async fn set_user_project(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    let project_id = req.get("project_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if project_id <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"message": "project_id required"}})),
        )
            .into_response();
    }
    match st.auth.set_user_project(user_id, project_id).await {
        Ok(()) => {
            Json(serde_json::json!({"user_id": user_id, "project_id": project_id})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("update failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Create a project with an aggregate quota.
async fn create_project(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let rpm = req.get("rpm_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    let tpm = req.get("tpm_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"message": "name required"}})),
        )
            .into_response();
    }
    match st.auth.create_project(&name, rpm, tpm).await {
        Ok(id) => {
            Json(serde_json::json!({"id": id, "name": name, "rpm_limit": rpm, "tpm_limit": tpm}))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("create failed: {e}")}})),
        )
            .into_response(),
    }
}

/// Update a project's aggregate quota.
async fn set_project_limits(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(project_id): axum::extract::Path<i64>,
    Json(req): Json<SetLimitsReq>,
) -> Response {
    if !admin_key_only(&st, &headers) {
        return unauthorized();
    }
    match st
        .auth
        .set_project_limits(project_id, req.rpm_limit, req.tpm_limit)
        .await
    {
        Ok(()) => Json(serde_json::json!({
            "project_id": project_id,
            "rpm_limit": req.rpm_limit,
            "tpm_limit": req.tpm_limit,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": {"message": format!("update failed: {e}")}})),
        )
            .into_response(),
    }
}

async fn register(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CredReq>,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    match st.auth.register(&req.username, &req.password).await {
        Ok(id) => (
            StatusCode::OK,
            Json(json!({"user_id": id, "username": req.username})),
        )
            .into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"error": e}))).into_response(),
    }
}

async fn login(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CredReq>,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    match st.auth.login(&req.username, &req.password).await {
        Ok(id) => {
            let mut resp = json!({"user_id": id});
            if let Some(jwt) = &st.jwt {
                if let Ok(token) = jwt.sign(id, &req.username) {
                    resp["token"] = json!(token);
                    resp["token_type"] = json!("Bearer");
                }
            } else {
                resp["token"] = json!(format!("dev-{}", id));
            }
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::UNAUTHORIZED, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct KeyReq {
    name: Option<String>,
    rpm_limit: Option<u64>,
    tpm_limit: Option<u64>,
    concurrency_limit: Option<u64>,
    end_user_rpm_limit: Option<u64>,
    end_user_tpm_limit: Option<u64>,
}

async fn create_key(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    Json(req): Json<KeyReq>,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    let uid = match user_id_from(&headers, &uri) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let limits = crate::ratelimit::Limits {
        rpm: req.rpm_limit.unwrap_or(0),
        tpm: req.tpm_limit.unwrap_or(0),
        concurrency: req.concurrency_limit.unwrap_or(0),
        end_user_rpm: req.end_user_rpm_limit.unwrap_or(0),
        end_user_tpm: req.end_user_tpm_limit.unwrap_or(0),
    };
    match st
        .auth
        .create_key(uid, req.name.as_deref().unwrap_or(""), limits)
        .await
    {
        Ok(key) => (
            StatusCode::OK,
            Json(json!({"key": key, "note": "shown once"})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn list_keys(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    let uid = match user_id_from(&headers, &uri) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match st.auth.list_keys(uid).await {
        Ok(keys) => (StatusCode::OK, Json(json!({"keys": keys}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct RechargeReq {
    amount_micros: i64,
    #[serde(default)]
    idempotency_key: String,
}

async fn recharge(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    Json(req): Json<RechargeReq>,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    let uid = match user_id_from(&headers, &uri) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match st
        .pay
        .recharge(uid, req.amount_micros, &req.idempotency_key)
        .await
    {
        Ok(id) => (
            StatusCode::OK,
            Json(json!({"recharge_id": id, "status": "PENDING"})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct PayReq {
    recharge_id: i64,
    #[serde(default)]
    channel: String,
}

async fn pay(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PayReq>,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    let channel = if req.channel.is_empty() {
        "mock"
    } else {
        &req.channel
    };
    match st.pay.pay(req.recharge_id, channel).await {
        Ok(txn) => (
            StatusCode::OK,
            Json(json!({"txn_id": txn, "status": "PAID"})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn recharge_status(
    State(st): State<Arc<PortalState>>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    if !admin_auth(&st, &headers).await {
        return unauthorized();
    }
    let rid = uri
        .query()
        .and_then(|s| {
            s.split('&')
                .find(|kv| kv.starts_with("recharge_id="))
                .map(|kv| kv[12..].to_string())
        })
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if rid <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "recharge_id required"})),
        )
            .into_response();
    }
    match st.pay.recharge_status(rid).await {
        Ok(status) => (
            StatusCode::OK,
            Json(json!({"recharge_id": rid, "status": status})),
        )
            .into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}
