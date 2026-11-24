use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
};
use rand::RngCore;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const INDEX_HTML: &str = include_str!("../static/index.html");
const COOKIE: &str = "sl_session";

const SESSION_TTL_SECS: i64 = 31_536_000;
const MAX_FAILURES: usize = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

struct Inner {
    db: Mutex<Connection>,
    household_code: String,
    secure_cookie: bool,
    /// Timestamps of recent failed logins (global limiter).
    failures: Mutex<Vec<Instant>>,
}
type App = Arc<Inner>;

/// Lock the DB, recovering from a poisoned mutex instead of cascading panics.
fn db(app: &App) -> MutexGuard<'_, Connection> {
    app.db.lock().unwrap_or_else(|e| e.into_inner())
}

fn internal<E: std::fmt::Display>(e: E) -> StatusCode {
    eprintln!("db error: {e}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn init_db(path: &str) -> Connection {
    let db = Connection::open(path).expect("open db");
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, name TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()));
         CREATE TABLE IF NOT EXISTS items(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            done INTEGER NOT NULL DEFAULT 0, added_by TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()));",
    )
    .expect("migrate");
    db
}

/// Authenticated user, resolved from the session cookie.
struct User(String);

impl FromRequestParts<App> for User {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, app: &App) -> Result<Self, StatusCode> {
        let token = cookie(&parts.headers, COOKIE).ok_or(StatusCode::UNAUTHORIZED)?;
        db(app)
            .query_row(
                "SELECT name FROM sessions WHERE token=?1 AND created_at > unixepoch() - ?2",
                params![token, SESSION_TTL_SECS],
                |r| r.get(0),
            )
            .map(User)
            .map_err(|_| StatusCode::UNAUTHORIZED)
    }
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
struct Login {
    code: String,
    name: String,
}

fn cookie_attrs(app: &App) -> &'static str {
    if app.secure_cookie { "; Secure" } else { "" }
}

async fn login(State(app): State<App>, Json(l): Json<Login>) -> Response {
    let name = l.name.trim();
    if name.is_empty() || name.len() > 40 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    {
        let mut f = app.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.retain(|t| t.elapsed() < FAILURE_WINDOW);
        if f.len() >= MAX_FAILURES {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        if !ct_eq(l.code.trim(), &app.household_code) {
            f.push(Instant::now());
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    {
        let db = db(&app);
        let _ = db.execute("DELETE FROM sessions WHERE created_at <= unixepoch() - ?1", [SESSION_TTL_SECS]);
        if let Err(e) = db.execute("INSERT INTO sessions(token,name) VALUES(?1,?2)", params![token, name]) {
            return internal(e).into_response();
        }
    }
    let c = format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}{}",
        cookie_attrs(&app)
    );
    ([(header::SET_COOKIE, c)], Json(Me { name: name.into() })).into_response()
}

#[derive(Serialize)]
struct Me {
    name: String,
}
async fn me(User(name): User) -> Json<Me> {
    Json(Me { name })
}

#[derive(Serialize)]
struct Item {
    id: i64,
    name: String,
    done: bool,
    added_by: String,
}

async fn list(_: User, State(app): State<App>) -> Result<Json<Vec<Item>>, StatusCode> {
    let db = db(&app);
    let mut st = db
        .prepare("SELECT id,name,done,added_by FROM items ORDER BY done, id DESC")
        .map_err(internal)?;
    let items = st
        .query_map([], |r| {
            Ok(Item { id: r.get(0)?, name: r.get(1)?, done: r.get(2)?, added_by: r.get(3)? })
        })
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    Ok(Json(items))
}

#[derive(Deserialize)]
struct NewItem {
    name: String,
}

async fn add(User(who): User, State(app): State<App>, Json(n): Json<NewItem>) -> StatusCode {
    let name = n.name.trim();
    if name.is_empty() || name.len() > 100 {
        return StatusCode::BAD_REQUEST;
    }
    match db(&app).execute("INSERT INTO items(name,added_by) VALUES(?1,?2)", params![name, who]) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct Toggle {
    done: bool,
}

fn affected(r: rusqlite::Result<usize>) -> StatusCode {
    match r {
        Ok(0) => StatusCode::NOT_FOUND,
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => internal(e),
    }
}

async fn set_done(_: User, State(app): State<App>, Path(id): Path<i64>, Json(t): Json<Toggle>) -> StatusCode {
    affected(db(&app).execute("UPDATE items SET done=?1 WHERE id=?2", params![t.done, id]))
}

async fn remove(_: User, State(app): State<App>, Path(id): Path<i64>) -> StatusCode {
    affected(db(&app).execute("DELETE FROM items WHERE id=?1", [id]))
}

async fn clear_done(_: User, State(app): State<App>) -> StatusCode {
    match db(&app).execute("DELETE FROM items WHERE done=1", []) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => internal(e),
    }
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(t) = cookie(&headers, COOKIE) {
        let _ = db(&app).execute("DELETE FROM sessions WHERE token=?1", [t]);
    }
    (
        [(header::SET_COOKIE, format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", cookie_attrs(&app)))],
        StatusCode::NO_CONTENT,
    )
}

/// Serve the page with `<html lang>` matching the visitor's saved language (default Norwegian).
async fn index(headers: HeaderMap) -> Html<String> {
    let lang = match cookie(&headers, "sl_lang").as_deref() {
        Some("en") => "en",
        _ => "nb",
    };
    Html(INDEX_HTML.replacen("<html lang=\"nb\">", &format!("<html lang=\"{lang}\">"), 1))
}

async fn shutdown_signal() {
    let ctrl_c = async { let _ = tokio::signal::ctrl_c().await; };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => { s.recv().await; }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[tokio::main]
async fn main() {
    let code = std::env::var("HOUSEHOLD_CODE").expect("HOUSEHOLD_CODE must be set");
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "shopping.db".into());
    let addr = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let secure_cookie = std::env::var("COOKIE_SECURE").is_ok_and(|v| v == "1" || v == "true");
    let app: App = Arc::new(Inner {
        db: Mutex::new(init_db(&db_path)),
        household_code: code,
        secure_cookie,
        failures: Mutex::new(Vec::new()),
    });

    let router = Router::new()
        .route("/", get(index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/items", get(list).post(add))
        .route("/api/items/{id}", patch(set_done).delete(remove))
        .route("/api/items/clear-done", post(clear_done))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("listening on {addr}");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}
