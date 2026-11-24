use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
};
use rand::RngCore;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const INDEX_HTML: &str = include_str!("../static/index.html");
const COOKIE: &str = "sl_session";

const SESSION_TTL_SECS: i64 = 31_536_000;
/// Item kinds: groceries are the main list; "other" (gifts, hardware...) is tagged freely.
const KINDS: [&str; 2] = ["grocery", "other"];
/// Max tags on one item, and max length of one tag.
const MAX_TAGS: usize = 5;
const MAX_TAG_LEN: usize = 30;
const THEMES: [&str; 11] = [
    "salvie", "mynte", "oliven", "skog", "maroon", "orken", "gruvbox", "brunost", "fjord", "midnatt", "synthwave",
];
const DEFAULT_THEME: &str = "salvie";
const TRIP_TTL: Duration = Duration::from_secs(30);
/// Aisle ids the UI knows about; "" means unsorted.
const CATEGORIES: [&str; 8] = ["", "produce", "dairy", "pantry", "meat", "frozen", "household", "bakery"];
/// Items bought at least this often on average count as "about every week".
const WEEKLY_MAX_INTERVAL_SECS: i64 = 10 * 86_400;
const MAX_FAILURES: usize = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

struct Inner {
    db: Mutex<Connection>,
    household_code: String,
    secure_cookie: bool,
    /// Timestamps of recent failed logins (global limiter).
    failures: Mutex<Vec<Instant>>,
    /// Who is out shopping right now (name -> last heartbeat).
    trip: Mutex<HashMap<String, Instant>>,
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
            created_at INTEGER NOT NULL DEFAULT (unixepoch()));
         CREATE TABLE IF NOT EXISTS purchases(
            id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
            name_key TEXT NOT NULL, name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '', qty TEXT NOT NULL DEFAULT '',
            bought_at INTEGER NOT NULL DEFAULT (unixepoch()));
         CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS tags(
            name_key TEXT PRIMARY KEY, name TEXT NOT NULL,
            used_at INTEGER NOT NULL DEFAULT (unixepoch()),
            uses INTEGER NOT NULL DEFAULT 1);
         CREATE INDEX IF NOT EXISTS purchases_key ON purchases(name_key);
         CREATE INDEX IF NOT EXISTS purchases_item ON purchases(item_id);",
    )
    .expect("migrate");
    // Additive migrations for databases created before these columns existed.
    for (table, col, ddl) in [
        ("items", "qty", "qty TEXT NOT NULL DEFAULT ''"),
        ("items", "category", "category TEXT NOT NULL DEFAULT ''"),
        ("items", "note", "note TEXT NOT NULL DEFAULT ''"),
        ("items", "kind", "kind TEXT NOT NULL DEFAULT 'grocery'"),
        ("items", "tag", "tag TEXT NOT NULL DEFAULT ''"),
        ("tags", "uses", "uses INTEGER NOT NULL DEFAULT 1"),
        ("purchases", "kind", "kind TEXT NOT NULL DEFAULT 'grocery'"),
        ("purchases", "tags", "tags TEXT NOT NULL DEFAULT ''"),
        ("purchases", "bought_by", "bought_by TEXT NOT NULL DEFAULT ''"),
    ] {
        let has: bool = db
            .query_row(&format!("SELECT count(*) > 0 FROM pragma_table_info('{table}') WHERE name=?1"), [col], |r| r.get(0))
            .expect("inspect schema");
        if !has {
            db.execute(&format!("ALTER TABLE {table} ADD COLUMN {ddl}"), []).expect("migrate column");
        }
    }
    db
}

/// Split a comma-separated tag string: trim each, collapse inner whitespace, drop empties and
/// case-insensitive duplicates (first spelling wins). Also used to read older single-string values.
fn parse_tags(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.split(',')
        .map(|t| t.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|t| !t.is_empty() && seen.insert(key(t)))
        .collect()
}

/// Case-insensitive identity of an item name (so "Egg" and "egg " are the same product).
fn key(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
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
    qty: String,
    category: String,
    note: String,
    kind: String,
    tags: Vec<String>,
}

async fn list(_: User, State(app): State<App>) -> Result<Json<Vec<Item>>, StatusCode> {
    let db = db(&app);
    let mut st = db
        .prepare("SELECT id,name,done,added_by,qty,category,note,kind,tag FROM items ORDER BY done, id DESC")
        .map_err(internal)?;
    let items = st
        .query_map([], |r| {
            Ok(Item {
                id: r.get(0)?,
                name: r.get(1)?,
                done: r.get(2)?,
                added_by: r.get(3)?,
                qty: r.get(4)?,
                category: r.get(5)?,
                note: r.get(6)?,
                kind: r.get(7)?,
                tags: parse_tags(&r.get::<_, String>(8)?),
            })
        })
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    Ok(Json(items))
}

#[derive(Deserialize)]
struct NewItem {
    name: String,
    #[serde(default)]
    qty: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    note: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    tag: String,
}

fn default_kind() -> String {
    "grocery".into()
}

async fn add(User(who): User, State(app): State<App>, Json(n): Json<NewItem>) -> StatusCode {
    let (name, qty, note) = (n.name.trim(), n.qty.trim(), n.note.trim());
    let tags = parse_tags(&n.tag);
    if name.is_empty()
        || name.chars().count() > 100
        || qty.chars().count() > 20
        || note.chars().count() > 200
        || tags.len() > MAX_TAGS
        || tags.iter().any(|t| t.chars().count() > MAX_TAG_LEN)
        || !KINDS.contains(&n.kind.as_str())
        || !CATEGORIES.contains(&n.category.as_str())
    {
        return StatusCode::BAD_REQUEST;
    }
    // Groceries are sorted by aisle, everything else by free-form tag (a store, "gifts", ...).
    let (category, tags) = if n.kind == "grocery" { (n.category.as_str(), vec![]) } else { ("", tags) };
    let db = db(&app);
    let k = key(name);
    let dup = db
        .prepare("SELECT name FROM items WHERE done=0 AND kind=?1")
        .and_then(|mut st| st.query_map([&n.kind], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>());
    match dup {
        Ok(names) if names.iter().any(|x| key(x) == k) => return StatusCode::CONFLICT,
        Ok(_) => {}
        Err(e) => return internal(e),
    }
    let res = db
        .execute(
            "INSERT INTO items(name,added_by,qty,category,note,kind,tag) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![name, who, qty, category, note, n.kind, tags.join(",")],
        )
        .and_then(|_| {
            for tag in &tags {
                db.execute(
                    "INSERT INTO tags(name_key,name) VALUES(?1,?2)
                     ON CONFLICT(name_key) DO UPDATE SET name=excluded.name, used_at=unixepoch(), uses=uses+1",
                    params![key(tag), tag],
                )?;
            }
            Ok(())
        });
    match res {
        Ok(_) => StatusCode::CREATED,
        Err(e) => internal(e),
    }
}

/// Tags for non-grocery items, most used first (ties: most recent).
async fn list_tags(_: User, State(app): State<App>) -> Result<Json<Vec<String>>, StatusCode> {
    let db = db(&app);
    let mut st = db.prepare("SELECT name FROM tags ORDER BY uses DESC, used_at DESC, rowid DESC LIMIT 30").map_err(internal)?;
    let tags = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    Ok(Json(tags))
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

/// Checking an item off records a purchase (the history; groceries also feed "often bought"); unchecking undoes it.
async fn set_done(User(who): User, State(app): State<App>, Path(id): Path<i64>, Json(t): Json<Toggle>) -> StatusCode {
    let db = db(&app);
    let row = db.query_row("SELECT name,category,qty,done,kind,tag FROM items WHERE id=?1", [id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, bool>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?))
    });
    let (name, category, qty, was_done, kind, tag) = match row {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return StatusCode::NOT_FOUND,
        Err(e) => return internal(e),
    };
    let res = (|| -> rusqlite::Result<()> {
        db.execute("UPDATE items SET done=?1 WHERE id=?2", params![t.done, id])?;
        if t.done && !was_done {
            db.execute(
                "INSERT INTO purchases(item_id,name_key,name,category,qty,kind,tags,bought_by) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![id, key(&name), name, category, qty, kind, tag, who],
            )?;
        } else if !t.done && was_done {
            db.execute("DELETE FROM purchases WHERE item_id=?1", [id])?;
        }
        Ok(())
    })();
    match res {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => internal(e),
    }
}

async fn remove(_: User, State(app): State<App>, Path(id): Path<i64>) -> StatusCode {
    affected(db(&app).execute("DELETE FROM items WHERE id=?1", [id]))
}

#[derive(Deserialize)]
struct ClearQuery {
    kind: Option<String>,
}

/// Remove checked-off items, optionally only of one kind (the shopping trip only clears groceries).
async fn clear_done(_: User, State(app): State<App>, Query(q): Query<ClearQuery>) -> StatusCode {
    let res = match q.kind.as_deref() {
        None => db(&app).execute("DELETE FROM items WHERE done=1", []),
        Some(k) if KINDS.contains(&k) => db(&app).execute("DELETE FROM items WHERE done=1 AND kind=?1", [k]),
        Some(_) => return StatusCode::BAD_REQUEST,
    };
    match res {
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

struct Product {
    name: String,
    category: String,
    qty: String,
    count: i64,
    first: i64,
    last: i64,
}

/// One entry per product (by name key), most recently bought first.
fn products(db: &Connection) -> rusqlite::Result<Vec<(String, Product)>> {
    let mut st = db.prepare("SELECT name_key,name,category,qty,bought_at FROM purchases WHERE kind='grocery' ORDER BY bought_at DESC, id DESC")?;
    let mut map: HashMap<String, Product> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let rows = st.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?))
    })?;
    for row in rows {
        let (k, name, category, qty, at) = row?;
        match map.get_mut(&k) {
            Some(p) => {
                p.count += 1;
                p.first = p.first.min(at);
            }
            None => {
                order.push(k.clone());
                map.insert(k, Product { name, category, qty, count: 1, first: at, last: at });
            }
        }
    }
    Ok(order.into_iter().filter_map(|k| map.remove(&k).map(|p| (k, p))).collect())
}

fn on_list(db: &Connection) -> rusqlite::Result<HashSet<String>> {
    let mut st = db.prepare("SELECT name FROM items WHERE done=0")?;
    st.query_map([], |r| r.get::<_, String>(0))?.map(|n| n.map(|n| key(&n))).collect()
}

#[derive(Serialize)]
struct Often {
    name: String,
    category: String,
    qty: String,
    last_bought: i64,
    times: i64,
    /// "weekly" or "sometimes"
    frequency: &'static str,
    on_list: bool,
}

/// Products bought at least twice, grouped by how regularly.
async fn history(_: User, State(app): State<App>) -> Result<Json<Vec<Often>>, StatusCode> {
    let db = db(&app);
    let listed = on_list(&db).map_err(internal)?;
    let out = products(&db)
        .map_err(internal)?
        .into_iter()
        .filter(|(_, p)| p.count >= 2)
        .map(|(k, p)| {
            let avg = (p.last - p.first) / (p.count - 1);
            Often {
                frequency: if avg <= WEEKLY_MAX_INTERVAL_SECS { "weekly" } else { "sometimes" },
                on_list: listed.contains(&k),
                name: p.name,
                category: p.category,
                qty: p.qty,
                last_bought: p.last,
                times: p.count,
            }
        })
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
struct RecentQuery {
    days: Option<i64>,
}

#[derive(Serialize)]
struct Purchase {
    id: i64,
    name: String,
    qty: String,
    kind: String,
    category: String,
    tags: Vec<String>,
    bought_by: String,
    bought_at: i64,
}

/// Everything checked off in the last `days` days (default 30, max 5 years), newest first, both kinds.
async fn recent(_: User, State(app): State<App>, Query(q): Query<RecentQuery>) -> Result<Json<Vec<Purchase>>, StatusCode> {
    let days = q.days.unwrap_or(30).clamp(1, 1825);
    let db = db(&app);
    let mut st = db
        .prepare(
            "SELECT id,name,qty,kind,category,tags,bought_by,bought_at FROM purchases
             WHERE bought_at >= unixepoch() - ?1 * 86400 ORDER BY bought_at DESC, id DESC LIMIT 1000",
        )
        .map_err(internal)?;
    let rows = st
        .query_map([days], |r| {
            Ok(Purchase {
                id: r.get(0)?,
                name: r.get(1)?,
                qty: r.get(2)?,
                kind: r.get(3)?,
                category: r.get(4)?,
                tags: parse_tags(&r.get::<_, String>(5)?),
                bought_by: r.get(6)?,
                bought_at: r.get(7)?,
            })
        })
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct SuggestQuery {
    q: String,
}

#[derive(Serialize)]
struct Suggestion {
    name: String,
    category: String,
}

/// Autocomplete from past purchases, most often bought first.
async fn suggest(_: User, State(app): State<App>, Query(q): Query<SuggestQuery>) -> Result<Json<Vec<Suggestion>>, StatusCode> {
    let q = key(&q.q);
    if q.is_empty() || q.chars().count() > 100 {
        return Ok(Json(vec![]));
    }
    let db = db(&app);
    let mut found: Vec<_> = products(&db)
        .map_err(internal)?
        .into_iter()
        .filter(|(k, _)| k.starts_with(&q) && *k != q)
        .map(|(_, p)| p)
        .collect();
    found.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(Json(found.into_iter().take(5).map(|p| Suggestion { name: p.name, category: p.category }).collect()))
}

/// Heartbeat while someone is shopping; returns the *other* people currently shopping.
async fn trip_ping(User(who): User, State(app): State<App>) -> Json<Vec<String>> {
    let mut m = app.trip.lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|_, t| t.elapsed() < TRIP_TTL);
    m.insert(who.clone(), Instant::now());
    let mut others: Vec<String> = m.keys().filter(|n| **n != who).cloned().collect();
    others.sort();
    Json(others)
}

async fn trip_end(User(who): User, State(app): State<App>) -> StatusCode {
    app.trip.lock().unwrap_or_else(|e| e.into_inner()).remove(&who);
    StatusCode::NO_CONTENT
}

/// The household's colour palette (shared by everyone).
fn theme(db: &Connection) -> String {
    db.query_row("SELECT value FROM settings WHERE key='theme'", [], |r| r.get::<_, String>(0))
        .ok()
        .filter(|t| THEMES.contains(&t.as_str()))
        .unwrap_or_else(|| DEFAULT_THEME.into())
}

#[derive(Serialize, Deserialize)]
struct Settings {
    theme: String,
}

async fn get_settings(_: User, State(app): State<App>) -> Json<Settings> {
    Json(Settings { theme: theme(&db(&app)) })
}

async fn put_settings(_: User, State(app): State<App>, Json(s): Json<Settings>) -> StatusCode {
    if !THEMES.contains(&s.theme.as_str()) {
        return StatusCode::BAD_REQUEST;
    }
    match db(&app).execute(
        "INSERT INTO settings(key,value) VALUES('theme',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [s.theme],
    ) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => internal(e),
    }
}

/// Serve the page with `<html lang>` and `data-theme` already set, so there is no flash of the wrong
/// language or palette. Language comes from the visitor's cookie (default Norwegian), theme from the household.
async fn index(State(app): State<App>, headers: HeaderMap) -> Html<String> {
    let lang = match cookie(&headers, "sl_lang").as_deref() {
        Some("en") => "en",
        _ => "nb",
    };
    let theme = theme(&db(&app));
    Html(INDEX_HTML.replacen(
        "<html lang=\"nb\" data-theme=\"salvie\">",
        &format!("<html lang=\"{lang}\" data-theme=\"{theme}\">"),
        1,
    ))
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
        trip: Mutex::new(HashMap::new()),
    });

    let router = router(app);
    serve(router, &addr).await;
}

fn router(app: App) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/items", get(list).post(add))
        .route("/api/items/{id}", patch(set_done).delete(remove))
        .route("/api/items/clear-done", post(clear_done))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/tags", get(list_tags))
        .route("/api/history", get(history))
        .route("/api/purchases", get(recent))
        .route("/api/suggest", get(suggest))
        .route("/api/trip", post(trip_ping).delete(trip_end))
        .with_state(app)
}

async fn serve(router: Router, addr: &str) {
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("listening on {addr}");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const CODE: &str = "test-code-not-a-secret";

    fn test_app() -> Router {
        router(Arc::new(Inner {
            db: Mutex::new(init_db(":memory:")),
            household_code: CODE.into(),
            secure_cookie: false,
            failures: Mutex::new(Vec::new()),
            trip: Mutex::new(HashMap::new()),
        }))
    }

    async fn call(app: &Router, method: &str, uri: &str, cookie: Option<&str>, body: Option<&str>) -> (StatusCode, Option<String>, String) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        let req = match body {
            Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let set = res.headers().get(header::SET_COOKIE).map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
        let text = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        (status, set, text)
    }

    async fn login_as(app: &Router, name: &str) -> String {
        let (st, set, _) = call(app, "POST", "/api/login", None, Some(&format!(r#"{{"name":"{name}","code":"{CODE}"}}"#))).await;
        assert_eq!(st, StatusCode::OK);
        set.unwrap()
    }

    #[tokio::test]
    async fn requires_login_and_checks_code() {
        let app = test_app();
        assert_eq!(call(&app, "GET", "/api/items", None, None).await.0, StatusCode::UNAUTHORIZED);
        let (st, ..) = call(&app, "POST", "/api/login", None, Some(r#"{"name":"J","code":"nope"}"#)).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn login_is_rate_limited() {
        let app = test_app();
        for _ in 0..MAX_FAILURES {
            call(&app, "POST", "/api/login", None, Some(r#"{"name":"J","code":"nope"}"#)).await;
        }
        let (st, ..) = call(&app, "POST", "/api/login", None, Some(&format!(r#"{{"name":"J","code":"{CODE}"}}"#))).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn item_lifecycle_and_validation() {
        let app = test_app();
        let c = login_as(&app, "Jonas").await;
        let add = |b: &'static str| call(&app, "POST", "/api/items", Some(&c), Some(b));
        assert_eq!(add(r#"{"name":"Havremelk","qty":"2","category":"dairy","note":"Oatly"}"#).await.0, StatusCode::CREATED);
        assert_eq!(add(r#"{"name":"  havremelk "}"#).await.0, StatusCode::CONFLICT);
        assert_eq!(add(r#"{"name":"X","category":"bogus"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(add(r#"{"name":"  "}"#).await.0, StatusCode::BAD_REQUEST);
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
        let items: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(items[0]["category"], "dairy");
        assert_eq!(items[0]["qty"], "2");
        assert_eq!(items[0]["added_by"], "Jonas");
        assert_eq!(call(&app, "PATCH", "/api/items/999", Some(&c), Some(r#"{"done":true}"#)).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn other_items_are_tagged_and_kept_out_of_history() {
        let app = test_app();
        let c = login_as(&app, "J").await;
        let post = |b: &'static str| call(&app, "POST", "/api/items", Some(&c), Some(b));
        assert_eq!(post(r#"{"name":"Lego","kind":"other","tag":"  Gaver  til Ola ","category":"dairy","qty":"1 stk"}"#).await.0, StatusCode::CREATED);
        // Same name is fine as a grocery, a duplicate within "other" is not.
        assert_eq!(post(r#"{"name":"lego","kind":"other"}"#).await.0, StatusCode::CONFLICT);
        assert_eq!(post(r#"{"name":"Lego"}"#).await.0, StatusCode::CREATED);
        assert_eq!(post(r#"{"name":"X","kind":"weapons"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"name":"X","kind":"other","tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#).await.0, StatusCode::BAD_REQUEST);
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
        let items: serde_json::Value = serde_json::from_str(&body).unwrap();
        let other = items.as_array().unwrap().iter().find(|i| i["kind"] == "other").unwrap();
        assert_eq!(other["tags"], serde_json::json!(["Gaver til Ola"]));
        assert_eq!(other["category"], "", "aisle is ignored for non-groceries");
        // Several tags in one field: trimmed, de-duplicated (case-insensitive), empties dropped.
        assert_eq!(post(r#"{"name":"Skruer","kind":"other","tag":" Gaver ,Clahs  Ohlson , gaver,, "}"#).await.0, StatusCode::CREATED);
        assert_eq!(post(r#"{"name":"Y","kind":"other","tag":"a,b,c,d,e,f"}"#).await.0, StatusCode::BAD_REQUEST);
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
        let skruer = serde_json::from_str::<serde_json::Value>(&body).unwrap().as_array().unwrap().iter().find(|i| i["name"] == "Skruer").unwrap().clone();
        assert_eq!(skruer["tags"], serde_json::json!(["Gaver", "Clahs Ohlson"]));
        // Suggestions: most used first ("Gaver" was used twice).
        assert_eq!(post(r#"{"name":"Kort","kind":"other","tag":"Gaver"}"#).await.0, StatusCode::CREATED);
        assert_eq!(call(&app, "GET", "/api/tags", Some(&c), None).await.2, r#"["Gaver","Clahs Ohlson","Gaver til Ola"]"#);
        // Buying it twice never makes it an "often bought" grocery.
        let id = other["id"].as_i64().unwrap();
        for done in ["true", "false", "true"] {
            call(&app, "PATCH", &format!("/api/items/{id}"), Some(&c), Some(&format!(r#"{{"done":{done}}}"#))).await;
        }
        assert_eq!(call(&app, "GET", "/api/history", Some(&c), None).await.2, "[]");
        // Clearing groceries leaves the checked "other" item alone.
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
        let g = serde_json::from_str::<serde_json::Value>(&body).unwrap().as_array().unwrap().iter().find(|i| i["kind"] == "grocery").unwrap()["id"].as_i64().unwrap();
        call(&app, "PATCH", &format!("/api/items/{g}"), Some(&c), Some(r#"{"done":true}"#)).await;
        assert_eq!(call(&app, "POST", "/api/items/clear-done?kind=grocery", Some(&c), None).await.0, StatusCode::NO_CONTENT);
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
        let left: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(left.as_array().unwrap().len(), 3);
        assert!(left.as_array().unwrap().iter().all(|i| i["kind"] == "other"));
        assert_eq!(call(&app, "POST", "/api/items/clear-done?kind=bogus", Some(&c), None).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn history_learns_from_purchases() {
        let app = test_app();
        let c = login_as(&app, "J").await;
        for _ in 0..2 {
            call(&app, "POST", "/api/items", Some(&c), Some(r#"{"name":"Egg","category":"dairy"}"#)).await;
            let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
            let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()[0]["id"].as_i64().unwrap();
            assert_eq!(call(&app, "PATCH", &format!("/api/items/{id}"), Some(&c), Some(r#"{"done":true}"#)).await.0, StatusCode::NO_CONTENT);
            call(&app, "POST", "/api/items/clear-done", Some(&c), None).await;
        }
        // A single purchase is not "often", and un-checking removes it again.
        call(&app, "POST", "/api/items", Some(&c), Some(r#"{"name":"Melk"}"#)).await;
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&c), None).await;
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()[0]["id"].as_i64().unwrap();
        for done in ["true", "false"] {
            call(&app, "PATCH", &format!("/api/items/{id}"), Some(&c), Some(&format!(r#"{{"done":{done}}}"#))).await;
        }
        let (_, _, body) = call(&app, "GET", "/api/history", Some(&c), None).await;
        let h: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(h.as_array().unwrap().len(), 1);
        assert_eq!(h[0]["name"], "Egg");
        assert_eq!(h[0]["times"], 2);
        assert_eq!(h[0]["frequency"], "weekly");
        assert_eq!(h[0]["on_list"], false);
        let (_, _, body) = call(&app, "GET", "/api/suggest?q=eg", Some(&c), None).await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()[0]["name"], "Egg");
    }

    #[tokio::test]
    async fn purchase_history_covers_both_kinds_and_records_who() {
        let app = test_app();
        let j = login_as(&app, "Jonas").await;
        let k = login_as(&app, "Kari").await;
        call(&app, "POST", "/api/items", Some(&j), Some(r#"{"name":"Melk","qty":"1.75 L","category":"dairy"}"#)).await;
        call(&app, "POST", "/api/items", Some(&j), Some(r#"{"name":"Lego","kind":"other","tag":"Gaver, Jollyroom"}"#)).await;
        let (_, _, body) = call(&app, "GET", "/api/items", Some(&j), None).await;
        let items: serde_json::Value = serde_json::from_str(&body).unwrap();
        let id = |n: &str| items.as_array().unwrap().iter().find(|i| i["name"] == n).unwrap()["id"].as_i64().unwrap();
        // Kari checks both off.
        for n in ["Melk", "Lego"] {
            call(&app, "PATCH", &format!("/api/items/{}", id(n)), Some(&k), Some(r#"{"done":true}"#)).await;
        }
        let (_, _, body) = call(&app, "GET", "/api/purchases", Some(&j), None).await;
        let p: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(p.as_array().unwrap().len(), 2);
        let lego = p.as_array().unwrap().iter().find(|x| x["name"] == "Lego").unwrap();
        assert_eq!(lego["kind"], "other");
        assert_eq!(lego["tags"], serde_json::json!(["Gaver", "Jollyroom"]));
        assert_eq!(lego["bought_by"], "Kari");
        let melk = p.as_array().unwrap().iter().find(|x| x["name"] == "Melk").unwrap();
        assert_eq!(melk["qty"], "1.75 L");
        // Unchecking takes it out of the history again; clearing checked items keeps it.
        call(&app, "PATCH", &format!("/api/items/{}", id("Lego")), Some(&k), Some(r#"{"done":false}"#)).await;
        call(&app, "POST", "/api/items/clear-done", Some(&k), None).await;
        let (_, _, body) = call(&app, "GET", "/api/purchases?days=7", Some(&j), None).await;
        let p: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(p.as_array().unwrap().len(), 1);
        assert_eq!(p[0]["name"], "Melk");
        assert_eq!(call(&app, "GET", "/api/purchases", None, None).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn trip_shows_other_shoppers() {
        let app = test_app();
        let a = login_as(&app, "J").await;
        let b = login_as(&app, "K").await;
        assert_eq!(call(&app, "POST", "/api/trip", Some(&a), None).await.2, "[]");
        assert_eq!(call(&app, "POST", "/api/trip", Some(&b), None).await.2, r#"["J"]"#);
        call(&app, "DELETE", "/api/trip", Some(&a), None).await;
        assert_eq!(call(&app, "POST", "/api/trip", Some(&b), None).await.2, "[]");
    }

    #[tokio::test]
    async fn index_lang_follows_cookie() {
        let app = test_app();
        assert!(call(&app, "GET", "/", None, None).await.2.contains(r#"<html lang="nb" data-theme="salvie">"#));
        assert!(call(&app, "GET", "/", Some("sl_lang=en"), None).await.2.contains(r#"<html lang="en" data-theme="salvie">"#));
    }

    #[test]
    fn every_theme_has_css_and_a_label() {
        for t in THEMES {
            assert!(INDEX_HTML.contains(&format!("[data-theme=\"{t}\"]")), "no CSS for theme {t}");
            assert!(INDEX_HTML.contains(&format!("{t}:['")), "no label for theme {t}");
        }
        assert!(INDEX_HTML.contains(&format!("const THEMES = [{}]", THEMES.map(|t| format!("'{t}'")).join(", "))));
    }

    #[tokio::test]
    async fn theme_is_shared_validated_and_served() {
        let app = test_app();
        assert_eq!(call(&app, "GET", "/api/settings", None, None).await.0, StatusCode::UNAUTHORIZED);
        let c = login_as(&app, "J").await;
        assert_eq!(call(&app, "GET", "/api/settings", Some(&c), None).await.2, r#"{"theme":"salvie"}"#);
        assert_eq!(call(&app, "PUT", "/api/settings", Some(&c), Some(r#"{"theme":"hotpink"}"#)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, "PUT", "/api/settings", Some(&c), Some(r#"{"theme":"skog"}"#)).await.0, StatusCode::NO_CONTENT);
        // Another person (and the login page, before signing in) gets the household's palette.
        let k = login_as(&app, "K").await;
        assert_eq!(call(&app, "GET", "/api/settings", Some(&k), None).await.2, r#"{"theme":"skog"}"#);
        assert!(call(&app, "GET", "/", None, None).await.2.contains(r#"data-theme="skog""#));
    }
}
