use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio_postgres::{Client, NoTls, Statement};

const SHARDS: usize = 64;
const BLOOM_WORDS: usize = 1 << 14;
const BLOOM_HASHES: u64 = 6;
const BATCH_MAX: usize = 128;
const MAX_PER_REQUEST: usize = 256;

const CLAIM_SQL: &str = "INSERT INTO nullifiers (nullifier) SELECT * FROM UNNEST($1::bytea[]) \
                         ON CONFLICT DO NOTHING RETURNING nullifier";

struct Shard {
    seen: HashSet<[u8; 32]>,
    bits: Vec<u64>,
}

struct Store {
    shards: Vec<Mutex<Shard>>,
}

#[derive(Default)]
struct Stats {
    claims: AtomicU64,
    accepted: AtomicU64,
    replayed: AtomicU64,
    cache_hits: AtomicU64,
    db_batches: AtomicU64,
}

struct Job {
    nullifier: [u8; 32],
    reply: oneshot::Sender<bool>,
}

#[derive(Clone)]
struct App {
    store: Arc<Store>,
    stats: Arc<Stats>,
    workers: Vec<mpsc::Sender<Job>>,
    token: String,
}

#[derive(Deserialize)]
struct ClaimBody {
    nullifiers: Vec<String>,
}

#[derive(Serialize)]
struct ClaimResult {
    nullifier: String,
    status: &'static str,
}

#[derive(Serialize)]
struct ClaimResponse {
    results: Vec<ClaimResult>,
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

impl Store {
    fn new() -> Store {
        let mut shards = Vec::with_capacity(SHARDS);
        for _ in 0..SHARDS {
            shards.push(Mutex::new(Shard {
                seen: HashSet::new(),
                bits: vec![0u64; BLOOM_WORDS],
            }));
        }
        Store { shards }
    }

    fn shard_of(&self, n: &[u8; 32]) -> usize {
        (n[31] as usize) % SHARDS
    }

    fn bloom_pair(n: &[u8; 32]) -> (u64, u64) {
        let a = mix(u64::from_le_bytes(n[0..8].try_into().unwrap()));
        let b = mix(u64::from_le_bytes(n[8..16].try_into().unwrap())) | 1;
        (a, b)
    }

    fn seen(&self, n: &[u8; 32]) -> bool {
        let (a, b) = Store::bloom_pair(n);
        let shard = self.shards[self.shard_of(n)].lock().unwrap();

        for i in 0..BLOOM_HASHES {
            let bit = (a.wrapping_add(i.wrapping_mul(b)) as usize) % (BLOOM_WORDS * 64);
            if shard.bits[bit / 64] & (1u64 << (bit % 64)) == 0 {
                return false;
            }
        }

        shard.seen.contains(n)
    }

    fn mark(&self, n: &[u8; 32]) {
        let (a, b) = Store::bloom_pair(n);
        let mut shard = self.shards[self.shard_of(n)].lock().unwrap();

        if shard.seen.insert(*n) {
            for i in 0..BLOOM_HASHES {
                let bit = (a.wrapping_add(i.wrapping_mul(b)) as usize) % (BLOOM_WORDS * 64);
                shard.bits[bit / 64] |= 1u64 << (bit % 64);
            }
        }
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().seen.len()).sum()
    }
}

async fn worker(
    mut rx: mpsc::Receiver<Job>,
    client: Client,
    stmt: Statement,
    store: Arc<Store>,
    stats: Arc<Stats>,
) {
    while let Some(first) = rx.recv().await {
        let mut jobs = vec![first];
        while jobs.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(job) => jobs.push(job),
                Err(_) => break,
            }
        }

        let values: Vec<&[u8]> = jobs.iter().map(|j| &j.nullifier[..]).collect();
        stats.db_batches.fetch_add(1, Ordering::Relaxed);

        let rows = match client.query(&stmt, &[&values]).await {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("claim failed: {e}");
                for job in jobs {
                    drop(job.reply);
                }
                continue;
            }
        };

        
        let fresh: HashSet<Vec<u8>> = rows.iter().map(|r| r.get::<_, Vec<u8>>(0)).collect();

        for job in jobs {
            store.mark(&job.nullifier);
            let _ = job.reply.send(fresh.contains(&job.nullifier[..]));
        }
    }
}

fn check_token(app: &App, headers: &HeaderMap) -> bool {
    if app.token.is_empty() {
        return true;
    }

    let given = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    given.len() == app.token.len()
        && given
            .bytes()
            .zip(app.token.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

async fn claim(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<ClaimBody>,
) -> Result<Json<ClaimResponse>, (StatusCode, String)> {
    if !check_token(&app, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "bad token".into()));
    }

    if body.nullifiers.is_empty() || body.nullifiers.len() > MAX_PER_REQUEST {
        return Err((StatusCode::BAD_REQUEST, format!("send 1 to {MAX_PER_REQUEST} nullifiers")));
    }

    let mut parsed = Vec::with_capacity(body.nullifiers.len());
    for text in &body.nullifiers {
        let raw = hex::decode(text).map_err(|_| (StatusCode::BAD_REQUEST, "not hex".to_string()))?;
        let n: [u8; 32] = raw
            .try_into()
            .map_err(|_| (StatusCode::BAD_REQUEST, "a nullifier is 32 bytes".to_string()))?;
        parsed.push(n);
    }

    let mut results = Vec::with_capacity(parsed.len());
    let mut waiting = Vec::new();
    let mut in_request = HashSet::new();

    for (i, n) in parsed.iter().enumerate() {
       
        if !in_request.insert(*n) || app.store.seen(n) {
            app.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            results.push((i, false));
            continue;
        }

        let (reply, wait) = oneshot::channel();
        let worker = app.store.shard_of(n) % app.workers.len();

        if app.workers[worker].send(Job { nullifier: *n, reply }).await.is_err() {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "worker is gone".into()));
        }
        waiting.push((i, wait));
    }

    for (i, wait) in waiting {
        match wait.await {
            Ok(fresh) => results.push((i, fresh)),
            Err(_) => return Err((StatusCode::SERVICE_UNAVAILABLE, "database is unavailable".into())),
        }
    }

    results.sort_by_key(|r| r.0);
    app.stats.claims.fetch_add(results.len() as u64, Ordering::Relaxed);

    let out = results
        .into_iter()
        .map(|(i, fresh)| {
            if fresh {
                app.stats.accepted.fetch_add(1, Ordering::Relaxed);
            } else {
                app.stats.replayed.fetch_add(1, Ordering::Relaxed);
            }
            ClaimResult {
                nullifier: body.nullifiers[i].clone(),
                status: if fresh { "accepted" } else { "replayed" },
            }
        })
        .collect();

    Ok(Json(ClaimResponse { results: out }))
}

async fn get_stats(State(app): State<App>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "claims": app.stats.claims.load(Ordering::Relaxed),
        "accepted": app.stats.accepted.load(Ordering::Relaxed),
        "replayed": app.stats.replayed.load(Ordering::Relaxed),
        "cache_hits": app.stats.cache_hits.load(Ordering::Relaxed),
        "db_batches": app.stats.db_batches.load(Ordering::Relaxed),
        "cached": app.store.len(),
        "shards": SHARDS,
    }))
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

#[tokio::main]
async fn main() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let token = std::env::var("NULLIFIER_TOKEN").unwrap_or_default();
    let bind = std::env::var("BIND").unwrap_or("0.0.0.0:8081".to_string());
    let connections: usize = std::env::var("DB_CONNECTIONS")
        .unwrap_or("16".to_string())
        .parse()
        .expect("DB_CONNECTIONS must be a number");

    let store = Arc::new(Store::new());
    let stats = Arc::new(Stats::default());
    let mut workers = Vec::new();

    for _ in 0..connections {
        let (client, connection) = tokio_postgres::connect(&db, NoTls)
            .await
            .expect("could not connect to postgres");

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("postgres connection lost: {e}");
            }
        });

        let stmt = client.prepare(CLAIM_SQL).await.expect("could not prepare claim");

        let (tx, rx) = mpsc::channel(BATCH_MAX * 8);
        workers.push(tx);
        tokio::spawn(worker(rx, client, stmt, store.clone(), stats.clone()));
    }

    let app = App { store, stats, workers, token };

    let router = Router::new()
        .route("/claim", post(claim))
        .route("/stats", get(get_stats))
        .route("/healthz", get(healthz))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&bind).await.expect("could not bind");
    println!("nullifier listening on {bind} with {connections} connections");

    axum::serve(listener, router).await.expect("server failed");
}
