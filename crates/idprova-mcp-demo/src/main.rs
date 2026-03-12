//! # IDProva MCP Demo Server
//!
//! A standalone MCP (Model Context Protocol) server secured by IDProva DAT
//! (Delegation Attestation Token) bearer authentication. Every tool call is
//! BLAKE3-chained into an append-only receipt log for tamper-evident auditing.
//!
//! ## Architecture
//!
//! ```text
//!   AI Agent ──Bearer DAT──▶ MCP Server ──verify──▶ IDProva Registry
//!                               │
//!                               ▼
//!                         receipts.jsonl  (BLAKE3-chained)
//! ```
//!
//! ## Endpoints
//!
//! | Method | Path       | Description                                      |
//! |--------|------------|--------------------------------------------------|
//! | POST   | `/`        | JSON-RPC 2.0 tool calls (requires `Authorization: Bearer <DAT>`) |
//! | GET    | `/receipts`| Last 100 receipt entries                         |
//! | GET    | `/health`  | Health check                                     |
//!
//! ## Scope Grammar
//!
//! Tool scopes follow the IDProva 4-part format: `mcp:tool:<name>:call`
//!
//! ## Quick Start
//!
//! ```bash
//! # 1. Start the IDProva registry (port 3000)
//! REGISTRY_PORT=3000 idprova-registry
//!
//! # 2. Start this MCP server (port 3001)
//! REGISTRY_URL=http://localhost:3000 MCP_PORT=3001 idprova-mcp-demo
//!
//! # 3. Issue a DAT with tool scopes
//! idprova dat issue --subject did:idprova:demo:agent \
//!   --scope "mcp:tool:echo:call,mcp:tool:calculate:call" --expires-in 1h
//!
//! # 4. Call a tool
//! curl -X POST http://localhost:3001/ \
//!   -H "Authorization: Bearer <DAT>" \
//!   -H "Content-Type: application/json" \
//!   -d '{"jsonrpc":"2.0","id":1,"method":"echo","params":{"message":"hello"}}'
//! ```

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tracing_subscriber::EnvFilter;
use ulid::Ulid;

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct McpRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct McpResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpError>,
}

#[derive(Debug, Serialize)]
struct McpError {
    code: i32,
    message: String,
}

impl McpResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }
    fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(McpError {
                code,
                message: message.into(),
            }),
        }
    }
}

// ── BLAKE3 receipt chain ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiptEntry {
    pub id: String,
    pub timestamp: String,
    pub tool: String,
    pub subject_did: String,
    pub scope: String,
    pub request_hash: String,
    pub prev_receipt_hash: String,
}

fn blake3_hex(data: &str) -> String {
    let hash = blake3::hash(data.as_bytes());
    hash.to_hex().to_string()
}

pub struct ReceiptLog {
    path: PathBuf,
}

impl ReceiptLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns BLAKE3 hash of the last line, or "genesis" if log is empty.
    pub fn last_hash(&self) -> String {
        if !self.path.exists() {
            return "genesis".to_string();
        }
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return "genesis".to_string(),
        };
        let reader = BufReader::new(file);
        let mut last_line = String::new();
        for line in reader.lines().map_while(Result::ok) {
            if !line.trim().is_empty() {
                last_line = line;
            }
        }
        if last_line.is_empty() {
            "genesis".to_string()
        } else {
            blake3_hex(&last_line)
        }
    }

    pub fn append(&self, entry: &ReceiptEntry) -> Result<()> {
        let json = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{json}")?;
        Ok(())
    }

    pub fn last_n(&self, n: usize) -> Vec<ReceiptEntry> {
        if !self.path.exists() {
            return vec![];
        }
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return vec![],
        };
        let all: Vec<ReceiptEntry> = BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(&l).ok())
            .collect();
        let skip = all.len().saturating_sub(n);
        all.into_iter().skip(skip).collect()
    }
}

// ── Registry DAT verification ─────────────────────────────────────────────────

#[derive(Serialize)]
struct DatVerifyReq<'a> {
    token: &'a str,
    scope: &'a str,
}

#[derive(Deserialize)]
struct DatVerifyResp {
    valid: bool,
    subject: Option<String>,
    scopes: Option<Vec<String>>,
    error: Option<String>,
}

async fn verify_with_registry(
    registry_url: &str,
    token: &str,
    scope: &str,
) -> Result<DatVerifyResp, (StatusCode, String)> {
    let url = format!("{}/v1/dat/verify", registry_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = client
        .post(&url)
        .json(&DatVerifyReq { token, scope })
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("registry unreachable: {e}"),
            )
        })?;

    resp.json::<DatVerifyResp>().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("bad registry response: {e}"),
        )
    })
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    registry_url: String,
    receipts: Arc<Mutex<ReceiptLog>>,
    public_dir: PathBuf,
}

// ── Tool catalogue (for tools/list discovery) ────────────────────────────────

/// Returns the MCP tool catalogue so clients can discover available tools
/// without prior knowledge. Called via JSON-RPC method `tools/list`.
fn tool_catalogue() -> Value {
    json!({
        "tools": [
            {
                "name": "echo",
                "description": "Echoes a message with IDProva DAT verification stamp",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": { "type": "string", "description": "Message to echo" }
                    },
                    "required": ["message"]
                }
            },
            {
                "name": "calculate",
                "description": "Evaluates a math expression (max 200 chars). Supported: +, -, *, /, parentheses.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expression": { "type": "string", "description": "Math expression to evaluate, e.g. '2+2*10'" }
                    },
                    "required": ["expression"]
                }
            },
            {
                "name": "read_file",
                "description": "Reads a file from the server's public/ directory (max 100 KB). Path traversal is rejected.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": { "type": "string", "description": "Filename relative to public/, e.g. 'readme.txt'" }
                    },
                    "required": ["filename"]
                }
            }
        ]
    })
}

// ── Tool handlers ─────────────────────────────────────────────────────────────

/// Echo tool: returns the input message with an IDProva verification stamp.
///
/// # Example (JSON-RPC request)
/// ```json
/// {"jsonrpc":"2.0","id":1,"method":"echo","params":{"message":"hello"}}
/// ```
pub fn handle_echo(params: &Value) -> Result<Value, String> {
    let msg = params
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "echo requires params.message (string)".to_string())?;

    Ok(json!({
        "content": [{ "type": "text", "text": format!("echo: {} — Verified by IDProva DAT", msg) }]
    }))
}

/// Calculate tool: evaluates a safe math expression and returns the result.
///
/// # Example (JSON-RPC request)
/// ```json
/// {"jsonrpc":"2.0","id":1,"method":"calculate","params":{"expression":"2+2*10"}}
/// ```
pub fn handle_calculate(params: &Value) -> Result<Value, String> {
    let expr = params
        .get("expression")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "calculate requires params.expression (string)".to_string())?;

    if expr.len() > 200 {
        return Err(format!(
            "expression too long: {} chars (max 200)",
            expr.len()
        ));
    }

    let result = evalexpr::eval(expr).map_err(|e| format!("evaluation error: {e}"))?;

    Ok(json!({
        "content": [{ "type": "text", "text": format!("{} = {}", expr, result) }]
    }))
}

/// Read file tool: serves files from the public/ directory with path-traversal protection.
///
/// # Security
/// - Rejects `..`, backslashes, and absolute paths
/// - Canonicalizes paths to catch symlink escapes
/// - Enforces a 100 KB size limit
///
/// # Example (JSON-RPC request)
/// ```json
/// {"jsonrpc":"2.0","id":1,"method":"read_file","params":{"filename":"readme.txt"}}
/// ```
pub fn handle_read_public_file(
    params: &Value,
    public_dir: &std::path::Path,
) -> Result<Value, String> {
    let filename = params
        .get("filename")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "read_public_file requires params.filename (string)".to_string())?;

    // Security: reject path traversal, absolute paths, backslashes
    if filename.contains("..") {
        return Err("path traversal not allowed".to_string());
    }
    if filename.contains('\\') {
        return Err("backslashes not allowed in filename".to_string());
    }
    if filename.starts_with('/') {
        return Err("absolute paths not allowed".to_string());
    }

    let target = public_dir.join(filename);

    // Canonicalize to detect any remaining traversal or symlinks
    let canonical =
        std::fs::canonicalize(&target).map_err(|_| format!("file not found: {filename}"))?;

    let canonical_public = std::fs::canonicalize(public_dir)
        .map_err(|_| "public directory not accessible".to_string())?;

    if !canonical.starts_with(&canonical_public) {
        return Err("access denied: file outside public directory".to_string());
    }

    let metadata =
        std::fs::metadata(&canonical).map_err(|_| format!("file not found: {filename}"))?;

    const MAX_SIZE: u64 = 100 * 1024; // 100 KB
    if metadata.len() > MAX_SIZE {
        return Err(format!(
            "file too large: {} bytes (max 100KB)",
            metadata.len()
        ));
    }

    let content =
        std::fs::read_to_string(&canonical).map_err(|e| format!("error reading file: {e}"))?;

    Ok(json!({
        "content": [{ "type": "text", "text": content }]
    }))
}

// ── JSON-RPC handler ──────────────────────────────────────────────────────────

async fn handle_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<McpRequest>,
) -> Response {
    let id = req.id.clone();

    // Validate JSON-RPC version
    if req.jsonrpc != "2.0" {
        return (
            StatusCode::BAD_REQUEST,
            Json(McpResponse::err(
                id,
                -32600,
                "Invalid Request: jsonrpc must be '2.0'",
            )),
        )
            .into_response();
    }

    // tools/list is unauthenticated — clients need to discover tools before auth
    if req.method == "tools/list" {
        return Json(McpResponse::ok(id, tool_catalogue())).into_response();
    }

    // Extract Bearer token
    let token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(McpResponse::err(
                    id,
                    -32001,
                    "Authorization: Bearer <DAT> required",
                )),
            )
                .into_response();
        }
    };

    // Determine required scope from method name (4-part grammar: mcp:tool:<name>:call)
    let scope = format!("mcp:tool:{}:call", req.method);

    // Verify DAT via registry
    let verified = match verify_with_registry(&state.registry_url, &token, &scope).await {
        Err((status, msg)) => {
            return (status, Json(McpResponse::err(id, -32002, msg))).into_response();
        }
        Ok(r) => r,
    };

    if !verified.valid {
        let msg = verified
            .error
            .unwrap_or_else(|| "token invalid".to_string());
        // Scope failures → 403, everything else → 401
        let status = if msg.to_lowercase().contains("scope") {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::UNAUTHORIZED
        };
        return (status, Json(McpResponse::err(id, -32003, msg))).into_response();
    }

    let subject_did = verified.subject.unwrap_or_else(|| "unknown".to_string());
    let scopes_granted = verified.scopes.unwrap_or_default();

    // Dispatch to tool
    let result_value = match req.method.as_str() {
        "echo" => match handle_echo(&req.params) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(McpResponse::err(id, -32602, e)),
                )
                    .into_response();
            }
        },
        "calculate" => match handle_calculate(&req.params) {
            Ok(v) => v,
            Err(e) => {
                // Tool errors (bad expression etc.) are JSON-RPC errors, not HTTP errors
                return Json(McpResponse::err(id, -32602, e)).into_response();
            }
        },
        "read_file" => match handle_read_public_file(&req.params, &state.public_dir) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(McpResponse::err(id, -32602, e)),
                )
                    .into_response();
            }
        },
        method => {
            return (
                StatusCode::NOT_FOUND,
                Json(McpResponse::err(
                    id,
                    -32601,
                    format!("Method not found: {method}"),
                )),
            )
                .into_response();
        }
    };

    // Write receipt with BLAKE3 chain
    let request_bytes = serde_json::to_vec(&req.params).unwrap_or_default();
    let request_hash = blake3::hash(&request_bytes).to_hex().to_string();

    let prev_hash = state.receipts.lock().unwrap().last_hash();

    let entry = ReceiptEntry {
        id: Ulid::new().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        tool: req.method.clone(),
        subject_did: subject_did.clone(),
        scope: scopes_granted.join(","),
        request_hash,
        prev_receipt_hash: prev_hash,
    };

    if let Err(e) = state.receipts.lock().unwrap().append(&entry) {
        tracing::warn!("Failed to write receipt: {e}");
    }

    tracing::info!(tool = %req.method, subject = %subject_did, receipt = %entry.id, "tool call verified");

    Json(McpResponse::ok(id, result_value)).into_response()
}

async fn list_receipts(State(state): State<AppState>) -> Json<Value> {
    let entries = state.receipts.lock().unwrap().last_n(100);
    let count = entries.len();
    Json(json!({ "total": count, "receipts": entries }))
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "idprova-mcp-demo",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let port = std::env::var("MCP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3001);

    let registry_url =
        std::env::var("REGISTRY_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let receipts_path = std::env::var("RECEIPTS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("receipts.jsonl"));

    let public_dir = std::env::var("PUBLIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("public"));

    tracing::info!("IDProva MCP Demo v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Registry: {registry_url}");
    tracing::info!("Receipts: {}", receipts_path.display());
    tracing::info!("Public dir: {}", public_dir.display());

    let state = AppState {
        registry_url,
        receipts: Arc::new(Mutex::new(ReceiptLog::new(receipts_path))),
        public_dir,
    };

    let app = Router::new()
        .route("/", post(handle_rpc))
        .route("/receipts", get(list_receipts))
        .route("/health", get(health))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    // ── ReceiptLog tests ──────────────────────────────────────────────────────

    #[test]
    fn test_receipt_chain_genesis() {
        let tmp = NamedTempFile::new().unwrap();
        let log = ReceiptLog::new(tmp.path().to_path_buf());
        assert_eq!(log.last_hash(), "genesis");
    }

    #[test]
    fn test_receipt_chain_integrity() {
        let tmp = NamedTempFile::new().unwrap();
        let log = ReceiptLog::new(tmp.path().to_path_buf());

        let e1 = ReceiptEntry {
            id: "01".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            tool: "echo".into(),
            subject_did: "did:idprova:test:agent".into(),
            scope: "mcp:tool:echo:call".into(),
            request_hash: "abc".into(),
            prev_receipt_hash: "genesis".into(),
        };
        log.append(&e1).unwrap();

        let e1_json = serde_json::to_string(&e1).unwrap();
        let expected = blake3_hex(&e1_json);
        assert_eq!(log.last_hash(), expected);

        let e2 = ReceiptEntry {
            id: "02".into(),
            timestamp: "2026-01-01T00:00:01Z".into(),
            tool: "echo".into(),
            subject_did: "did:idprova:test:agent".into(),
            scope: "mcp:tool:echo:call".into(),
            request_hash: "def".into(),
            prev_receipt_hash: expected.clone(),
        };
        log.append(&e2).unwrap();
        let e2_json = serde_json::to_string(&e2).unwrap();
        assert_eq!(log.last_hash(), blake3_hex(&e2_json));
    }

    #[test]
    fn test_receipt_last_n() {
        let tmp = NamedTempFile::new().unwrap();
        let log = ReceiptLog::new(tmp.path().to_path_buf());
        for i in 0..5u8 {
            log.append(&ReceiptEntry {
                id: i.to_string(),
                timestamp: "t".into(),
                tool: "echo".into(),
                subject_did: "did:test".into(),
                scope: "mcp:tool:echo:call".into(),
                request_hash: "h".into(),
                prev_receipt_hash: "genesis".into(),
            })
            .unwrap();
        }
        assert_eq!(log.last_n(3).len(), 3);
        assert_eq!(log.last_n(100).len(), 5);
    }

    // ── Echo tool tests ───────────────────────────────────────────────────────

    #[test]
    fn test_echo_tool_success() {
        let params = json!({ "message": "hello world" });
        let result = handle_echo(&params).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("echo: hello world"));
        assert!(text.contains("Verified by IDProva DAT"));
    }

    #[test]
    fn test_echo_missing_message() {
        assert!(handle_echo(&json!({})).is_err());
    }

    // ── Calculate tool tests ──────────────────────────────────────────────────

    #[test]
    fn test_calculate_basic_arithmetic() {
        let result = handle_calculate(&json!({ "expression": "2+2*3" })).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("= 8"), "expected '= 8', got: {text}");
    }

    #[test]
    fn test_calculate_division_by_zero() {
        let err = handle_calculate(&json!({ "expression": "1/0" })).unwrap_err();
        assert!(
            err.contains("evaluation error") || err.contains("division") || err.contains("zero"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_calculate_expression_too_long() {
        let long_expr = "1+".repeat(101); // 202 chars
        let err = handle_calculate(&json!({ "expression": long_expr })).unwrap_err();
        assert!(err.contains("too long"), "unexpected error: {err}");
    }

    #[test]
    fn test_calculate_missing_expression() {
        assert!(handle_calculate(&json!({})).is_err());
    }

    #[test]
    fn test_calculate_complex_expression() {
        let result = handle_calculate(&json!({ "expression": "(10 + 5) * 2 - 3" })).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("= 27"), "expected '= 27', got: {text}");
    }

    // ── read_public_file tool tests ───────────────────────────────────────────

    #[test]
    fn test_read_file_path_traversal_dotdot() {
        let tmp = TempDir::new().unwrap();
        let err = handle_read_public_file(&json!({ "filename": "../etc/passwd" }), tmp.path())
            .unwrap_err();
        assert!(err.contains("path traversal"), "unexpected error: {err}");
    }

    #[test]
    fn test_read_file_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let err =
            handle_read_public_file(&json!({ "filename": "/etc/passwd" }), tmp.path()).unwrap_err();
        assert!(err.contains("absolute paths"), "unexpected error: {err}");
    }

    #[test]
    fn test_read_file_backslash_rejected() {
        let tmp = TempDir::new().unwrap();
        let err = handle_read_public_file(&json!({ "filename": "..\\etc\\passwd" }), tmp.path())
            .unwrap_err();
        assert!(
            err.contains("backslash") || err.contains("path traversal"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_read_file_success() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("readme.txt");
        std::fs::write(&file_path, "Hello from IDProva public file!").unwrap();

        let result =
            handle_read_public_file(&json!({ "filename": "readme.txt" }), tmp.path()).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "Hello from IDProva public file!");
    }

    #[test]
    fn test_read_file_not_found() {
        let tmp = TempDir::new().unwrap();
        let err = handle_read_public_file(&json!({ "filename": "nonexistent.txt" }), tmp.path())
            .unwrap_err();
        assert!(
            err.contains("not found") || err.contains("nonexistent"),
            "unexpected error: {err}"
        );
    }

    // ── Scope format test ─────────────────────────────────────────────────────

    #[test]
    fn test_scope_format_4_part() {
        for method in ["echo", "calculate", "read_file"] {
            let scope = format!("mcp:tool:{method}:call");
            let parts: Vec<&str> = scope.split(':').collect();
            assert_eq!(parts.len(), 4, "scope must be 4-part for method {method}");
            assert_eq!(parts[0], "mcp");
            assert_eq!(parts[1], "tool");
            assert_eq!(parts[2], method);
            assert_eq!(parts[3], "call");
        }
    }

    // ── tools/list discovery test ────────────────────────────────────────────

    #[test]
    fn test_tool_catalogue_structure() {
        let catalogue = tool_catalogue();
        let tools = catalogue["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3, "expected 3 tools in catalogue");

        let names: Vec<&str> = tools
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"echo"));
        assert!(names.contains(&"calculate"));
        assert!(names.contains(&"read_file"));

        // Every tool must have inputSchema
        for tool in tools {
            assert!(tool.get("inputSchema").is_some(), "tool {} missing inputSchema", tool["name"]);
            assert!(tool.get("description").is_some(), "tool {} missing description", tool["name"]);
        }
    }
}
