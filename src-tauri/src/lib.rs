use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{fs, process::Command, sync::Mutex};
use tauri::{Manager, State};
use uuid::Uuid;

struct AppState { db: Mutex<Connection> }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FederationNode {
    id: String, name: String, ssh_host: String, ssh_port: u16, ssh_user: String,
    lan_cidrs: Vec<String>, zero_tier_address: Option<String>, public_endpoint: Option<String>,
    status: String, last_audit_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditFinding {
    id: String, node_id: String, severity: String, component: String,
    summary: String, remediation: Option<String>,
}

fn migrate(db: &Connection) -> Result<(), String> {
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY,name TEXT NOT NULL,ssh_host TEXT NOT NULL,ssh_port INTEGER NOT NULL,ssh_user TEXT NOT NULL,lan_cidrs TEXT NOT NULL,zero_tier_address TEXT,public_endpoint TEXT,status TEXT NOT NULL,last_audit_at TEXT);
      CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,observed_at TEXT NOT NULL,payload TEXT NOT NULL);")
      .map_err(|error| error.to_string())
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<FederationNode> {
    let lan_cidrs: String = row.get(5)?;
    Ok(FederationNode { id: row.get(0)?, name: row.get(1)?, ssh_host: row.get(2)?, ssh_port: row.get(3)?, ssh_user: row.get(4)?, lan_cidrs: serde_json::from_str(&lan_cidrs).unwrap_or_default(), zero_tier_address: row.get(6)?, public_endpoint: row.get(7)?, status: row.get(8)?, last_audit_at: row.get(9)? })
}

#[tauri::command]
fn list_nodes(state: State<'_, AppState>) -> Result<Vec<FederationNode>, String> {
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    let mut statement = db.prepare("SELECT id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at FROM nodes ORDER BY name").map_err(|error| error.to_string())?;
    let rows = statement.query_map([], row_to_node).map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
}

#[tauri::command]
fn save_node(node: FederationNode, state: State<'_, AppState>) -> Result<FederationNode, String> {
    if node.name.trim().is_empty() || node.ssh_host.trim().is_empty() || node.ssh_host.starts_with('-') { return Err("Název a bezpečná SSH adresa jsou povinné.".into()); }
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    db.execute("INSERT INTO nodes(id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET name=excluded.name,ssh_host=excluded.ssh_host,ssh_port=excluded.ssh_port,ssh_user=excluded.ssh_user,lan_cidrs=excluded.lan_cidrs,zero_tier_address=excluded.zero_tier_address,public_endpoint=excluded.public_endpoint,status=excluded.status,last_audit_at=excluded.last_audit_at",
      params![node.id,node.name,node.ssh_host,node.ssh_port,node.ssh_user,serde_json::to_string(&node.lan_cidrs).map_err(|error| error.to_string())?,node.zero_tier_address,node.public_endpoint,node.status,node.last_audit_at]).map_err(|error| error.to_string())?;
    Ok(node)
}

fn load_node(db: &Connection, node_id: &str) -> Result<FederationNode, String> {
    db.query_row("SELECT id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at FROM nodes WHERE id=?1", [node_id], row_to_node).map_err(|_| "Uzel nebyl nalezen.".to_string())
}

#[tauri::command]
fn audit_node(node_id: String, state: State<'_, AppState>) -> Result<Vec<AuditFinding>, String> {
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    let node = load_node(&db, &node_id)?;
    if node.ssh_user.starts_with('-') || node.ssh_user.contains('@') { return Err("Neplatný SSH uživatel.".into()); }
    let target = format!("{}@{}", node.ssh_user, node.ssh_host);
    let port = node.ssh_port.to_string();
    let probe = "set +e; echo __TF_SYSTEM__; ubus call system board 2>&1; echo __TF_ADDRESSES__; ip -j address show 2>&1; echo __TF_ROUTES__; ip -j route show table all 2>&1; echo __TF_ZEROTIER__; zerotier-cli info 2>&1; zerotier-cli listnetworks -j 2>&1; echo __TF_WIREGUARD__; wg show all dump 2>&1; echo __TF_PACKAGES__; opkg status zerotier wireguard-tools 2>&1; echo __TF_UCI_NETWORK__; uci export network 2>&1; echo __TF_UCI_FIREWALL__; uci export firewall 2>&1";
    let output = Command::new("ssh").args(["-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","ConnectTimeout=10","-p",&port,"--",&target,probe]).output().map_err(|error| format!("SSH nelze spustit: {error}"))?;
    if !output.status.success() { return Err(format!("SSH audit selhal: {}", String::from_utf8_lossy(&output.stderr).trim())); }
    let payload = String::from_utf8_lossy(&output.stdout).into_owned();
    let observed_at = Utc::now().to_rfc3339();
    db.execute("INSERT INTO observations(id,node_id,observed_at,payload) VALUES(?1,?2,?3,?4)", params![Uuid::new_v4().to_string(),node.id,observed_at,payload]).map_err(|error| error.to_string())?;
    let mut findings = Vec::new();
    let mut add = |severity: &str, component: &str, summary: String, remediation: &str| findings.push(AuditFinding { id: Uuid::new_v4().to_string(), node_id: node.id.clone(), severity: severity.into(), component: component.into(), summary, remediation: Some(remediation.into()) });
    if payload.contains("zerotier-cli: not found") { add("error","zerotier","ZeroTier není nainstalovaný".into(),"Připravit instalaci balíku a připojení do privátní discovery sítě."); }
    else if !payload.contains("ONLINE") { add("warning","zerotier","ZeroTier není ve stavu ONLINE".into(),"Zkontrolovat službu, identitu a členství v síti."); }
    if payload.contains("wg: not found") { add("warning","wireguard","WireGuard nástroje nejsou nainstalované".into(),"Připravit instalaci wireguard-tools a návrh peerů."); }
    for cidr in &node.lan_cidrs { if !payload.contains(cidr) { add("warning","routes",format!("Draft síť {cidr} nebyla nalezena"),"Prověřit adresaci a připravit směrovací pravidlo federace."); } }
    let status = if findings.is_empty() { "healthy" } else { "drifted" };
    db.execute("UPDATE nodes SET status=?1,last_audit_at=?2 WHERE id=?3", params![status,observed_at,node.id]).map_err(|error| error.to_string())?;
    Ok(findings)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default().setup(|app| {
        let data_dir = app.path().app_data_dir()?; fs::create_dir_all(&data_dir)?;
        let db = Connection::open(data_dir.join("federation.db"))?;
        migrate(&db).map_err(std::io::Error::other)?;
        app.manage(AppState { db: Mutex::new(db) }); Ok(())
    }).invoke_handler(tauri::generate_handler![list_nodes,save_node,audit_node]).run(tauri::generate_context!()).expect("Turris Federation failed to start");
}
