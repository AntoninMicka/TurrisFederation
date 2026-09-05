use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, sync::Mutex};

mod ssh;
mod network;
mod zerotier;
use tauri::{Manager, State};
use uuid::Uuid;

struct AppState { db: Mutex<Connection>, ssh_dir: PathBuf }

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
    expected_state: String, observed_state: String, observed_at: String,
}

fn migrate(db: &Connection) -> Result<(), String> {
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY,name TEXT NOT NULL,ssh_host TEXT NOT NULL,ssh_port INTEGER NOT NULL,ssh_user TEXT NOT NULL,lan_cidrs TEXT NOT NULL,zero_tier_address TEXT,public_endpoint TEXT,status TEXT NOT NULL,last_audit_at TEXT);
      CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,observed_at TEXT NOT NULL,payload TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS ssh_host_keys (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,host TEXT NOT NULL,port INTEGER NOT NULL,keys TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS app_settings (name TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS zerotier_status (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,payload TEXT NOT NULL);")
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
    if node.name.trim().is_empty() { return Err("Název uzlu je povinný.".into()); }
    ssh::validate(&node.ssh_host, &node.ssh_user, node.ssh_port)?;
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    db.execute("INSERT INTO nodes(id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET name=excluded.name,ssh_host=excluded.ssh_host,ssh_port=excluded.ssh_port,ssh_user=excluded.ssh_user,lan_cidrs=excluded.lan_cidrs,zero_tier_address=excluded.zero_tier_address,public_endpoint=excluded.public_endpoint,status=excluded.status,last_audit_at=excluded.last_audit_at",
      params![node.id,node.name,node.ssh_host,node.ssh_port,node.ssh_user,serde_json::to_string(&node.lan_cidrs).map_err(|error| error.to_string())?,node.zero_tier_address,node.public_endpoint,node.status,node.last_audit_at]).map_err(|error| error.to_string())?;
    Ok(node)
}

fn load_node(db: &Connection, node_id: &str) -> Result<FederationNode, String> {
    db.query_row("SELECT id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at FROM nodes WHERE id=?1", [node_id], row_to_node).map_err(|_| "Uzel nebyl nalezen.".to_string())
}

fn saved_host_key(db: &Connection, node: &FederationNode) -> Result<Option<String>, String> {
    use rusqlite::OptionalExtension;
    db.query_row("SELECT keys FROM ssh_host_keys WHERE node_id=?1 AND host=?2 AND port=?3",
        params![node.id, node.ssh_host, node.ssh_port], |row| row.get(0))
        .optional().map_err(|e| e.to_string())
}

#[tauri::command]
async fn inspect_connection(node_id: String, state: State<'_, AppState>) -> Result<ssh::HostIdentity, String> {
    let (node, saved) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let node = load_node(&db, &node_id)?;
        let saved = saved_host_key(&db, &node)?;
        (node, saved)
    };
    ssh::validate(&node.ssh_host, &node.ssh_user, node.ssh_port)?;
    ssh::inspect(&state.ssh_dir, saved.as_deref(), &node.ssh_host, node.ssh_port).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshCredentials { password: String, host_key: String, trust_host_key: bool }

async fn authenticated_probe(node_id: &str, credentials: SshCredentials, state: &AppState, probe: &str) -> Result<(FederationNode, String), String> {
    authenticated_probe_with_timeout(node_id, credentials, state, probe, 45).await
}

async fn authenticated_probe_with_timeout(node_id: &str, credentials: SshCredentials, state: &AppState, probe: &str, seconds: u64) -> Result<(FederationNode, String), String> {
    let (node, saved) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let node = load_node(&db, node_id)?;
        let saved = saved_host_key(&db, &node)?;
        (node, saved)
    };
    ssh::validate(&node.ssh_host, &node.ssh_user, node.ssh_port)?;
    let keys = ssh::canonical_keys(&credentials.host_key, &node.ssh_host, node.ssh_port)?;
    ssh::check_trust(saved.as_deref(), &keys, credentials.trust_host_key)?;
    let result = ssh::execute(&state.ssh_dir, &node.ssh_host, &node.ssh_user, node.ssh_port, &credentials.password, &keys, probe, seconds).await;
    let db = state.db.lock().map_err(|e| e.to_string())?;
    match result {
        Ok(payload) => {
            db.execute("INSERT INTO ssh_host_keys(node_id,host,port,keys) VALUES(?1,?2,?3,?4) ON CONFLICT(node_id) DO UPDATE SET host=excluded.host,port=excluded.port,keys=excluded.keys",
                params![node.id, node.ssh_host, node.ssh_port, keys]).map_err(|e| e.to_string())?;
            Ok((node, payload))
        }
        Err(error) => {
            db.execute("UPDATE nodes SET status='unreachable' WHERE id=?1", [&node.id]).map_err(|e| e.to_string())?;
            Err(error)
        }
    }
}

#[tauri::command]
async fn connect_node(node_id: String, credentials: SshCredentials, state: State<'_, AppState>) -> Result<FederationNode, String> {
    let (node, payload) = authenticated_probe(&node_id, credentials, &state, "printf '__TF_CONNECTED__\\n'").await?;
    if !payload.lines().any(|line| line == "__TF_CONNECTED__") {
        return Err("SSH odpovědělo, ale router neumožnil provést ověřovací příkaz.".into());
    }
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.execute("UPDATE nodes SET status=CASE WHEN status IN ('draft','unreachable') THEN 'observed' ELSE status END WHERE id=?1", [&node.id]).map_err(|e| e.to_string())?;
    load_node(&db, &node.id)
}

#[tauri::command]
async fn audit_node(node_id: String, credentials: SshCredentials, state: State<'_, AppState>) -> Result<Vec<AuditFinding>, String> {
    let settings = { let db = state.db.lock().map_err(|e| e.to_string())?; load_zerotier_settings(&db)? };
    let zt_probe = zerotier::probe(settings.network_id.as_deref(), false)?;
    let probe = format!("set +e; echo __TF_SYSTEM__; ubus call system board 2>&1; {} echo __TF_WIREGUARD__; wg show all dump 2>&1; echo __TF_PACKAGES__; opkg status zerotier wireguard-tools 2>&1; echo __TF_UCI_NETWORK__; uci export network 2>&1; echo __TF_UCI_FIREWALL__; uci export firewall 2>&1; {}", network::PROBE, zt_probe);
    let (node, payload) = authenticated_probe(&node_id, credentials, &state, &probe).await?;
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let observed_at = Utc::now().to_rfc3339();
    db.execute("INSERT INTO observations(id,node_id,observed_at,payload) VALUES(?1,?2,?3,?4)", params![Uuid::new_v4().to_string(),node.id,observed_at,payload]).map_err(|error| error.to_string())?;
    let findings = build_findings(&node, &payload, &observed_at, settings.network_id.as_deref());
    persist_zerotier_status(&db, &zerotier::parse(&payload, &node.id, settings.network_id.as_deref(), &observed_at))?;
    let status = if findings.is_empty() { "healthy" } else { "drifted" };
    db.execute("UPDATE nodes SET status=?1,last_audit_at=?2 WHERE id=?3", params![status,observed_at,node.id]).map_err(|error| error.to_string())?;
    Ok(findings)
}

// Pouze výstup příslušné kontroly; celý audit obsahuje i citlivou konfiguraci.
fn audit_section<'a>(payload: &'a str, marker: &str) -> Option<String> {
    let mut lines = payload.lines().skip_while(|line| line.trim() != marker);
    lines.next()?;
    Some(lines.take_while(|line| !line.starts_with("__TF_")).collect::<Vec<_>>().join("\n").trim().to_string())
}

fn display_observation(section: Option<&str>) -> String {
    match section {
        None => "Stav se nepodařilo načíst (chybí výstup kontroly).".into(),
        Some("") => "Router vrátil prázdný výstup.".into(),
        Some(text) => serde_json::from_str::<serde_json::Value>(text)
            .ok().and_then(|value| serde_json::to_string_pretty(&value).ok())
            .unwrap_or_else(|| text.to_string()),
    }
}

fn build_findings(node: &FederationNode, payload: &str, observed_at: &str, network_id: Option<&str>) -> Vec<AuditFinding> {
    let wireguard = audit_section(payload, "__TF_WIREGUARD__");
    let addresses = audit_section(payload, "__TF_ADDRESSES__");
    let routes = audit_section(payload, "__TF_ROUTES__");
    let mut findings = Vec::new();
    let mut add = |severity: &str, component: &str, summary: String, remediation: &str, expected: String, observed: String| {
        findings.push(AuditFinding {
            id: Uuid::new_v4().to_string(), node_id: node.id.clone(), severity: severity.into(), component: component.into(),
            summary, remediation: Some(remediation.into()), expected_state: expected, observed_state: observed, observed_at: observed_at.into(),
        });
    };
    let zt = zerotier::parse(payload, &node.id, network_id, observed_at);
    if zt.state != "connected" && !(network_id.is_none() && zt.state == "no_network") {
        add(if zt.state == "not_installed" || zt.state == "error" || zt.state == "unknown" { "error" } else { "warning" }, "zerotier", zt.summary.clone(),
            "Použijte kontrolu a nastavení ZeroTier. Čekající router autorizujte v ZeroTier Central a obnovte stav.",
            network_id.map(|id| format!("ONLINE a členství OK v síti {id}")).unwrap_or_else(|| "ONLINE".into()), zt.details.clone());
    } else if network_id.is_some() && (!zt.persistent || zt.service_enabled != Some(true)) {
        add("warning", "zerotier", "ZeroTier nemá potvrzené trvalé nastavení pro restart routeru.".into(),
            "Použijte nastavení ZeroTier pro uložení členství a zapnutí služby při startu.", "Trvalé členství a automatický start služby.".into(),
            format!("Členství v UCI: {}\nStart služby: {:?}", zt.persistent, zt.service_enabled));
    }
    // Výpis wg dump obsahuje privátní klíče. Do nálezu patří pouze chyba nástroje.
    if let Some(error) = wireguard.as_deref().and_then(|text| text.lines().find(|line| line.contains("wg: not found"))) {
        add("warning", "wireguard", "WireGuard nástroje nejsou nainstalované".into(),
            "Připravit instalaci wireguard-tools a návrh peerů.",
            "Nástroj wg je dostupný.".into(), error.into());
    }
    let address_status = audit_section(payload, "__TF_ADDRESSES_STATUS__");
    let route_status = audit_section(payload, "__TF_ROUTES_STATUS__");
    let addresses_loaded = network::loaded(addresses.as_deref(), address_status.as_deref());
    let routes_loaded = network::loaded(routes.as_deref(), route_status.as_deref());
    let observed = format!("Adresy rozhraní:\n{}\n\nSměrovací tabulka:\n{}", display_observation(addresses.as_deref()), display_observation(routes.as_deref()));
    if !addresses_loaded || !routes_loaded {
        add("error", "routes", "Síťový stav se nepodařilo kompletně načíst".into(),
            "Prověřit výstup příkazů ip a oprávnění SSH uživatele. Chybějící sítě zatím nelze spolehlivě vyhodnotit.",
            "Úspěšné načtení adres rozhraní i směrovací tabulky.".into(), observed);
    } else {
        let mut actual_networks = network::networks(addresses.as_deref().unwrap_or_default());
        actual_networks.extend(network::networks(routes.as_deref().unwrap_or_default()));
        for cidr in &node.lan_cidrs {
            if !network::cidr(cidr).is_some_and(|net| actual_networks.contains(&net)) {
                add("warning", "routes", format!("Draft síť {cidr} nebyla nalezena"),
                    "Prověřit adresaci a připravit směrovací pravidlo federace.", cidr.clone(), observed.clone());
            }
        }
    }
    findings
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    fn node() -> FederationNode {
        FederationNode { id: "test".into(), name: "Router".into(), ssh_host: "router".into(), ssh_port: 22, ssh_user: "root".into(),
            lan_cidrs: vec!["192.168.10.0/24".into()], zero_tier_address: None, public_endpoint: None, status: "draft".into(), last_audit_at: None }
    }
    #[test]
    fn findings_include_relevant_state_without_configuration_secrets() {
        let payload = "__TF_ADDRESSES__\n[]\n__TF_ROUTES__\n[{\"dst\":\"10.0.0.0/24\"}]\n__TF_ZT_INSTALLED__\n1\n__TF_ZT_INFO__\n200 info abcdef1234 1.0 OFFLINE\n__TF_ZT_INFO_RC__\n0\n__TF_ZT_NETWORKS__\n[]\n__TF_ZT_NETWORKS_RC__\n0\n__TF_WIREGUARD__\nwg: not found\n__TF_UCI_NETWORK__\nprivate_key SECRET\n192.168.10.0/24 ONLINE";
        let findings = build_findings(&node(), payload, "2026-09-05T12:00:00Z", None);
        assert_eq!(findings.len(), 3);
        let zt = findings.iter().find(|f| f.component == "zerotier").unwrap();
        assert!(zt.observed_state.contains("OFFLINE"));
        assert_eq!(zt.expected_state, "ONLINE");
        let routes = findings.iter().find(|f| f.component == "routes").unwrap();
        assert_eq!(routes.expected_state, "192.168.10.0/24");
        assert!(routes.observed_state.contains("10.0.0.0/24"));
        for finding in findings {
            assert!(!finding.observed_state.contains("SECRET"));
            assert_eq!(finding.observed_at, "2026-09-05T12:00:00Z");
        }
    }
    #[test]
    fn missing_and_empty_observations_are_explicit() {
        assert!(display_observation(None).contains("nepodařilo"));
        assert!(display_observation(Some("")).contains("prázdný"));
        assert!(build_findings(&node(), "", "now", None).iter().all(|f| !f.observed_state.is_empty()));
    }

    #[test]
    fn zerotier_migration_preserves_existing_nodes_and_stores_settings_and_status() {
        let db = Connection::open_in_memory().unwrap();
        migrate(&db).unwrap();
        db.execute("INSERT INTO nodes(id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,status) VALUES('test','Router','router',22,'root','[]','draft')", []).unwrap();
        db.execute_batch("DROP TABLE app_settings; DROP TABLE zerotier_status;").unwrap();
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(load_node(&db, "test").unwrap().name, "Router");
        assert!(load_zerotier_settings(&db).unwrap().network_id.is_none());
        db.execute("INSERT INTO app_settings(name,value) VALUES('zerotier',?1)", [r#"{"networkId":"ABCDEF0123456789","central":"legacy"}"#]).unwrap();
        assert_eq!(load_zerotier_settings(&db).unwrap().network_id.as_deref(), Some("abcdef0123456789"));
        let status = zerotier::parse("__TF_ZT_INSTALLED__\n0\n__TF_ZT_END__", "test", Some("abcdef0123456789"), "now");
        persist_zerotier_status(&db, &status).unwrap();
        let saved: String = db.query_row("SELECT payload FROM zerotier_status WHERE node_id='test'", [], |row| row.get(0)).unwrap();
        assert_eq!(serde_json::from_str::<zerotier::Status>(&saved).unwrap().state, "not_installed");
    }
}

fn load_zerotier_settings(db: &Connection) -> Result<zerotier::Settings, String> {
    use rusqlite::OptionalExtension;
    let json: Option<String> = db.query_row("SELECT value FROM app_settings WHERE name='zerotier'", [], |row| row.get(0)).optional().map_err(|e| e.to_string())?;
    match json { Some(json) => serde_json::from_str::<zerotier::Settings>(&json).map_err(|e| e.to_string())?.normalize(), None => Ok(zerotier::Settings::default()) }
}

#[tauri::command]
fn get_zerotier_settings(state: State<'_, AppState>) -> Result<zerotier::Settings, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    load_zerotier_settings(&db)
}

#[tauri::command]
fn save_zerotier_settings(settings: zerotier::Settings, state: State<'_, AppState>) -> Result<zerotier::Settings, String> {
    let settings = settings.normalize()?;
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.execute("INSERT INTO app_settings(name,value) VALUES('zerotier',?1) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        [serde_json::to_string(&settings).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
    Ok(settings)
}

fn persist_zerotier_status(db: &Connection, status: &zerotier::Status) -> Result<(), String> {
    db.execute("INSERT INTO zerotier_status(node_id,payload) VALUES(?1,?2) ON CONFLICT(node_id) DO UPDATE SET payload=excluded.payload",
        params![status.router_id, serde_json::to_string(status).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn list_zerotier_status(state: State<'_, AppState>) -> Result<Vec<zerotier::Status>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let mut stmt = db.prepare("SELECT payload FROM zerotier_status").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).map_err(|e| e.to_string())?;
    rows.map(|row| serde_json::from_str(&row.map_err(|e| e.to_string())?).map_err(|e| e.to_string())).collect()
}

#[tauri::command]
async fn manage_zerotier(node_id: String, credentials: SshCredentials, network_id: Option<String>, configure: bool, state: State<'_, AppState>) -> Result<zerotier::Status, String> {
    let settings = { let db = state.db.lock().map_err(|e| e.to_string())?; load_zerotier_settings(&db)? };
    if network_id != settings.network_id { return Err("Network ID se změnilo. Znovu otevřete kontrolu ZeroTier.".into()); }
    let probe = zerotier::probe(network_id.as_deref(), configure)?;
    let (node, payload) = authenticated_probe_with_timeout(&node_id, credentials, &state, &probe, if configure { 300 } else { 45 }).await
        .map_err(|error| if configure { format!("{error}\nNastavení mohlo být provedeno částečně. Před opakováním načtěte stav ZeroTier.") } else { error })?;
    if configure && !payload.lines().any(|line| line == "__TF_ZT_SETUP_OK__") { return Err("Router nepotvrdil dokončení nastavení. Znovu načtěte stav ZeroTier.".into()); }
    let result = zerotier::parse(&payload, &node.id, network_id.as_deref(), &Utc::now().to_rfc3339());
    let db = state.db.lock().map_err(|e| e.to_string())?;
    persist_zerotier_status(&db, &result)?;
    Ok(result)
}

#[tauri::command]
async fn open_zerotier_central(state: State<'_, AppState>) -> Result<String, String> {
    let settings = { let db = state.db.lock().map_err(|e| e.to_string())?; load_zerotier_settings(&db)? };
    let url = settings.url();
    let mut child = tokio::process::Command::new("xdg-open").arg(url)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn().map_err(|e| format!("Prohlížeč nelze otevřít: {e}. Otevřete {url} ručně."))?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) if status.success() => (),
        Ok(_) => return Err(format!("Prohlížeč se nepodařilo otevřít. Otevřete {url} ručně.")),
        Err(_) => { tauri::async_runtime::spawn(async move { let _ = child.wait().await; }); }
    }
    Ok(url.into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default().setup(|app| {
        let data_dir = app.path().app_data_dir()?; fs::create_dir_all(&data_dir)?;
        let db = Connection::open(data_dir.join("federation.db"))?;
        migrate(&db).map_err(std::io::Error::other)?;
        app.manage(AppState { db: Mutex::new(db), ssh_dir: data_dir.join("ssh") }); Ok(())
    }).invoke_handler(tauri::generate_handler![list_nodes,save_node,inspect_connection,connect_node,audit_node,get_zerotier_settings,save_zerotier_settings,list_zerotier_status,manage_zerotier,open_zerotier_central]).run(tauri::generate_context!()).expect("Turris Federation failed to start");
}
