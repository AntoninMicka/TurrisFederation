use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, Mutex}};

mod ssh;
mod network;
mod zerotier;
mod deployment;
mod notebooks;
mod single_instance;
use tauri::{Emitter, Manager, State};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use uuid::Uuid;

struct AppState { db: Mutex<Connection>, ssh_dir: PathBuf }

#[derive(Default)]
struct AppLifecycle { allow_exit: AtomicBool }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FederationNode {
    id: String, name: String, ssh_host: String, ssh_port: u16, ssh_user: String,
    lan_cidrs: Vec<String>, zero_tier_address: Option<String>, public_endpoint: Option<String>,
    #[serde(default = "draft_status")] status: String, last_audit_at: Option<String>,
    #[serde(default)] wireguard_address: Option<String>,
}

fn draft_status() -> String { "draft".into() }

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsExport {
    version: u32,
    exported_at: String,
    nodes: Vec<serde_json::Value>,
    zerotier: zerotier::Settings,
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
      .map_err(|error| error.to_string())?;
    let has_column = {
        let mut statement = db.prepare("PRAGMA table_info(nodes)").map_err(|e| e.to_string())?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1)).map_err(|e| e.to_string())?;
        columns.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?.iter().any(|name| name == "wireguard_address")
    };
    if !has_column { db.execute_batch("ALTER TABLE nodes ADD COLUMN wireguard_address TEXT;").map_err(|e| e.to_string())?; }
    // Retain audit metadata, remove historical raw sections which could contain private keys.
    let mut statement = db.prepare("SELECT id,payload FROM observations WHERE payload LIKE '%__TF_UCI_%' OR payload LIKE '%__TF_WIREGUARD__%'").map_err(|e| e.to_string())?;
    let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
    let rows = rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    for (id, payload) in rows {
        let mut omit = false;
        let safe = payload.lines().filter(|line| {
            if line.starts_with("__TF_") { omit = line.starts_with("__TF_UCI_") || *line == "__TF_WIREGUARD__"; }
            !omit
        }).collect::<Vec<_>>().join("\n");
        db.execute("UPDATE observations SET payload=?1 WHERE id=?2", params![safe,id]).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<FederationNode> {
    let lan_cidrs: String = row.get(5)?;
    Ok(FederationNode { id: row.get(0)?, name: row.get(1)?, ssh_host: row.get(2)?, ssh_port: row.get(3)?, ssh_user: row.get(4)?, lan_cidrs: serde_json::from_str(&lan_cidrs).unwrap_or_default(), zero_tier_address: row.get(6)?, public_endpoint: row.get(7)?, status: row.get(8)?, last_audit_at: row.get(9)?, wireguard_address: row.get(10)? })
}

#[tauri::command]
fn list_nodes(state: State<'_, AppState>) -> Result<Vec<FederationNode>, String> {
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    let mut statement = db.prepare("SELECT id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at,wireguard_address FROM nodes ORDER BY name").map_err(|error| error.to_string())?;
    let rows = statement.query_map([], row_to_node).map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
}

fn list_nodes_from_db(db: &Connection) -> Result<Vec<FederationNode>, String> {
    let mut statement = db.prepare("SELECT id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at,wireguard_address FROM nodes ORDER BY name")
        .map_err(|error| error.to_string())?;
    let rows = statement.query_map([], row_to_node).map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
}

fn validate_import_node(node: &FederationNode) -> Result<(), String> {
    if Uuid::parse_str(&node.id).is_err() {
        return Err("Uzel musí mít platné UUID.".into());
    }
    if node.name.trim().is_empty() {
        return Err(format!("Uzel {} nemá název.", node.id));
    }
    if !node.ssh_host.is_empty() { ssh::validate(&node.ssh_host, &node.ssh_user, node.ssh_port)?; }
    for cidr in &node.lan_cidrs {
        if network::cidr(cidr).is_none() {
            return Err(format!("Uzel {} obsahuje neplatnou LAN síť.", node.name));
        }
    }
    Ok(())
}

#[tauri::command]
fn export_settings(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    notebooks::require_admin(&app)?;
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    let export = SettingsExport {
        version: 2,
        exported_at: Utc::now().to_rfc3339(),
        nodes: list_nodes_from_db(&db)?.into_iter().map(|node| {
            let mut value = serde_json::to_value(node).map_err(|e| e.to_string())?;
            value.as_object_mut().unwrap().remove("status");
            value.as_object_mut().unwrap().remove("lastAuditAt");
            Ok(value)
        }).collect::<Result<Vec<_>, String>>()?,
        zerotier: load_zerotier_settings(&db)?,
    };
    serde_json::to_string_pretty(&export).map_err(|error| error.to_string())
}

#[tauri::command]
fn import_settings(payload: String, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    notebooks::require_admin(&app)?;
    let mut db = state.db.lock().map_err(|e| e.to_string())?;
    import_settings_to_db(&payload, &mut db)
}

fn import_settings_to_db(payload: &str, db: &mut Connection) -> Result<(), String> {
    let mut import: SettingsExport = serde_json::from_str(&payload)
        .map_err(|error| format!("Soubor není platný export Turris Federation: {error}"))?;
    if ![1, 2].contains(&import.version) {
        return Err(format!("Nepodporovaná verze exportu {}.", import.version));
    }
    import.zerotier = import.zerotier.normalize()?;
    let imported_nodes = import.nodes.into_iter().map(|value| serde_json::from_value::<FederationNode>(value).map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
    let mut ids = std::collections::HashSet::new();
    for node in &imported_nodes {
        validate_import_node(node)?;
        if !ids.insert(&node.id) { return Err("Import obsahuje duplicitní ID uzlu.".into()); }
    }

    let tx = db.transaction().map_err(|error| error.to_string())?;


    for node in imported_nodes {
        tx.execute(
            "INSERT INTO nodes(id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at,wireguard_address)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'draft',NULL,?9) ON CONFLICT(id) DO UPDATE SET name=excluded.name,ssh_host=excluded.ssh_host,ssh_port=excluded.ssh_port,ssh_user=excluded.ssh_user,lan_cidrs=excluded.lan_cidrs,zero_tier_address=excluded.zero_tier_address,public_endpoint=excluded.public_endpoint,wireguard_address=excluded.wireguard_address,status='draft',last_audit_at=NULL",
            params![
                node.id,
                node.name,
                node.ssh_host,
                node.ssh_port,
                node.ssh_user,
                serde_json::to_string(&node.lan_cidrs).map_err(|error| error.to_string())?,
                node.zero_tier_address,
                node.public_endpoint, node.wireguard_address
            ],
        ).map_err(|error| error.to_string())?;
    }

    tx.execute(
        "INSERT INTO app_settings(name,value) VALUES('zerotier',?1)
         ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        [serde_json::to_string(&import.zerotier).map_err(|error| error.to_string())?],
    ).map_err(|error| error.to_string())?;

    tx.commit().map_err(|error| error.to_string())
}

#[tauri::command]
fn save_node(node: FederationNode, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<FederationNode, String> {
    notebooks::require_admin(&app)?;
    validate_import_node(&node)?;
    let db = state.db.lock().map_err(|_| "Databáze je právě používána.".to_string())?;
    db.execute("INSERT INTO nodes(id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at,wireguard_address) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'draft',NULL,?9) ON CONFLICT(id) DO UPDATE SET name=excluded.name,ssh_host=excluded.ssh_host,ssh_port=excluded.ssh_port,ssh_user=excluded.ssh_user,lan_cidrs=excluded.lan_cidrs,zero_tier_address=excluded.zero_tier_address,public_endpoint=excluded.public_endpoint,wireguard_address=excluded.wireguard_address,status='draft',last_audit_at=NULL",
      params![node.id,node.name,node.ssh_host,node.ssh_port,node.ssh_user,serde_json::to_string(&node.lan_cidrs).map_err(|error| error.to_string())?,node.zero_tier_address,node.public_endpoint,node.wireguard_address]).map_err(|error| error.to_string())?;
    load_node(&db, &node.id)
}

fn load_node(db: &Connection, node_id: &str) -> Result<FederationNode, String> {
    db.query_row("SELECT id,name,ssh_host,ssh_port,ssh_user,lan_cidrs,zero_tier_address,public_endpoint,status,last_audit_at,wireguard_address FROM nodes WHERE id=?1", [node_id], row_to_node).map_err(|_| "Uzel nebyl nalezen.".to_string())
}

fn saved_host_key(db: &Connection, node: &FederationNode) -> Result<Option<String>, String> {
    use rusqlite::OptionalExtension;
    db.query_row("SELECT keys FROM ssh_host_keys WHERE node_id=?1 AND host=?2 AND port=?3",
        params![node.id, node.ssh_host, node.ssh_port], |row| row.get(0))
        .optional().map_err(|e| e.to_string())
}

#[tauri::command]
async fn inspect_connection(node_id: String, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<ssh::HostIdentity, String> {
    notebooks::require_admin(&app)?;
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
async fn connect_node(node_id: String, credentials: SshCredentials, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<FederationNode, String> {
    notebooks::require_admin(&app)?;
    let (node, payload) = authenticated_probe(&node_id, credentials, &state, "printf '__TF_CONNECTED__\\n'").await?;
    if !payload.lines().any(|line| line == "__TF_CONNECTED__") {
        return Err("SSH odpovědělo, ale router neumožnil provést ověřovací příkaz.".into());
    }
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.execute("UPDATE nodes SET status=CASE WHEN status IN ('draft','unreachable') THEN 'observed' ELSE status END WHERE id=?1", [&node.id]).map_err(|e| e.to_string())?;
    load_node(&db, &node.id)
}

#[tauri::command]
async fn audit_node(node_id: String, credentials: SshCredentials, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<Vec<AuditFinding>, String> {
    notebooks::require_admin(&app)?;
    let settings = { let db = state.db.lock().map_err(|e| e.to_string())?; load_zerotier_settings(&db)? };
    let zt_probe = zerotier::probe(settings.network_id.as_deref(), false)?;
    let probe = format!("set +e; echo __TF_SYSTEM__; ubus call system board 2>&1; {} echo __TF_WIREGUARD__; wg show all public-key 2>&1; echo __TF_PACKAGES__; opkg status zerotier wireguard-tools 2>&1; {}", network::PROBE, zt_probe);
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

// Pouze výstup příslušné kontroly.
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
    if zt.wireguard_interface_blocked == Some(false) {
        add("warning", "zerotier", "ZeroTier může použít federační WireGuard rozhraní jako fyzickou cestu.".into(),
            "Spusťte nastavení ZeroTier; uloží interfacePrefixBlacklist pro tf_wg a bezpečně restartuje službu.",
            "ZeroTier má načtený zákaz prefixu rozhraní tf_wg.".into(), zt.details.clone());
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
            lan_cidrs: vec!["192.168.10.0/24".into()], zero_tier_address: None, public_endpoint: None, status: "draft".into(), last_audit_at: None, wireguard_address: None }
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
    fn audit_warns_when_zerotier_can_discover_over_wireguard() {
        let payload = "__TF_ADDRESSES__\n[{\"local\":\"192.168.10.1\",\"prefixlen\":24}]\n__TF_ADDRESSES_STATUS__\n0\n__TF_ROUTES__\n[]\n__TF_ROUTES_STATUS__\n0\n__TF_ZT_INSTALLED__\n1\n__TF_ZT_INFO__\n{\"address\":\"abcdef1234\",\"online\":true,\"version\":\"1.14.0\",\"config\":{\"settings\":{\"interfacePrefixBlacklist\":[]}}}\n__TF_ZT_INFO_RC__\n0\n__TF_ZT_NETWORKS__\n[]\n__TF_ZT_NETWORKS_RC__\n0\n__TF_ZT_ENABLED__\n1\n__TF_ZT_PERSISTENT__\n1\n__TF_WIREGUARD__\n";
        let findings = build_findings(&node(), payload, "now", None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].summary.contains("WireGuard"));
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
fn save_zerotier_settings(settings: zerotier::Settings, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<zerotier::Settings, String> {
    notebooks::require_admin(&app)?;
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
async fn check_notebook_zerotier(state: State<'_, AppState>) -> Result<zerotier::Status, String> {
    let settings = { let db = state.db.lock().map_err(|e| e.to_string())?; load_zerotier_settings(&db)? };
    let network_id = settings.network_id.clone();
    let mut result = tokio::task::spawn_blocking(move || zerotier::notebook_status(network_id.as_deref()))
        .await.map_err(|e| e.to_string())??;
    result.summary = result.summary.replace("Router", "Notebook").replace("routeru", "notebooku");
    Ok(result)
}

#[tauri::command]
async fn manage_zerotier(node_id: String, credentials: SshCredentials, network_id: Option<String>, configure: bool, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<zerotier::Status, String> {
    notebooks::require_admin(&app)?;
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
async fn open_zerotier_central(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    notebooks::require_admin(&app)?;
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
    let app = tauri::Builder::default().setup(|app| {
        app.manage(AppLifecycle::default());
        let background = std::env::args_os().any(|argument| argument == "--background");
        if matches!(single_instance::acquire(app.handle(), !background).map_err(std::io::Error::other)?, single_instance::Instance::Secondary) {
            app.state::<AppLifecycle>().allow_exit.store(true, Ordering::Release);
            app.handle().exit(0);
            return Ok(());
        }
        let data_dir = app.path().app_data_dir()?; fs::create_dir_all(&data_dir)?;
        let config_dir = app.path().config_dir()?;
        let db = Connection::open(data_dir.join("federation.db"))?;
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        migrate(&db).map_err(std::io::Error::other)?;
        let notebook_service = notebooks::NotebookService::default();
        notebooks::resume(&data_dir, &config_dir, &notebook_service);
        app.manage(notebook_service);
        app.manage(notebooks::NotebookCommandGate::default());
        app.manage(AppState { db: Mutex::new(db), ssh_dir: data_dir.join("ssh") });

        let tray_state = notebooks::tray_state();
        let status = MenuItem::with_id(app, "backend-status", tray_state.label(), false, None::<&str>)?;
        let open = MenuItem::with_id(app, "open-ui", "Otevřít Turris Federation", true, None::<&str>)?;
        let disconnect = MenuItem::with_id(app, "disconnect-notebook", "Zastavit službu / odpojit tento notebook…", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit-ui", "Ukončit UI (backend zůstane běžet)", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&status, &open, &disconnect, &quit])?;
        let mut tray = TrayIconBuilder::with_id("main").menu(&menu).tooltip("Turris Federation");
        tray = tray.icon(tray_icon(tray_state));
        tray.build(app)?;
        if !background {
            if let Some(window) = app.get_webview_window("main") { window.show()?; }
        }
        let status_item = status.clone();
        let handle = app.handle().clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(10));
            let state = notebooks::tray_state();
            let _ = status_item.set_text(state.label());
            if let Some(tray) = handle.tray_by_id("main") {
                let _ = tray.set_icon(Some(tray_icon(state)));
                let _ = tray.set_tooltip(Some(format!("Turris Federation · {}", state.label())));
            }
        });
        Ok(())
    }).on_menu_event(|app, event| match event.id().as_ref() {
        "open-ui" => if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        },
        "quit-ui" => {
            app.state::<AppLifecycle>().allow_exit.store(true, Ordering::Release);
            app.exit(0);
        },
        "disconnect-notebook" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
            let _ = app.emit("tray-disconnect-requested", ());
        },
        _ => (),
    }).on_window_event(|window, event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = window.hide();
        }
    }).invoke_handler(tauri::generate_handler![notebooks::notebook_action,check_notebook_zerotier,deployment::deployment_action,list_nodes,save_node,inspect_connection,connect_node,audit_node,get_zerotier_settings,save_zerotier_settings,export_settings,import_settings,list_zerotier_status,manage_zerotier,open_zerotier_central]).build(tauri::generate_context!()).expect("Turris Federation failed to start");
    app.run(|handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let lifecycle = handle.state::<AppLifecycle>();
            if !lifecycle.allow_exit.load(Ordering::Acquire) {
                api.prevent_exit();
                if let Some(window) = handle.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
        }
    });
}

fn tray_icon(state: notebooks::TrayState) -> tauri::image::Image<'static> {
    const SIZE: usize = 22;
    let color = state.color();
    let mut rgba = vec![0_u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as i32 - 10;
            let dy = y as i32 - 10;
            if dx * dx + dy * dy <= 81 {
                let offset = (y * SIZE + x) * 4;
                let border = dx * dx + dy * dy >= 64;
                let pixel = if border { [35, 40, 45, 255] } else { [color[0], color[1], color[2], 255] };
                rgba[offset..offset + 4].copy_from_slice(&pixel);
            }
        }
    }
    tauri::image::Image::new_owned(rgba, SIZE as u32, SIZE as u32)
}
