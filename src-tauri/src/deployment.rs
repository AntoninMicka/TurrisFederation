use crate::{AppState, SshCredentials, list_nodes_from_db, load_zerotier_settings, load_node, saved_host_key, ssh};
use serde_json::{json, Value};
use tauri::State;
use tokio::io::AsyncWriteExt;
use std::{fs, process::Stdio, time::Duration};

const CONTROLLER: &str = include_str!("../../router/files/usr/lib/turris-federation/federation.py");

#[tauri::command]
pub async fn deployment_action(action: String, node_id: Option<String>, credentials: Option<SshCredentials>, plan_id: Option<String>, state: State<'_, AppState>) -> Result<Value, String> {
    if !["overview", "validate", "deploy", "publish"].contains(&action.as_str()) {
        return Err("Neznámá operace deploye.".into());
    }
    let (nodes, settings) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        (list_nodes_from_db(&db)?, load_zerotier_settings(&db)?)
    };
    let mut auth = Value::Null;
    let mut trusted = None;
    if action == "validate" || action == "deploy" {
        let id = node_id.as_deref().ok_or("Chybí uzel.")?;
        let credentials = credentials.ok_or("Chybí přihlášení.")?;
        let (node, saved) = {
            let db = state.db.lock().map_err(|e| e.to_string())?;
            let node = load_node(&db, id)?;
            let saved = saved_host_key(&db, &node)?;
            (node, saved)
        };
        ssh::validate(&node.ssh_host, &node.ssh_user, node.ssh_port)?;
        let keys = ssh::canonical_keys(&credentials.host_key, &node.ssh_host, node.ssh_port)?;
        ssh::check_trust(saved.as_deref(), &keys, credentials.trust_host_key)?;
        auth = json!({"password": credentials.password, "hostKey": keys});
        trusted = Some((node, keys));
    }
    // Each process loads its own source; concurrent calls cannot truncate an executing script.
    let root = state.ssh_dir.parent().ok_or("Chybí datový adresář.")?.join("deployment");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let script = root.join(format!("controller-{}.py", uuid::Uuid::new_v4()));
    fs::write(&script, CONTROLLER).map_err(|e| e.to_string())?;
    let request = json!({"action": action, "nodeId": node_id, "planId": plan_id, "credentials": auth,
                        "nodes": nodes, "networkId": settings.network_id});
    let result = async {
        let mut child = tokio::process::Command::new("python3").arg(&script).arg("controller").arg(&root)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true)
            .spawn().map_err(|e| format!("Nelze spustit deploy. Notebook potřebuje python3 a openssl: {e}"))?;
        let mut input = child.stdin.take().ok_or("Chybí vstup controlleru.")?;
        input.write_all(&serde_json::to_vec(&request).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
        drop(input);
        let output = tokio::time::timeout(Duration::from_secs(900), child.wait_with_output()).await
            .map_err(|_| "Deploy překročil časový limit. Před opakováním ověřte stav routeru.".to_string())?
            .map_err(|e| e.to_string())?;
        if !output.status.success() { return Err(String::from_utf8_lossy(&output.stderr).trim().to_string()); }
        serde_json::from_slice::<Value>(&output.stdout).map_err(|e| format!("Neplatná odpověď deploye: {e}"))
    }.await;
    let _ = fs::remove_file(&script);
    if result.is_ok() {
        if let Some((node, keys)) = trusted {
            let db = state.db.lock().map_err(|e| e.to_string())?;
            db.execute("INSERT INTO ssh_host_keys(node_id,host,port,keys) VALUES(?1,?2,?3,?4) ON CONFLICT(node_id) DO UPDATE SET host=excluded.host,port=excluded.port,keys=excluded.keys",
                       rusqlite::params![node.id,node.ssh_host,node.ssh_port,keys]).map_err(|e| e.to_string())?;
        }
    }
    result
}
