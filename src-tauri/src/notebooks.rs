use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, fs, io::{Read, Write}, os::unix::net::UnixStream, path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::Mutex, time::Duration};
use tauri::Manager;

const SERVICE: &str = include_str!("../../scripts/notebook_sync.py");
const FEDERATION: &str = include_str!("../../router/files/usr/lib/turris-federation/federation.py");
const UNIT_NAME: &str = "turris-federation-backend.service";
const AUTOSTART_NAME: &str = "cz.turris.federation-tray.desktop";

#[derive(Default)]
pub struct NotebookService {
    child: Mutex<Option<Child>>,
    startup_error: Mutex<Option<String>>,
}
impl Drop for NotebookService {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            if let Some(mut process) = child.take() { let _ = process.kill(); let _ = process.wait(); }
        }
    }
}

fn scripts(data: &Path) -> Result<PathBuf, String> {
    let mut hash = DefaultHasher::new();
    SERVICE.hash(&mut hash);
    FEDERATION.hash(&mut hash);
    let directory = data.join("notebooks").join(format!("service-{:x}", hash.finish()));
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    // Immutable per-version sources: commands cannot truncate a running daemon.
    let script = directory.join("notebook_sync.py");
    if !script.exists() {
        fs::write(directory.join("federation.py"), FEDERATION).map_err(|e| e.to_string())?;
        fs::write(&script, SERVICE).map_err(|e| e.to_string())?;
    }
    Ok(script)
}

fn unit_path(config: &Path) -> PathBuf { config.join("systemd/user").join(UNIT_NAME) }

fn autostart_path(config: &Path) -> PathBuf { config.join("autostart").join(AUTOSTART_NAME) }

fn remove_tray_autostart(config: &Path) -> Result<(), String> {
    let target = autostart_path(config);
    if target.exists() {
        fs::remove_file(target).map_err(|e| e.to_string())?;
        systemctl(&["daemon-reload"])?;
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl").arg("--user").args(args).output()
        .map_err(|e| format!("Nelze spustit systemctl --user: {e}"))?;
    if output.status.success() { Ok(()) } else {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if error.is_empty() { "Uživatelskou službu nelze změnit.".into() } else { error })
    }
}

fn systemctl_succeeds(args: &[&str]) -> bool {
    Command::new("systemctl").arg("--user").args(args)
        .stdout(Stdio::null()).stderr(Stdio::null()).status()
        .map(|status| status.success()).unwrap_or(false)
}

fn service_state(config: &Path) -> Value {
    let installed = unit_path(config).exists();
    let enabled = installed && systemctl_succeeds(&["is-enabled", "--quiet", UNIT_NAME]);
    let active = installed && systemctl_succeeds(&["is-active", "--quiet", UNIT_NAME]);
    json!({"installed": installed, "enabled": enabled, "active": active, "unit": UNIT_NAME})
}

fn content_hash(contents: &[u8]) -> String { format!("{:x}", Sha256::digest(contents)) }

fn file_hash(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|contents| content_hash(&contents))
}

fn component(id: &str, label: &str, expected: String, installed: Option<String>, active: Option<bool>) -> Value {
    let state = match installed.as_deref() {
        None => "missing",
        Some(value) if value == expected => "matching",
        Some(_) => "mismatch",
    };
    json!({"id": id, "label": label, "expectedHash": expected,
           "installedHash": installed, "state": state, "active": active})
}

fn local_components(data: &Path, running_backend: Option<&str>) -> Value {
    let desktop = std::env::current_exe().ok().and_then(|path| file_hash(&path));
    let desktop_expected = desktop.clone().unwrap_or_default();
    let script = scripts(data).ok();
    let expected_backend = content_hash(SERVICE.as_bytes());
    let expected_federation = content_hash(FEDERATION.as_bytes());
    let backend_running = Some(running_backend.is_some());
    let values = vec![
        component("desktop", "Desktop a frontend", desktop_expected.clone(), desktop, Some(true)),
        component("backendRunning", "Backend této relace", expected_backend.clone(),
                  running_backend.map(str::to_string), backend_running),
        component("backendFile", "Soubor notebookového backendu", expected_backend,
                  script.as_ref().and_then(|path| file_hash(path)), None),
        component("federationLibrary", "Federační knihovna backendu", expected_federation,
                  script.as_ref().and_then(|path| file_hash(&path.with_file_name("federation.py"))), None),
    ];
    json!({"matching": values.iter().all(|value| value["state"].as_str() == Some("matching")
                                         && value["active"].as_bool() != Some(false)),
           "components": values})
}

fn remove_service(config: &Path) -> Result<(), String> {
    let target = unit_path(config);
    if target.exists() {
        systemctl(&["disable", "--now", UNIT_NAME])?;
        fs::remove_file(target).map_err(|e| e.to_string())?;
        systemctl(&["daemon-reload"])?;
    }
    Ok(())
}

fn backend_status() -> Result<Value, String> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").ok_or("Chybí XDG_RUNTIME_DIR.")?;
    let mut socket = UnixStream::connect(PathBuf::from(runtime).join("turris-federation/backend.sock"))
        .map_err(|_| "Uživatelský backend neodpovídá.".to_string())?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
    socket.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
    socket.write_all(b"{\"action\":\"status\"}\n").map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    socket.take(2 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let response: Value = serde_json::from_slice(&raw).map_err(|_| "Backend vrátil neplatný stav.".to_string())?;
    if response["ok"].as_bool() != Some(true) { return Err(response["error"].as_str().unwrap_or("Backend odmítl požadavek.").into()); }
    Ok(response)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TrayState { Connected, Limited, Disconnected, Error }

impl TrayState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "Připojeno · místní kontrola je v pořádku",
            Self::Limited => "Připojeno s omezením nebo bez aktuální kontroly",
            Self::Disconnected => "Notebook je odpojený",
            Self::Error => "Backend neběží nebo hlásí chybu",
        }
    }

    pub fn color(self) -> [u8; 3] {
        match self {
            Self::Connected => [35, 166, 92],
            Self::Limited => [230, 159, 0],
            Self::Disconnected => [120, 130, 140],
            Self::Error => [207, 61, 61],
        }
    }
}

fn tray_state_from(response: &Value, now: f64) -> TrayState {
    let status = &response["status"];
    if status["error"].is_string() || status["vpn"]["state"].as_str() == Some("error") {
        return TrayState::Error;
    }
    if status["vpn"]["state"].as_str() != Some("installed") {
        return TrayState::Disconnected;
    }
    if matches!(status["vpn"]["profileState"].as_str(), Some("missing" | "inactive")) {
        return TrayState::Disconnected;
    }
    let diagnostics = &status["vpn"]["diagnostics"];
    let fresh = diagnostics["checkedAt"].as_f64().is_some_and(|checked| now - checked <= 120.0);
    let topology_matches = status["vpn"]["topologyRevision"].as_u64()
        .is_none_or(|revision| diagnostics["revision"].as_u64() == Some(revision));
    let healthy = status["vpn"]["updateAvailable"].as_bool() != Some(true)
        && topology_matches
        && diagnostics["state"].as_str() == Some("complete")
        && diagnostics["profile"].as_str() == Some("active")
        && diagnostics["interfacePresent"].as_bool() == Some(true)
        && diagnostics["addressAssigned"].as_bool() == Some(true)
        && diagnostics["routesExpected"].as_u64() == diagnostics["routesActive"].as_u64()
        && diagnostics["forwarding"]["ipv4"].as_bool() == Some(false)
        && diagnostics["forwarding"]["ipv6"].as_bool() == Some(false)
        && diagnostics["nodes"].as_object().is_some_and(|nodes| nodes.values().all(|node| {
            node["handshakeState"].as_str() == Some("recent")
                && node["wireguard"]["successPercent"].as_f64() == Some(100.0)
        }));
    if fresh && healthy { TrayState::Connected } else { TrayState::Limited }
}

pub fn tray_state() -> TrayState {
    backend_status().map(|response| tray_state_from(&response, chrono::Utc::now().timestamp_millis() as f64 / 1000.0))
        .unwrap_or(TrayState::Error)
}

fn stop(service: &NotebookService) -> Result<(), String> {
    if let Some(mut child) = service.child.lock().map_err(|e| e.to_string())?.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

fn start(data: &Path, service: &NotebookService) -> Result<(), String> {
    stop(service)?;
    let script = scripts(data)?;
    let child = Command::new("python3").arg(script).arg("serve").arg(data)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|e| format!("Nelze spustit synchronizaci: {e}"))?;
    *service.child.lock().map_err(|e| e.to_string())? = Some(child);
    Ok(())
}

fn script_request(data: &Path, request: &Value) -> Result<Value, String> {
    let script = scripts(data)?;
    let mut child = Command::new("python3").arg(&script).arg("command").arg(data)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("Notebook potřebuje python3 a openssl: {e}"))?;
    child.stdin.take().ok_or("Chybí vstup synchronizace.")?
        .write_all(&serde_json::to_vec(request).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() { return Err(String::from_utf8_lossy(&output.stderr).trim().into()); }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

pub fn require_admin(app: &tauri::AppHandle) -> Result<(), String> {
    let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let access = script_request(&data, &json!({"action": "access_status"}))?;
    if access["state"].as_str() == Some("valid") && access["role"].as_str() == Some("administrator") { Ok(()) }
    else { Err("Operace vyžaduje platné administrátorské pověření notebooku.".into()) }
}

pub fn require_member(app: &tauri::AppHandle) -> Result<String, String> {
    let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let access = script_request(&data, &json!({"action": "access_status"}))?;
    match (access["state"].as_str(), access["role"].as_str()) {
        (Some("valid"), Some(role @ ("administrator" | "user"))) => Ok(role.into()),
        _ => Err("Operace vyžaduje platné pověření člena federace.".into()),
    }
}

fn session_backend_desired(config: Option<&Value>, access: Option<&Value>) -> bool {
    config.and_then(|value| value["enabled"].as_bool()) == Some(true)
        || matches!(
            access.map(|value| (value["state"].as_str(), value["role"].as_str())),
            Some((Some("valid"), Some("administrator" | "user")))
        )
}

pub fn resume(data: &Path, _config_dir: &Path, service: &NotebookService) {
    let config = fs::read(data.join("notebooks/config.json")).ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
    let access = script_request(data, &json!({"action": "access_status"})).ok();
    if !session_backend_desired(config.as_ref(), access.as_ref()) { return; }
    let error = start(data, service).err()
        .map(|error| format!("Backend této relace se nepodařilo spustit: {error}"));
    if let Ok(mut current) = service.startup_error.lock() {
        *current = error;
    }
}

#[tauri::command]
pub async fn notebook_action(request: Value, app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
        let config_dir = app.path().config_dir().map_err(|e| e.to_string())?;
        let service = app.state::<NotebookService>();
        let action = request["action"].as_str().ok_or("Chybí operace.")?;
        if !["status", "access_status", "bootstrap_admin", "network_enrollment_start", "network_enrollment_status", "network_enrollment_configure", "network_enrollment_approve_request", "network_enrollment_approve_address", "enrollment_request", "issue_user_join_grant", "accept_user_join_grant", "enrollment_address_confirmation", "issue_user_invitation", "accept_user_invitation", "revoke_user_notebook", "topology_update_export", "topology_refresh_plan", "topology_refresh_apply", "vpn_plan", "vpn_install", "vpn_rollback", "vpn_status", "vpn_diagnostics", "configure", "stop", "disconnect", "pair", "unpair", "resolve", "manual", "service_remove", "backend_status"].contains(&action) {
            return Err("Neznámá operace notebooku.".into());
        }
        // Serialize commands, including config/status updates, without blocking the UI.
        let gate = app.state::<NotebookCommandGate>();
        let _guard = gate.0.lock().map_err(|e| e.to_string())?;
        if action == "service_remove" {
            remove_service(&config_dir)?;
            remove_tray_autostart(&config_dir)?;
            let enabled = fs::read(data.join("notebooks/config.json")).ok()
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                .and_then(|config| config["enabled"].as_bool()).unwrap_or(false);
            if enabled { start(&data, &service)?; }
            *service.startup_error.lock().map_err(|e| e.to_string())? = None;
            return Ok(json!({"service": service_state(&config_dir)}));
        }
        if action == "backend_status" {
            let mut result = backend_status()?;
            result["service"] = service_state(&config_dir);
            return Ok(result);
        }
        let mut result = script_request(&data, &request)?;
        if action == "network_enrollment_start" {
            stop(&service)?;
            start(&data, &service)?;
            result["serviceError"] = json!(
                "Automatické párování běží pouze po dobu otevřené desktopové aplikace."
            );
            result["service"] = service_state(&config_dir);
        }
        if action == "accept_user_join_grant" {
            let network_id = result["networkId"].as_str().ok_or("Povolení neobsahuje Network ID.")?;
            let status = crate::zerotier::notebook_join(network_id)?;
            result["zerotier"] = serde_json::to_value(status).map_err(|e| e.to_string())?;
        }
        if action == "accept_user_invitation" {
            stop(&service)?;
            start(&data, &service)?;
        } else if action == "configure" {
            stop(&service)?;
            start(&data, &service)?;
        } else if action == "stop" || action == "disconnect" {
            stop(&service)?;
        }
        let child_running = service.child.lock().map_err(|e| e.to_string())?.as_mut()
            .map(|child| child.try_wait().map(|status| status.is_none()).unwrap_or(false)).unwrap_or(false);
        let configured = result["config"]["enabled"].as_bool() == Some(true);
        let running = configured && child_running;
        result["running"] = json!(running);
        result["service"] = service_state(&config_dir);
        let running_backend = backend_status().ok()
            .and_then(|response| response["status"]["software"]["version"].as_str().map(str::to_string));
        result["localComponents"] = local_components(&data, running_backend.as_deref());
        if let Some(error) = service.startup_error.lock().ok().and_then(|value| value.clone()) {
            result["serviceError"] = json!(error);
        }
        Ok(result)
    }).await.map_err(|e| e.to_string())?
}

#[derive(Default)]
pub struct NotebookCommandGate(pub Mutex<()>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_manifest_distinguishes_matching_mismatched_and_missing_files() {
        let expected = content_hash(b"expected");
        let matching = component("matching", "Matching", expected.clone(), Some(expected.clone()), Some(true));
        let mismatch = component("mismatch", "Mismatch", expected.clone(), Some(content_hash(b"old")), Some(true));
        let missing = component("missing", "Missing", expected, None, None);
        assert_eq!(matching["state"], "matching");
        assert_eq!(mismatch["state"], "mismatch");
        assert_eq!(missing["state"], "missing");
        assert_eq!(content_hash(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn valid_existing_member_uses_only_session_backend() {
        let disabled = json!({"enabled": false});
        let user = json!({"state": "valid", "role": "user"});
        let administrator = json!({"state": "valid", "role": "administrator"});
        let invalid = json!({"state": "invalid", "role": "user"});
        assert!(session_backend_desired(Some(&disabled), Some(&user)));
        assert!(session_backend_desired(Some(&disabled), Some(&administrator)));
        assert!(!session_backend_desired(Some(&disabled), Some(&invalid)));
        assert!(session_backend_desired(Some(&json!({"enabled": true})), None));
    }

    #[test]
    fn tray_state_requires_fresh_healthy_local_diagnostics() {
        let healthy = json!({"status": {"vpn": {"state": "installed", "updateAvailable": false,
            "topologyRevision": 3, "diagnostics": {
            "revision": 3, "state": "complete", "checkedAt": 950.0, "profile": "active",
            "interfacePresent": true, "addressAssigned": true,
            "routesExpected": 2, "routesActive": 2,
            "forwarding": {"ipv4": false, "ipv6": false},
            "nodes": {"router": {"handshakeState": "recent", "wireguard": {"successPercent": 100.0}}}
        }}}});
        assert_eq!(TrayState::Connected, tray_state_from(&healthy, 1000.0));
        assert_eq!(TrayState::Limited, tray_state_from(&healthy, 1100.0));
        let mut update = healthy.clone();
        update["status"]["vpn"]["updateAvailable"] = json!(true);
        assert_eq!(TrayState::Limited, tray_state_from(&update, 1000.0));
        let mut stale_revision = healthy.clone();
        stale_revision["status"]["vpn"]["diagnostics"]["revision"] = json!(2);
        assert_eq!(TrayState::Limited, tray_state_from(&stale_revision, 1000.0));
        let mut missing_profile = healthy.clone();
        missing_profile["status"]["vpn"]["profileState"] = json!("missing");
        assert_eq!(TrayState::Disconnected, tray_state_from(&missing_profile, 1000.0));
        let disconnected = json!({"status": {"vpn": {"state": "rolled_back"}}});
        assert_eq!(TrayState::Disconnected, tray_state_from(&disconnected, 1000.0));
        let error = json!({"status": {"error": "sync failed", "vpn": {"state": "installed"}}});
        assert_eq!(TrayState::Error, tray_state_from(&error, 1000.0));
    }
}
