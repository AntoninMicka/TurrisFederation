use serde_json::{json, Value};
use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, fs, io::{Read, Write}, os::unix::{fs::PermissionsExt, net::UnixStream}, path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::Mutex, time::Duration};
use tauri::Manager;

const SERVICE: &str = include_str!("../../scripts/notebook_sync.py");
const FEDERATION: &str = include_str!("../../router/files/usr/lib/turris-federation/federation.py");
const UNIT_NAME: &str = "turris-federation-backend.service";
const AUTOSTART_NAME: &str = "cz.turris.federation-tray.desktop";
const TRAY_EXECUTABLE_ENV: &str = "TF_TRAY_EXECUTABLE";

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

fn quote_unit_path(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("Cesta služby není platné UTF-8.")?;
    if value.chars().any(char::is_control) { return Err("Cesta služby obsahuje řídicí znak.".into()); }
    Ok(format!("\"{}\"", value.replace('%', "%%").replace('\\', "\\\\").replace('"', "\\\"")))
}

fn unit_contents(data: &Path, script: &Path) -> Result<String, String> {
    let python = Path::new("/usr/bin/python3");
    if !python.exists() { return Err("Chybí /usr/bin/python3 pro uživatelskou službu.".into()); }
    Ok(format!("[Unit]\nDescription=Turris Federation notebook backend\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} {} serve {}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nRuntimeDirectory=turris-federation\nEnvironment=TF_BACKEND_SOCKET=%t/turris-federation/backend.sock\nNoNewPrivileges=true\nRestrictNamespaces=true\nRestrictSUIDSGID=true\nLockPersonality=true\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\n[Install]\nWantedBy=default.target\n",
        quote_unit_path(python)?, quote_unit_path(script)?, quote_unit_path(data)?))
}

fn unit_path(config: &Path) -> PathBuf { config.join("systemd/user").join(UNIT_NAME) }

fn autostart_path(config: &Path) -> PathBuf { config.join("autostart").join(AUTOSTART_NAME) }

fn quote_desktop_exec(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("Cesta klienta stavové lišty není platné UTF-8.")?;
    if value.chars().any(char::is_control) { return Err("Cesta klienta stavové lišty obsahuje řídicí znak.".into()); }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"").replace('`', "\\`").replace('$', "\\$")))
}

fn autostart_contents(executable: &Path) -> Result<String, String> {
    let executable = quote_desktop_exec(executable)?;
    // TryExec is a plain string in the desktop-entry specification, not an
    // Exec field. Quoting an absolute path there makes systemd's XDG generator
    // look for a filename which literally contains quote characters. Exec is
    // sufficient and remains safe for paths containing spaces.
    Ok(format!("[Desktop Entry]\nType=Application\nName=Turris Federation\nComment=Stav federovaného připojení\nExec={executable} --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"))
}

fn validate_tray_executable(executable: PathBuf) -> Result<PathBuf, String> {
    if !executable.is_absolute() {
        return Err("Cesta klienta stavové lišty musí být absolutní.".into());
    }
    let executable = fs::canonicalize(&executable)
        .map_err(|e| format!("Klient stavové lišty {} není dostupný: {e}", executable.display()))?;
    let metadata = fs::metadata(&executable).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("Klient stavové lišty {} není spustitelný soubor.", executable.display()));
    }
    Ok(executable)
}

fn tray_executable() -> Result<PathBuf, String> {
    let executable = match std::env::var_os(TRAY_EXECUTABLE_ENV) {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()
            .map_err(|e| format!("Nelze zjistit cestu klienta stavové lišty: {e}"))?,
    };
    validate_tray_executable(executable)
}

fn install_tray_autostart(config: &Path) -> Result<(), String> {
    let target = autostart_path(config);
    let parent = target.parent().ok_or("Chybí adresář automatického spuštění.")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let executable = tray_executable()?;
    let temporary = parent.join(format!(".{AUTOSTART_NAME}.tmp-{}", std::process::id()));
    fs::write(&temporary, autostart_contents(&executable)?).map_err(|e| e.to_string())?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
    fs::rename(&temporary, &target).map_err(|e| e.to_string())?;
    // With user lingering enabled, the user manager survives logout. Its XDG
    // autostart generator therefore does not discover a newly created desktop
    // entry at the next login unless the manager configuration is reloaded.
    systemctl(&["daemon-reload"])
}

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

fn install_service(data: &Path, config: &Path) -> Result<(), String> {
    let script = scripts(data)?;
    let target = unit_path(config);
    let parent = target.parent().ok_or("Chybí adresář uživatelské služby.")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let previous = fs::read(&target).ok();
    let previous_enabled = systemctl_succeeds(&["is-enabled", "--quiet", UNIT_NAME]);
    let previous_active = systemctl_succeeds(&["is-active", "--quiet", UNIT_NAME]);
    let temporary = parent.join(format!(".{UNIT_NAME}.tmp-{}", std::process::id()));
    fs::write(&temporary, unit_contents(data, &script)?).map_err(|e| e.to_string())?;
    fs::rename(&temporary, &target).map_err(|e| e.to_string())?;
    // `enable --now` does not restart an already running unit after its
    // ExecStart changed. Enable and restart separately so a stale development
    // or Snap revision path is replaced immediately and configuration changes
    // take effect in the persistent backend.
    let result = systemctl(&["daemon-reload"])
        .and_then(|_| systemctl(&["enable", UNIT_NAME]))
        .and_then(|_| systemctl(&["restart", UNIT_NAME]));
    if let Err(error) = result {
        if let Some(contents) = previous.as_ref() {
            let _ = fs::write(&target, contents);
        } else {
            // Remove the wants symlink while the unit still contains its
            // [Install] metadata; otherwise a failed first install leaves a
            // dangling enabled unit behind.
            let _ = systemctl(&["disable", "--now", UNIT_NAME]);
            let _ = fs::remove_file(&target);
        }
        let _ = systemctl(&["daemon-reload"]);
        if previous.is_some() {
            let _ = if previous_enabled { systemctl(&["enable", UNIT_NAME]) }
                else { systemctl(&["disable", UNIT_NAME]) };
            let _ = if previous_active { systemctl(&["restart", UNIT_NAME]) }
                else { systemctl(&["stop", UNIT_NAME]) };
        }
        return Err(error);
    }
    Ok(())
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

fn persistent_backend_requires_reconcile(
    backend_desired: bool, unit_matches: bool, unit_enabled: bool, unit_active: bool,
) -> bool {
    backend_desired && (!unit_matches || !unit_enabled || !unit_active)
}

fn persistent_backend_desired(config: Option<&Value>, access: Option<&Value>, unit_exists: bool) -> bool {
    unit_exists
        || config.and_then(|value| value["enabled"].as_bool()) == Some(true)
        || matches!(
            access.map(|value| (value["state"].as_str(), value["role"].as_str())),
            Some((Some("valid"), Some("administrator" | "user")))
        )
}

pub fn resume(data: &Path, config_dir: &Path, service: &NotebookService) {
    let config = fs::read(data.join("notebooks/config.json")).ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
    // A user notebook needs the persistent local backend even though it never
    // enables administrator-to-administrator discovery. Once installed, the
    // unit itself records that intent; legacy administrators additionally use
    // config.enabled as the migration signal.
    let access = script_request(data, &json!({"action": "access_status"})).ok();
    let backend_desired = persistent_backend_desired(
        config.as_ref(), access.as_ref(), unit_path(config_dir).exists(),
    );
    if !backend_desired { return; }
    let mut startup_errors = Vec::new();
    if let Err(error) = install_tray_autostart(config_dir) {
        startup_errors.push(format!("Automatické spuštění ikony se nepodařilo nastavit: {error}"));
    }
    let unit_matches = scripts(data).and_then(|script| unit_contents(data, &script))
        .ok().is_some_and(|expected| fs::read_to_string(unit_path(config_dir)).ok().as_deref() == Some(expected.as_str()));
    let state = service_state(config_dir);
    if persistent_backend_requires_reconcile(
        backend_desired, unit_matches,
        state["enabled"].as_bool() == Some(true), state["active"].as_bool() == Some(true),
    ) {
        // Reconcile missing, disabled, stopped and stale units. In particular,
        // development launches can inherit a revision-specific Snap data path,
        // which must not remain in ExecStart after the application moves.
        if let Err(error) = install_service(data, config_dir) {
            startup_errors.push(format!("Trvalou uživatelskou službu se nepodařilo nainstalovat: {error}"));
            // Preserve the previous same-session behaviour; the UI exposes
            // that the persistent service still needs repair.
            if state["active"].as_bool() != Some(true) { let _ = start(data, service); }
        }
    }
    if let Ok(mut current) = service.startup_error.lock() {
        *current = if startup_errors.is_empty() { None } else { Some(startup_errors.join(" ")) };
    }
}

#[tauri::command]
pub async fn notebook_action(request: Value, app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
        let config_dir = app.path().config_dir().map_err(|e| e.to_string())?;
        let service = app.state::<NotebookService>();
        let action = request["action"].as_str().ok_or("Chybí operace.")?;
        if !["status", "access_status", "bootstrap_admin", "network_enrollment_start", "network_enrollment_status", "network_enrollment_approve_request", "network_enrollment_approve_address", "enrollment_request", "issue_user_join_grant", "accept_user_join_grant", "enrollment_address_confirmation", "issue_user_invitation", "accept_user_invitation", "revoke_user_notebook", "topology_update_export", "topology_refresh_plan", "topology_refresh_apply", "vpn_plan", "vpn_install", "vpn_rollback", "vpn_status", "vpn_diagnostics", "configure", "stop", "disconnect", "pair", "unpair", "resolve", "manual", "service_install", "service_remove", "backend_status"].contains(&action) {
            return Err("Neznámá operace notebooku.".into());
        }
        // Serialize commands, including config/status updates, without blocking the UI.
        let gate = app.state::<NotebookCommandGate>();
        let _guard = gate.0.lock().map_err(|e| e.to_string())?;
        if action == "service_install" {
            stop(&service)?;
            if let Err(error) = install_service(&data, &config_dir) {
                let enabled = fs::read(data.join("notebooks/config.json")).ok()
                    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                    .and_then(|config| config["enabled"].as_bool()).unwrap_or(false);
                if enabled { let _ = start(&data, &service); }
                return Err(error);
            }
            install_tray_autostart(&config_dir)
                .map_err(|error| format!("Backendová služba běží, ale automatický start ikony se nepodařilo nastavit: {error}"))?;
            *service.startup_error.lock().map_err(|e| e.to_string())? = None;
            return Ok(json!({"service": service_state(&config_dir)}));
        }
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
            // The LAN listener must outlive this one-shot command. Prefer the
            // persistent user unit; if systemd is unavailable, keep the
            // current desktop session usable through the child backend.
            stop(&service)?;
            match install_service(&data, &config_dir) {
                Err(error) => {
                    start(&data, &service)?;
                    result["serviceError"] = json!(format!(
                        "Automatické párování poběží jen s otevřenou aplikací: {error}"
                    ));
                }
                Ok(()) => {
                    if let Err(error) = install_tray_autostart(&config_dir) {
                        result["serviceError"] = json!(format!(
                            "Backend běží, ale automatický start ikony se nepodařilo nastavit: {error}"
                        ));
                    }
                }
            }
            result["service"] = service_state(&config_dir);
        }
        if action == "accept_user_join_grant" {
            let network_id = result["networkId"].as_str().ok_or("Povolení neobsahuje Network ID.")?;
            let status = crate::zerotier::notebook_join(network_id)?;
            result["zerotier"] = serde_json::to_value(status).map_err(|e| e.to_string())?;
        }
        let mut service_error = None;
        if action == "accept_user_invitation" {
            stop(&service)?;
            if let Err(error) = install_service(&data, &config_dir) {
                // Enrollment and credential persistence have already
                // succeeded. Keep the UI usable and report the independently
                // repairable service failure instead of making the one-time
                // invitation appear reusable.
                let _ = start(&data, &service);
                service_error = Some(format!(
                    "Členství bylo přijato, ale trvalou službu se nepodařilo nainstalovat: {error}"
                ));
            } else if let Err(error) = install_tray_autostart(&config_dir) {
                service_error = Some(format!(
                    "Backendová služba běží, ale automatický start ikony se nepodařilo nastavit: {error}"
                ));
            }
        } else if action == "configure" {
            stop(&service)?;
            if let Err(error) = install_service(&data, &config_dir) {
                let _ = start(&data, &service);
                return Err(format!(
                    "Nastavení bylo uloženo, ale automatický start backendu se nepodařilo zapnout: {error}"
                ));
            }
            install_tray_autostart(&config_dir)
                .map_err(|error| format!("Backendová služba běží, ale automatický start ikony se nepodařilo nastavit: {error}"))?;
        } else if action == "stop" || action == "disconnect" {
            if unit_path(&config_dir).exists() {
                if action == "disconnect" { systemctl(&["stop", UNIT_NAME])?; }
                else { systemctl(&["restart", UNIT_NAME])?; }
            } else {
                stop(&service)?;
            }
        }
        let child_running = service.child.lock().map_err(|e| e.to_string())?.as_mut()
            .map(|child| child.try_wait().map(|status| status.is_none()).unwrap_or(false)).unwrap_or(false);
        let configured = result["config"]["enabled"].as_bool() == Some(true);
        let running = configured && (child_running || service_state(&config_dir)["active"].as_bool() == Some(true));
        result["running"] = json!(running);
        result["service"] = service_state(&config_dir);
        if let Some(error) = service_error.or_else(|| service.startup_error.lock().ok().and_then(|value| value.clone())) {
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
    fn user_unit_is_unprivileged_private_and_restartable() {
        let data = Path::new("/home/test user/.local/share/cz.turris.federation");
        let script = data.join("notebooks/service-a/notebook_sync.py");
        let unit = unit_contents(data, &script).unwrap();
        assert!(unit.contains("ExecStart=\"/usr/bin/python3\" \"/home/test user/.local/share/cz.turris.federation/notebooks/service-a/notebook_sync.py\" serve"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("UMask=0077"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("RestrictNamespaces=true"));
        assert!(unit.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"));
        assert!(!unit.contains("ProtectSystem="));
        assert!(!unit.contains("ProtectHome="));
        assert!(!unit.contains("PrivateTmp="));
        assert!(unit.contains("TF_BACKEND_SOCKET=%t/turris-federation/backend.sock"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("User=root"));
        assert_eq!(quote_unit_path(Path::new("/tmp/100% ready")).unwrap(), "\"/tmp/100%% ready\"");
        assert!(quote_unit_path(Path::new("/tmp/bad\nunit")).is_err());
    }

    #[test]
    fn tray_autostart_uses_background_mode_and_quotes_executable() {
        let entry = autostart_contents(Path::new("/home/test user/Turris $Federation")).unwrap();
        assert!(entry.contains("Exec=\"/home/test user/Turris \\$Federation\" --background"));
        assert!(!entry.contains("TryExec="));
        assert!(entry.contains("X-GNOME-Autostart-enabled=true"));
        assert!(quote_desktop_exec(Path::new("/tmp/bad\nentry")).is_err());
    }

    #[test]
    fn tray_executable_must_be_absolute_and_executable() {
        assert!(validate_tray_executable(PathBuf::from("relative/client")).is_err());
        assert!(validate_tray_executable(PathBuf::from("/definitely/missing/turris-federation")).is_err());
        assert!(validate_tray_executable(std::env::current_exe().unwrap()).is_ok());
    }

    #[test]
    fn configured_legacy_backend_requires_persistent_service_installation() {
        assert!(persistent_backend_requires_reconcile(true, false, false, false));
        assert!(persistent_backend_requires_reconcile(true, true, false, false));
        assert!(persistent_backend_requires_reconcile(true, true, true, false));
        assert!(!persistent_backend_requires_reconcile(true, true, true, true));
        assert!(!persistent_backend_requires_reconcile(false, false, false, false));
    }

    #[test]
    fn valid_existing_member_requires_service_even_without_admin_sync_config() {
        let disabled = json!({"enabled": false});
        let user = json!({"state": "valid", "role": "user"});
        let administrator = json!({"state": "valid", "role": "administrator"});
        let invalid = json!({"state": "invalid", "role": "user"});
        assert!(persistent_backend_desired(Some(&disabled), Some(&user), false));
        assert!(persistent_backend_desired(Some(&disabled), Some(&administrator), false));
        assert!(!persistent_backend_desired(Some(&disabled), Some(&invalid), false));
        assert!(persistent_backend_desired(Some(&disabled), None, true));
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
