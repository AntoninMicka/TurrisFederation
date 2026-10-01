use serde_json::{json, Value};
use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, fs, io::{Read, Write}, os::unix::net::UnixStream, path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::Mutex, time::Duration};
use tauri::Manager;

const SERVICE: &str = include_str!("../../scripts/notebook_sync.py");
const FEDERATION: &str = include_str!("../../router/files/usr/lib/turris-federation/federation.py");
const UNIT_NAME: &str = "turris-federation-backend.service";

#[derive(Default)]
pub struct NotebookService(pub Mutex<Option<Child>>);
impl Drop for NotebookService {
    fn drop(&mut self) {
        if let Ok(child) = self.0.get_mut() {
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
    Ok(format!("[Unit]\nDescription=Turris Federation notebook backend\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} {} serve {}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nRuntimeDirectory=turris-federation\nEnvironment=TF_BACKEND_SOCKET=%t/turris-federation/backend.sock\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths={}\n\n[Install]\nWantedBy=default.target\n",
        quote_unit_path(python)?, quote_unit_path(script)?, quote_unit_path(data)?, quote_unit_path(data)?))
}

fn unit_path(config: &Path) -> PathBuf { config.join("systemd/user").join(UNIT_NAME) }

fn systemctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl").arg("--user").args(args).output()
        .map_err(|e| format!("Nelze spustit systemctl --user: {e}"))?;
    if output.status.success() { Ok(()) } else {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if error.is_empty() { "Uživatelskou službu nelze změnit.".into() } else { error })
    }
}

fn service_state(config: &Path) -> Value {
    let installed = unit_path(config).exists();
    let active = installed && Command::new("systemctl").args(["--user", "is-active", "--quiet", UNIT_NAME])
        .status().map(|status| status.success()).unwrap_or(false);
    json!({"installed": installed, "active": active, "unit": UNIT_NAME})
}

fn install_service(data: &Path, config: &Path) -> Result<(), String> {
    let script = scripts(data)?;
    let target = unit_path(config);
    let parent = target.parent().ok_or("Chybí adresář uživatelské služby.")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let previous = fs::read(&target).ok();
    let temporary = parent.join(format!(".{UNIT_NAME}.tmp-{}", std::process::id()));
    fs::write(&temporary, unit_contents(data, &script)?).map_err(|e| e.to_string())?;
    fs::rename(&temporary, &target).map_err(|e| e.to_string())?;
    let result = systemctl(&["daemon-reload"]).and_then(|_| systemctl(&["enable", "--now", UNIT_NAME]));
    if let Err(error) = result {
        if let Some(contents) = previous { let _ = fs::write(&target, contents); }
        else { let _ = fs::remove_file(&target); }
        let _ = systemctl(&["daemon-reload"]);
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

pub fn indicator() -> String {
    match backend_status() {
        Ok(response) if response["status"]["error"].is_string() => "Backend: omezený provoz".into(),
        Ok(response) if response["status"]["config"]["enabled"].as_bool() == Some(true) => "Backend: běží a synchronizuje".into(),
        Ok(_) => "Backend: běží, synchronizace vypnutá".into(),
        Err(_) => "Backend: neběží".into(),
    }
}

fn stop(service: &NotebookService) -> Result<(), String> {
    if let Some(mut child) = service.0.lock().map_err(|e| e.to_string())?.take() {
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
    *service.0.lock().map_err(|e| e.to_string())? = Some(child);
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

pub fn resume(data: &Path, config_dir: &Path, service: &NotebookService) {
    if unit_path(config_dir).exists() { return; }
    let config = fs::read(data.join("notebooks/config.json")).ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
    if config.as_ref().and_then(|c| c["enabled"].as_bool()) == Some(true) {
        let _ = start(data, service);
    }
}

#[tauri::command]
pub async fn notebook_action(request: Value, app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
        let config_dir = app.path().config_dir().map_err(|e| e.to_string())?;
        let service = app.state::<NotebookService>();
        let action = request["action"].as_str().ok_or("Chybí operace.")?;
        if !["status", "access_status", "bootstrap_admin", "configure", "stop", "pair", "unpair", "resolve", "manual", "service_install", "service_remove", "backend_status"].contains(&action) {
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
            return Ok(json!({"service": service_state(&config_dir)}));
        }
        if action == "service_remove" {
            remove_service(&config_dir)?;
            let enabled = fs::read(data.join("notebooks/config.json")).ok()
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                .and_then(|config| config["enabled"].as_bool()).unwrap_or(false);
            if enabled { start(&data, &service)?; }
            return Ok(json!({"service": service_state(&config_dir)}));
        }
        if action == "backend_status" {
            let mut result = backend_status()?;
            result["service"] = service_state(&config_dir);
            return Ok(result);
        }
        let mut result = script_request(&data, &request)?;
        if action == "configure" || action == "stop" {
            if unit_path(&config_dir).exists() {
                systemctl(&["restart", UNIT_NAME])?;
            } else if action == "configure" {
                start(&data, &service)?;
            } else {
                stop(&service)?;
            }
        }
        let child_running = service.0.lock().map_err(|e| e.to_string())?.as_mut()
            .map(|child| child.try_wait().map(|status| status.is_none()).unwrap_or(false)).unwrap_or(false);
        let configured = result["config"]["enabled"].as_bool() == Some(true);
        let running = configured && (child_running || service_state(&config_dir)["active"].as_bool() == Some(true));
        result["running"] = json!(running);
        result["service"] = service_state(&config_dir);
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
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("TF_BACKEND_SOCKET=%t/turris-federation/backend.sock"));
        assert!(!unit.contains("User=root"));
        assert_eq!(quote_unit_path(Path::new("/tmp/100% ready")).unwrap(), "\"/tmp/100%% ready\"");
        assert!(quote_unit_path(Path::new("/tmp/bad\nunit")).is_err());
    }
}
