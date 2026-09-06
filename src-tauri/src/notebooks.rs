use serde_json::{json, Value};
use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, fs, io::Write, path::{Path, PathBuf}, process::{Child, Command, Stdio}, sync::Mutex};
use tauri::Manager;

const SERVICE: &str = include_str!("../../scripts/notebook_sync.py");
const FEDERATION: &str = include_str!("../../router/files/usr/lib/turris-federation/federation.py");

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

pub fn resume(data: &Path, service: &NotebookService) {
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
        let service = app.state::<NotebookService>();
        let action = request["action"].as_str().ok_or("Chybí operace.")?;
        if !["status", "configure", "stop", "pair", "unpair", "resolve", "manual"].contains(&action) {
            return Err("Neznámá operace notebooku.".into());
        }
        // Serialize commands, including config/status updates, without blocking the UI.
        let gate = app.state::<NotebookCommandGate>();
        let _guard = gate.0.lock().map_err(|e| e.to_string())?;
        let script = scripts(&data)?;
        let mut child = Command::new("python3").arg(&script).arg("command").arg(&data)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().map_err(|e| format!("Notebook potřebuje python3 a openssl: {e}"))?;
        child.stdin.take().ok_or("Chybí vstup synchronizace.")?
            .write_all(&serde_json::to_vec(&request).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() { return Err(String::from_utf8_lossy(&output.stderr).trim().into()); }
        let mut result: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
        if action == "configure" { start(&data, &service)?; }
        if action == "stop" { stop(&service)?; }
        let running = service.0.lock().map_err(|e| e.to_string())?.as_mut()
            .map(|child| child.try_wait().map(|status| status.is_none()).unwrap_or(false)).unwrap_or(false);
        result["running"] = json!(running);
        Ok(result)
    }).await.map_err(|e| e.to_string())?
}

#[derive(Default)]
pub struct NotebookCommandGate(pub Mutex<()>);
