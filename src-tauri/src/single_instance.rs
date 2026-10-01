use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::{FileTypeExt, PermissionsExt}, net::{UnixListener, UnixStream}},
    path::{Path, PathBuf},
    time::Duration,
};
use tauri::Manager;

pub enum Instance {
    Primary,
    Secondary,
}

fn socket_path() -> Result<PathBuf, String> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or("Chybí XDG_RUNTIME_DIR pro zámek jediné instance UI.")?;
    Ok(PathBuf::from(runtime).join("turris-federation").join("ui.sock"))
}

fn connect(path: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else { return false };
    stream.set_write_timeout(Some(Duration::from_secs(1))).ok();
    stream.write_all(b"show\n").is_ok()
}

pub fn acquire(app: &tauri::AppHandle) -> Result<Instance, String> {
    let path = socket_path()?;
    let directory = path.parent().ok_or("Chybí adresář zámku UI.")?;
    if directory.is_symlink() {
        return Err("Adresář zámku UI nesmí být symbolický odkaz.".into());
    }
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;

    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(_) if connect(&path) => return Ok(Instance::Secondary),
        Err(_) => {
            // The previous process may have crashed. Remove only our exact socket.
            if path.symlink_metadata().map(|m| m.file_type().is_socket()).unwrap_or(false) {
                fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
            UnixListener::bind(&path).map_err(|e| format!("Nelze vytvořit zámek UI: {e}"))?
        }
    };
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let handle = app.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { break };
            stream.set_read_timeout(Some(Duration::from_secs(1))).ok();
            let mut request = [0_u8; 5];
            if stream.read_exact(&mut request).is_ok() && &request == b"show\n" {
                if let Some(window) = handle.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
        }
    });
    Ok(Instance::Primary)
}
