use serde::Serialize;
use std::{fs, path::{Path, PathBuf}, process::{Output, Stdio}, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostIdentity {
    pub host_key: String,
    pub fingerprints: String,
    pub trust: String,
}

pub fn validate(host: &str, user: &str, port: u16) -> Result<(), String> {
    if host.is_empty() || host.starts_with('-') || !host.bytes().all(|c| c.is_ascii_alphanumeric() || b".-:_%".contains(&c))
        || user.is_empty() || user.starts_with('-') || !user.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) || port == 0 {
        return Err("Vyplňte platnou SSH adresu (bez ssh://), uživatele a port 1–65535.".into());
    }
    Ok(())
}

pub fn check_trust(saved: Option<&str>, keys: &str, confirmed: bool) -> Result<(), String> {
    if saved != Some(keys) && !confirmed {
        return Err("Nejdřív potvrďte otisk SSH klíče routeru.".into());
    }
    Ok(())
}

async fn output(mut command: Command, input: Option<&[u8]>, seconds: u64) -> Result<Output, String> {
    command.kill_on_drop(true).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| format!("SSH nástroj nelze spustit: {e}. Spusťte znovu ./run.sh pro doplnění závislostí."))?;
    if let Some(bytes) = input {
        let mut stdin = child.stdin.take().ok_or("Chybí vstup SSH procesu.")?;
        stdin.write_all(bytes).await.map_err(|e| format!("Nelze předat vstup SSH procesu: {e}"))?;
    }
    timeout(Duration::from_secs(seconds), child.wait_with_output()).await
        .map_err(|_| "SSH překročilo časový limit. Ověřte adresu, port a dostupnost routeru.".to_string())?
        .map_err(|e| format!("SSH proces selhal: {e}"))
}

// Každé připojení používá vlastní soubor; jiný pokus nesmí změnit jeho důvěru.
struct KeyFile(PathBuf);
impl KeyFile {
    fn new(dir: &Path, keys: &str) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("probe-{}.known_hosts", Uuid::new_v4()));
        fs::write(&path, keys).map_err(|e| e.to_string())?;
        Ok(Self(path))
    }
}
impl Drop for KeyFile {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

pub fn canonical_keys(text: &str, host: &str, port: u16) -> Result<String, String> {
    let expected = if port == 22 { host.to_string() } else { format!("[{host}]:{port}") };
    let mut keys = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || fields[0] != expected
            || !["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"].contains(&fields[1])
            || !fields[2].bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c)) {
            return Err("Router vrátil neplatný SSH klíč.".into());
        }
        keys.push(fields.join(" "));
    }
    keys.sort(); keys.dedup();
    if keys.is_empty() { return Err("Router neposkytl SSH klíč. Ověřte adresu, port a dostupnost SSH.".into()); }
    Ok(keys.join("\n") + "\n")
}

pub async fn inspect(dir: &Path, saved: Option<&str>, host: &str, port: u16) -> Result<HostIdentity, String> {
    let mut scan = Command::new("ssh-keyscan");
    scan.args(["-T", "5", "-p", &port.to_string(), "-t", "ed25519,ecdsa,rsa", "--", host]);
    let result = output(scan, None, 20).await?;
    let host_key = canonical_keys(&String::from_utf8_lossy(&result.stdout), host, port)?;
    let file = KeyFile::new(dir, &host_key)?;
    let mut fingerprint = Command::new("ssh-keygen");
    fingerprint.args(["-l", "-E", "sha256", "-f"]).arg(&file.0);
    let result = output(fingerprint, None, 5).await?;
    if !result.status.success() { return Err("Otisk SSH klíče nelze ověřit.".into()); }
    let trust = match saved { None => "new", Some(key) if key == host_key => "trusted", Some(_) => "changed" };
    Ok(HostIdentity { host_key, fingerprints: String::from_utf8_lossy(&result.stdout).trim().into(), trust: trust.into() })
}

fn ssh_command(host: &str, user: &str, port: u16, key_file: &Path, probe: &str) -> Command {
    let mut command = Command::new("sshpass");
    command.args(["-d", "0", "ssh", "-F", "/dev/null", "-T", "-n", "-o", "BatchMode=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=keyboard-interactive,password", "-o"])
        .arg(format!("UserKnownHostsFile={}", key_file.display()))
        .args(["-p", &port.to_string(), "-l", user, "--", host, probe]);
    command
}

pub async fn execute(dir: &Path, host: &str, user: &str, port: u16, password: &str, keys: &str, probe: &str, seconds: u64) -> Result<String, String> {
    validate(host, user, port)?;
    if password.is_empty() || password.len() > 4096 || password.contains(['\n', '\r', '\0']) { return Err("Zadejte heslo o délce 1–4096 bajtů bez řídicích znaků nového řádku.".into()); }
    let file = KeyFile::new(dir, keys)?;
    let command = ssh_command(host, user, port, &file.0, probe);
    let input = format!("{password}\n");
    let result = output(command, Some(input.as_bytes()), seconds).await?;
    if !result.status.success() {
        let detail = String::from_utf8_lossy(&result.stderr);
        let summary = if result.status.code() == Some(5) || detail.contains("Permission denied") {
            "Přihlášení bylo odmítnuto. Ověřte uživatele, heslo a povolení přihlášení heslem na routeru."
        } else if detail.contains("Host key verification failed") || detail.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
            "SSH klíč routeru se změnil. Znovu načtěte a ověřte jeho otisk."
        } else { "SSH připojení nebo vzdálený příkaz selhal. Podrobnosti:" };
        return Err(format!("{summary}\n{}", detail.trim()));
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_options_and_shell_input() {
        for host in ["-oProxyCommand=id", "router;id", "a@router", "$(id)", "host\nother"] { assert!(validate(host, "root", 22).is_err()); }
        assert!(validate("router", "-root", 22).is_err());
        assert!(validate("router", "root", 0).is_err());
        assert!(validate("2001:db8::1", "root", 2222).is_ok());
    }
    #[test]
    fn keys_are_scoped_to_host_and_port() {
        assert!(canonical_keys("other ssh-ed25519 AAAA", "router", 22).is_err());
        assert!(canonical_keys("router ssh-ed25519 AAAA", "router", 2222).is_err());
        assert_eq!(canonical_keys("# comment\n[router]:2222 ssh-ed25519 AAAA\n", "router", 2222).unwrap(), "[router]:2222 ssh-ed25519 AAAA\n");
        assert!(canonical_keys("", "router", 22).is_err());
    }

    #[test]
    fn ssh_checks_pinned_keys_and_reads_password_from_pipe() {
        let command = ssh_command("router", "root", 2222, Path::new("/tmp/keys"), "printf ok");
        let args: Vec<_> = command.as_std().get_args().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(&args[..3], ["-d", "0", "ssh"]);
        assert!(args.contains(&"StrictHostKeyChecking=yes"));
        assert!(args.contains(&"UserKnownHostsFile=/tmp/keys"));
        assert_eq!(&args[args.len()-3..], ["--", "router", "printf ok"]);
    }

    #[test]
    fn new_and_changed_keys_require_confirmation() {
        assert!(check_trust(None, "key", false).is_err());
        assert!(check_trust(Some("old"), "key", false).is_err());
        assert!(check_trust(Some("key"), "key", false).is_ok());
        assert!(check_trust(None, "key", true).is_ok());
        assert!(check_trust(Some("old"), "key", true).is_ok());
    }

    #[test]
    #[ignore = "requires installed sshpass and access to a PTY"]
    fn real_sshpass_delivers_password_to_ssh_prompt() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("turris-ssh-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let fake_ssh = dir.join("ssh");
        fs::write(&fake_ssh, "#!/bin/sh\nprintf 'Password: ' >/dev/tty\nIFS= read -r value </dev/tty\n[ \"$value\" = 'test-only-secret' ] || exit 1\nprintf '__TF_CONNECTED__\\n'\n").unwrap();
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = ssh_command("router", "root", 22, &dir.join("keys"), "printf ok");
        command.env("PATH", format!("{}:/usr/bin:/bin", dir.display()));
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let result = rt.block_on(output(command, Some(b"test-only-secret\n"), 5));
        fs::remove_dir_all(&dir).unwrap();
        let result = result.unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        assert_eq!(result.stdout, b"__TF_CONNECTED__\n");
    }

    #[test]
    fn subprocess_reads_pipe_and_times_out() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let mut command = Command::new("sh");
            command.args(["-c", "IFS= read -r password; test \"$password\" = 'test-only-secret' && printf ok"]);
            let result = output(command, Some(b"test-only-secret\n"), 5).await.unwrap();
            assert!(result.status.success());
            assert_eq!(result.stdout, b"ok");
            let mut command = Command::new("sleep");
            command.arg("10");
            assert!(output(command, None, 1).await.unwrap_err().contains("časový limit"));
        });
    }
}
