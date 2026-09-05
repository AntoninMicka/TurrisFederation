use std::{collections::BTreeSet, net::IpAddr};

// Starší BusyBox nepodporuje -j, některé varianty ani table all / -o.
// Neúspěšné pokusy neznečistí skutečně načtený stav nápovědou programu.
pub const PROBE: &str = r#"
echo __TF_ADDRESSES__
if tf_output=$(ip -j address show 2>/dev/null); then tf_status=0
elif tf_output=$(ip -o address show 2>/dev/null); then tf_status=0
else tf_output=$(ip address show 2>&1); tf_status=$?; fi
printf '%s\n' "$tf_output"
echo __TF_ADDRESSES_STATUS__
echo "$tf_status"
echo __TF_ROUTES__
if tf_output=$(ip -j route show table all 2>/dev/null); then tf_status=0
elif tf_output=$(ip route show table all 2>/dev/null); then tf_status=0
else tf_output=$(ip route show 2>&1); tf_status=$?; fi
printf '%s\n' "$tf_output"
echo __TF_ROUTES_STATUS__
echo "$tf_status"
"#;

pub fn loaded(output: Option<&str>, status: Option<&str>) -> bool {
    let Some(text) = output else { return false; };
    if let Some(code) = status { return code.trim() == "0"; }
    // Starší uložené výstupy ještě nemají návratové kódy.
    !text.contains("Usage: ip") && !text.contains("not found") && !text.contains("Operation not permitted")
}

pub fn cidr(value: &str) -> Option<String> {
    let (address, prefix) = value.split_once('/')?;
    let prefix: u32 = prefix.parse().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            Some(format!("{}/{}", std::net::Ipv4Addr::from(u32::from(ip) & mask), prefix))
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            Some(format!("{}/{}", std::net::Ipv6Addr::from(u128::from(ip) & mask), prefix))
        }
        _ => None,
    }
}

pub fn networks(text: &str) -> BTreeSet<String> {
    fn json_networks(value: &serde_json::Value, result: &mut BTreeSet<String>) {
        if let Some(dst) = value.get("dst").and_then(|v| v.as_str()).and_then(cidr) { result.insert(dst); }
        if let (Some(local), Some(prefix)) = (value.get("local").and_then(|v| v.as_str()), value.get("prefixlen").and_then(|v| v.as_u64())) {
            if let Some(net) = cidr(&format!("{local}/{prefix}")) { result.insert(net); }
        }
        match value {
            serde_json::Value::Array(items) => for item in items { json_networks(item, result); },
            serde_json::Value::Object(items) => for item in items.values() { json_networks(item, result); },
            _ => (),
        }
    }
    let mut result = BTreeSet::new();
    if let Ok(value) = serde_json::from_str(text) { json_networks(&value, &mut result); }
    else { result.extend(text.split_whitespace().filter_map(cidr)); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognizes_busybox_and_json_networks() {
        assert!(networks("2: br-lan inet 192.168.10.1/24 brd 192.168.10.255").contains("192.168.10.0/24"));
        assert!(networks(r#"[{"addr_info":[{"local":"192.168.10.1","prefixlen":24}]}]"#).contains("192.168.10.0/24"));
        assert!(networks("192.168.10.0/24 dev br-lan proto kernel").contains("192.168.10.0/24"));
        assert!(!networks("192.168.110.0/24 dev br-lan").contains("192.168.10.0/24"));
        assert_eq!(cidr("2001:db8::1/64").unwrap(), "2001:db8::/64");
        assert_eq!(cidr("1.2.3.4/0").unwrap(), "0.0.0.0/0");
    }
    #[test]
    fn failures_are_not_empty_successes() {
        assert!(!loaded(Some("Usage: ip [OPTIONS]"), None));
        assert!(!loaded(Some(""), Some("1")));
        assert!(loaded(Some(""), Some("0")));
        assert!(!loaded(None, Some("0")));
    }
    #[test]
    fn probe_falls_back_when_busybox_rejects_json_and_table_all() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tf-ip-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let ip = dir.join("ip");
        std::fs::write(&ip, "#!/bin/sh\ncase \"$*\" in\n'-o address show') echo '2: br-lan inet 192.168.10.1/24';;\n'route show') echo '192.168.10.0/24 dev br-lan';;\n*) echo 'Usage: ip [OPTIONS]'; exit 1;;\nesac\n").unwrap();
        std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = std::process::Command::new("/bin/sh").args(["-c", PROBE]).env("PATH", &dir).output().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(!text.contains("Usage:"));
        assert!(text.contains("inet 192.168.10.1/24"));
        assert!(text.contains("192.168.10.0/24 dev br-lan"));
        assert!(text.contains("__TF_ADDRESSES_STATUS__\n0"));
        assert!(text.contains("__TF_ROUTES_STATUS__\n0"));
    }
}
