use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const STATUS_SCRIPT: &str = include_str!("../../scripts/zerotier-status.sh");
const SETUP_SCRIPT: &str = include_str!("../../scripts/zerotier-setup.sh");

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub network_id: Option<String>,
    pub central: String,
    pub zero_tier_subnet: Option<String>,
    pub wireguard_subnet: Option<String>,
}
impl Default for Settings {
    fn default() -> Self { Self { network_id: None, central: "new".into(), zero_tier_subnet: None, wireguard_subnet: None } }
}
impl Settings {
    pub fn normalize(mut self) -> Result<Self, String> {
        self.network_id = self.network_id.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase);
        if let Some(id) = &self.network_id { validate_network_id(id)?; }
        if !["new", "legacy"].contains(&self.central.as_str()) { return Err("Neznámá verze ZeroTier Central.".into()); }
        self.zero_tier_subnet = self.zero_tier_subnet.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
        self.wireguard_subnet = self.wireguard_subnet.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
        Ok(self)
    }
    pub fn url(&self) -> &'static str {
        if self.central == "legacy" { "https://my.zerotier.com/" } else { "https://central.zerotier.com/" }
    }
}

pub fn validate_network_id(id: &str) -> Result<(), String> {
    if id.len() != 16 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("ZeroTier Network ID musí mít přesně 16 hexadecimálních znaků.".into());
    }
    Ok(())
}

pub fn probe(network_id: Option<&str>, setup: bool) -> Result<String, String> {
    if let Some(id) = network_id { validate_network_id(id)?; }
    if setup && network_id.is_none() { return Err("Nejdřív uložte ZeroTier Network ID.".into()); }
    Ok(format!("TF_ZT_NETWORK='{}'\n{}\n{}", network_id.unwrap_or_default(), if setup { SETUP_SCRIPT } else { "" }, STATUS_SCRIPT))
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub router_id: String,
    pub network_id: Option<String>,
    pub installed: bool,
    pub device_id: Option<String>,
    pub version: Option<String>,
    pub online: Option<bool>,
    pub network_status: Option<String>,
    pub network_name: Option<String>,
    pub assigned_addresses: Vec<String>,
    pub device: Option<String>,
    pub service_enabled: Option<bool>,
    pub persistent: bool,
    pub state: String,
    pub summary: String,
    pub details: String,
    pub checked_at: String,
}

fn section(payload: &str, marker: &str) -> Option<String> { crate::audit_section(payload, marker) }
fn text(value: &Value, key: &str) -> Option<String> { value.get(key)?.as_str().map(String::from) }

pub fn parse(payload: &str, router_id: &str, network_id: Option<&str>, checked_at: &str) -> Status {
    let installed_raw = section(payload, "__TF_ZT_INSTALLED__");
    let info = section(payload, "__TF_ZT_INFO__").unwrap_or_default();
    let networks = section(payload, "__TF_ZT_NETWORKS__").unwrap_or_default();
    let mut result = Status {
        router_id: router_id.into(), network_id: network_id.map(String::from), installed: installed_raw.as_deref() == Some("1"),
        device_id: None, version: None, online: None, network_status: None, network_name: None,
        assigned_addresses: Vec::new(), device: None,
        service_enabled: match section(payload, "__TF_ZT_ENABLED__").as_deref() { Some("1") => Some(true), Some("0") => Some(false), _ => None },
        persistent: section(payload, "__TF_ZT_PERSISTENT__").as_deref() == Some("1"),
        state: "unknown".into(), summary: "Stav ZeroTier se nepodařilo načíst.".into(),
        details: format!("Služba:\n{info}\n\nČlenství v sítích:\n{networks}"), checked_at: checked_at.into(),
    };
    if installed_raw.is_none() { return result; }
    if !result.installed { result.state = "not_installed".into(); result.summary = "ZeroTier není nainstalovaný.".into(); return result; }
    if section(payload, "__TF_ZT_INFO_RC__").as_deref() != Some("0") {
        result.state = "service_unavailable".into(); result.summary = "ZeroTier neodpovídá; služba neběží nebo chybí oprávnění.".into(); return result;
    }
    if let Ok(value) = serde_json::from_str::<Value>(&info) {
        result.device_id = text(&value, "address"); result.version = text(&value, "version");
        result.online = value.get("online").and_then(Value::as_bool);
    } else {
        let words: Vec<_> = info.split_whitespace().collect();
        if words.len() >= 5 && words[0] == "200" && words[1] == "info" {
            result.device_id = Some(words[2].into());
            result.online = if words.contains(&"ONLINE") || words.contains(&"TUNNELED") { Some(true) } else if words.contains(&"OFFLINE") { Some(false) } else { None };
            result.version = words[3..].iter().find(|s| s.chars().next().is_some_and(|c| c.is_ascii_digit())).map(|s| s.to_string());
        }
    }
    result.device_id = result.device_id.filter(|id| id.len() == 10 && id.bytes().all(|c| c.is_ascii_hexdigit()));
    if result.online.is_none() || result.device_id.is_none() { return result; }
    if section(payload, "__TF_ZT_NETWORKS_RC__").as_deref() != Some("0") {
        result.state = "error".into(); result.summary = "Členství v sítích se nepodařilo načíst.".into(); return result;
    }
    let mut parsed = false;
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&networks) {
        parsed = items.iter().all(|item| text(item, "nwid").or_else(|| text(item, "id")).is_some_and(|id| validate_network_id(&id).is_ok()) && text(item, "status").is_some());
        if let Some(item) = items.iter().find(|item| text(item, "nwid").or_else(|| text(item, "id")).as_deref() == network_id) {
            result.network_status = text(item, "status"); result.network_name = text(item, "name"); result.device = text(item, "portDeviceName");
            result.assigned_addresses = item.get("assignedAddresses").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default();
        }
    } else {
        for line in networks.lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            if words.len() >= 2 && words[0] == "200" && words[1] == "listnetworks" {
                parsed = true;
                if words.len() >= 9 && Some(words[2]) == network_id {
                    // Jméno sítě může obsahovat mezery; status následuje za MAC adresou.
                    if let Some(index) = words.iter().position(|s| ["OK", "ACCESS_DENIED", "REQUESTING_CONFIGURATION", "NOT_FOUND", "PORT_ERROR", "CLIENT_TOO_OLD"].contains(s)) {
                        result.network_status = Some(words[index].into());
                        if index >= 4 { result.network_name = Some(words[3..index-1].join(" ")); }
                        result.device = words.get(index+2).filter(|s| **s != "-").map(|s| s.to_string());
                        result.assigned_addresses = words.get(index+3).map(|s| s.split(',').filter(|s| *s != "-").map(String::from).collect()).unwrap_or_default();
                    }
                }
            }
        }
    }
    if !parsed { result.state = "error".into(); result.summary = "ZeroTier vrátil neznámý formát seznamu sítí.".into(); return result; }
    let (state, summary) = if result.online == Some(false) {
        ("offline", "ZeroTier je OFFLINE; zkontrolujte přístup routeru k internetu.")
    } else if network_id.is_none() {
        ("no_network", "ZeroTier běží. Pro kontrolu členství uložte Network ID.")
    } else { match result.network_status.as_deref() {
        Some("OK") => ("connected", "Router je autorizovaný a připojený do vybrané sítě."),
        Some("ACCESS_DENIED") => ("waiting_authorization", "Router čeká na autorizaci v ZeroTier Central."),
        Some("REQUESTING_CONFIGURATION") => ("requesting_configuration", "Router čeká na konfiguraci od řadiče. Po chvíli obnovte stav."),
        Some("NOT_FOUND") => ("error", "Síť nebyla nalezena. Zkontrolujte Network ID."),
        Some("PORT_ERROR") => ("error", "ZeroTier nemůže vytvořit síťové rozhraní; zkontrolujte TUN a stav routeru."),
        Some(_) => ("error", "ZeroTier hlásí chybu členství; viz načtený stav."),
        None => ("not_joined", "Router není členem vybrané sítě."),
    }};
    result.state = state.into(); result.summary = summary.into();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(network_status: &str) -> String {
        format!("__TF_ZT_INSTALLED__\n1\n__TF_ZT_INFO__\n{{\"address\":\"abcdef1234\",\"online\":true,\"version\":\"1.14.0\"}}\n__TF_ZT_INFO_RC__\n0\n__TF_ZT_NETWORKS__\n[{{\"nwid\":\"0123456789abcdef\",\"status\":\"{network_status}\",\"assignedAddresses\":[\"10.1.1.2/24\"]}}]\n__TF_ZT_NETWORKS_RC__\n0\n__TF_ZT_ENABLED__\n1\n__TF_ZT_PERSISTENT__\n1\n__TF_ZT_END__\n")
    }
    #[test]
    fn online_is_not_authorized_and_other_network_does_not_count() {
        let denied = parse(&payload("ACCESS_DENIED"), "router", Some("0123456789abcdef"), "now");
        assert_eq!(denied.state, "waiting_authorization");
        assert_eq!(denied.device_id.as_deref(), Some("abcdef1234"));
        assert_eq!(parse(&payload("OK"), "router", Some("1111111111111111"), "now").state, "not_joined");
        let ok = parse(&payload("OK"), "router", Some("0123456789abcdef"), "now");
        assert_eq!(ok.state, "connected"); assert!(ok.persistent);
        assert_eq!(ok.assigned_addresses, vec!["10.1.1.2/24"]);
    }
    #[test]
    fn missing_and_failed_probes_are_not_success() {
        assert_eq!(parse("", "r", None, "now").state, "unknown");
        assert_eq!(parse("__TF_ZT_INSTALLED__\n0\n__TF_ZT_END__", "r", None, "now").state, "not_installed");
        assert_eq!(parse(&payload("OK").replace("__TF_ZT_INFO_RC__\n0", "__TF_ZT_INFO_RC__\n1"), "r", None, "now").state, "service_unavailable");
    }
    #[test]
    fn validates_settings_and_only_opens_official_websites() {
        for id in ["", "short", "$(touch /tmp/a)", "0123456789abcdeg", "0123456789abcdef;id"] { assert!(validate_network_id(id).is_err()); }
        assert!(probe(Some("0123456789abcdef;id"), true).is_err());
        let settings = Settings { network_id: Some(" ABCDEF0123456789 ".into()), central: "legacy".into() }.normalize().unwrap();
        assert_eq!(settings.network_id.as_deref(), Some("abcdef0123456789"));
        assert_eq!(settings.url(), "https://my.zerotier.com/");
        assert!(probe(None, true).is_err());
    }
    #[test]
    fn parses_legacy_text_and_rejects_malformed_network_list() {
        let input = payload("OK")
            .replace(r#"{"address":"abcdef1234","online":true,"version":"1.14.0"}"#, "200 info abcdef1234 ONLINE 1.2.12")
            .replace(r#"[{"nwid":"0123456789abcdef","status":"OK","assignedAddresses":["10.1.1.2/24"]}]"#, "200 listnetworks 0123456789abcdef Home Network aa:bb:cc:dd:ee:ff OK PRIVATE zt0 10.1.1.2/24");
        let result = parse(&input, "r", Some("0123456789abcdef"), "now");
        assert_eq!(result.state, "connected");
        assert_eq!(result.version.as_deref(), Some("1.2.12"));
        assert_eq!(result.network_name.as_deref(), Some("Home Network"));
        assert_eq!(result.assigned_addresses, vec!["10.1.1.2/24"]);
        let malformed = payload("OK").replace("\"status\":\"OK\"", "\"unexpected\":true");
        assert_eq!(parse(&malformed, "r", Some("0123456789abcdef"), "now").state, "error");
    }
}
