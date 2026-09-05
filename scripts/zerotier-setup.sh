# Invoked remotely with a validated TF_ZT_NETWORK. All diagnostics go to stderr.
set -eu
umask 077
tf_fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || tf_fail 'Nastavení ZeroTier vyžaduje SSH přihlášení jako root.'
command -v uci >/dev/null 2>&1 || tf_fail 'Router neposkytuje UCI; automatické nastavení není podporované.'
[ -z "$(uci -q changes zerotier)" ] || tf_fail 'ZeroTier má neuložené UCI změny. Nejdřív je dokončete na routeru.'
tf_fresh=0
if ! command -v zerotier-cli >/dev/null 2>&1; then
    command -v opkg >/dev/null 2>&1 || tf_fail 'Chybí opkg pro instalaci ZeroTier.'
    [ -e /etc/config/zerotier ] || tf_fresh=1
    printf 'Instaluji balíček zerotier…\n' >&2
    opkg update >&2 || tf_fail 'Aktualizace seznamu balíčků selhala.'
    opkg install zerotier >&2 || tf_fail 'Instalace ZeroTier selhala. Zkontrolujte repozitáře a volné místo.'
fi
command -v zerotier-cli >/dev/null 2>&1 || tf_fail 'Balíček neposkytuje zerotier-cli.'
[ -x /etc/init.d/zerotier ] || tf_fail 'Chybí služba /etc/init.d/zerotier.'

# Rozpoznáme UCI schéma z dodané služby, ne pouze podle verze balíčku.
if grep -Eq 'config_foreach[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]+network([[:space:]]|$)' /etc/init.d/zerotier; then
    tf_schema=new
elif grep -Eq 'config_foreach[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]+zerotier([[:space:]]|$)' /etc/init.d/zerotier; then
    tf_schema=old
else
    tf_fail 'Neznámé UCI schéma služby ZeroTier. Konfigurace nebyla změněna.'
fi
mkdir -p /etc/turris-federation/backups
tf_backup=$(mktemp /etc/turris-federation/backups/zerotier.XXXXXX)
if [ -f /etc/config/zerotier ]; then cp /etc/config/zerotier "$tf_backup"; fi
printf 'Záloha konfigurace: %s\n' "$tf_backup" >&2
tf_committed=0
trap 'if [ "$tf_committed" = 0 ]; then uci -q revert zerotier; fi' EXIT

if [ "$tf_schema" = new ]; then
    tf_global=$(uci -q get zerotier.global || true)
    [ -z "$tf_global" ] || [ "$tf_global" = zerotier ] || tf_fail 'Sekce zerotier.global má neočekávaný typ.'
    uci set zerotier.global=zerotier
    uci set zerotier.global.enabled=1
    tf_section=global
    # Čerstvá instalace nesmí automaticky připojit ukázkovou veřejnou síť.
    if [ "$tf_fresh" = 1 ] && [ "$(uci -q get zerotier.earth.id || true)" = 8056c2e21c000001 ]; then
        uci delete zerotier.earth
    fi
    tf_network_section=
    tf_i=0
    while uci -q get "zerotier.@network[$tf_i]" >/dev/null 2>&1; do
        if [ "$(uci -q get "zerotier.@network[$tf_i].id" || true)" = "$TF_ZT_NETWORK" ]; then
            tf_network_section="@network[$tf_i]"; break
        fi
        tf_i=$((tf_i + 1))
    done
    if [ -z "$tf_network_section" ]; then
        tf_network_section=$(uci add zerotier network)
        uci set "zerotier.$tf_network_section.id=$TF_ZT_NETWORK"
    fi
    uci set "zerotier.$tf_network_section.allow_managed=1"
    uci set "zerotier.$tf_network_section.allow_global=0"
    uci set "zerotier.$tf_network_section.allow_default=0"
    uci set "zerotier.$tf_network_section.allow_dns=0"
else
    tf_section=
    tf_count=0
    tf_i=0
    while uci -q get "zerotier.@zerotier[$tf_i]" >/dev/null 2>&1; do
        tf_enabled=$(uci -q get "zerotier.@zerotier[$tf_i].enabled" || true)
        case "$tf_enabled" in 1|on|true|yes)
            tf_count=$((tf_count + 1)); tf_section="@zerotier[$tf_i]";;
        esac
        tf_i=$((tf_i + 1))
    done
    [ "$tf_count" -le 1 ] || tf_fail 'Více aktivních ZeroTier instancí: nejdřív vyberte konfiguraci na routeru.'
    if [ -z "$tf_section" ]; then
        tf_section=$(uci add zerotier zerotier)
    fi
    uci set "zerotier.$tf_section.enabled=1"
    tf_found=0
    for tf_id in $(uci -q get "zerotier.$tf_section.join" || true); do
        [ "$tf_id" = "$TF_ZT_NETWORK" ] && tf_found=1
    done
    [ "$tf_found" = 1 ] || uci add_list "zerotier.$tf_section.join=$TF_ZT_NETWORK"
fi
# Zachovat existující identitu i u routeru původně nastaveného jen přes CLI.
if [ -z "$(uci -q get "zerotier.$tf_section.secret" || true)" ] && [ -s /var/lib/zerotier-one/identity.secret ]; then
    uci set "zerotier.$tf_section.secret=$(cat /var/lib/zerotier-one/identity.secret)"
fi
uci commit zerotier
tf_committed=1
/etc/init.d/zerotier enable >&2 || tf_fail 'Nepodařilo se zapnout automatický start ZeroTier.'
if ! zerotier-cli info >/dev/null 2>&1; then
    /etc/init.d/zerotier start >&2 || tf_fail 'Službu ZeroTier nelze spustit.'
fi
tf_attempt=0
until zerotier-cli info >/dev/null 2>&1; do
    tf_attempt=$((tf_attempt + 1))
    [ "$tf_attempt" -lt 20 ] || tf_fail 'Služba ZeroTier nezačala odpovídat. Konfigurace je uložená; ověřte stav služby.'
    sleep 1
done
zerotier-cli join "$TF_ZT_NETWORK" >&2 || tf_fail 'Připojení do ZeroTier sítě selhalo.'
for tf_setting in allowManaged=true allowGlobal=false allowDefault=false allowDNS=false; do
    zerotier-cli set "$TF_ZT_NETWORK" "${tf_setting%=*}" "${tf_setting#*=}" >&2 || tf_fail 'Nastavení parametrů ZeroTier selhalo.'
done
echo __TF_ZT_SETUP_OK__
