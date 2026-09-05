# Invoked remotely with TF_ZT_NETWORK set to a validated network ID (or empty).
set +e
echo __TF_ZT_INSTALLED__
if command -v zerotier-cli >/dev/null 2>&1; then
    echo 1
    echo __TF_ZT_INFO__
    if tf_info=$(zerotier-cli -j info 2>/dev/null); then tf_rc=0
    else tf_info=$(zerotier-cli info 2>&1); tf_rc=$?; fi
    printf '%s\n' "$tf_info"
    echo __TF_ZT_INFO_RC__
    echo "$tf_rc"
    echo __TF_ZT_NETWORKS__
    if tf_networks=$(zerotier-cli -j listnetworks 2>/dev/null); then tf_rc=0
    else tf_networks=$(zerotier-cli listnetworks 2>&1); tf_rc=$?; fi
    printf '%s\n' "$tf_networks"
    echo __TF_ZT_NETWORKS_RC__
    echo "$tf_rc"
else
    echo 0
fi
echo __TF_ZT_ENABLED__
if [ -x /etc/init.d/zerotier ]; then
    if /etc/init.d/zerotier enabled >/dev/null 2>&1; then echo 1; else echo 0; fi
else echo unknown; fi
echo __TF_ZT_PERSISTENT__
tf_persistent=0
if [ -n "$TF_ZT_NETWORK" ] && command -v uci >/dev/null 2>&1; then
    tf_i=0
    while uci -q get "zerotier.@zerotier[$tf_i]" >/dev/null 2>&1; do
        tf_enabled=$(uci -q get "zerotier.@zerotier[$tf_i].enabled")
        tf_join=$(uci -q get "zerotier.@zerotier[$tf_i].join")
        case "$tf_enabled" in 1|on|true|yes)
            for tf_id in $tf_join; do
                [ "$tf_id" = "$TF_ZT_NETWORK" ] && tf_persistent=1
            done;;
        esac
        tf_i=$((tf_i + 1))
    done
    tf_enabled=$(uci -q get zerotier.global.enabled)
    case "$tf_enabled" in 1|on|true|yes)
        tf_i=0
        while uci -q get "zerotier.@network[$tf_i]" >/dev/null 2>&1; do
            [ "$(uci -q get "zerotier.@network[$tf_i].id")" = "$TF_ZT_NETWORK" ] && tf_persistent=1
            tf_i=$((tf_i + 1))
        done;;
    esac
fi
echo "$tf_persistent"
echo __TF_ZT_END__
exit 0
