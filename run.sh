#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# Terminál editoru instalovaného přes Snap dědí cesty k jeho knihovnám.
# Nativní WebKit musí načítat systémové GTK/GIO a stejnou glibc jako aplikace.
snap_environment=false
if [[ -n ${SNAP:-} || -n ${SNAP_NAME:-} ]]; then
    snap_environment=true
fi
for variable in LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT GTK_PATH GTK_EXE_PREFIX \
    GTK_DATA_PREFIX GTK_IM_MODULE_FILE GIO_MODULE_DIR GIO_EXTRA_MODULES \
    GDK_PIXBUF_MODULE_FILE GDK_PIXBUF_MODULEDIR GSETTINGS_SCHEMA_DIR; do
    if [[ ${!variable:-} == *'/snap/'* ]]; then
        snap_environment=true
    fi
done
if [[ $snap_environment == true ]]; then
    unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT
    unset GTK_PATH GTK_EXE_PREFIX GTK_DATA_PREFIX GTK_MODULES
    unset GTK_IM_MODULE_FILE GIO_MODULE_DIR GIO_EXTRA_MODULES
    unset GDK_PIXBUF_MODULE_FILE GDK_PIXBUF_MODULEDIR
    unset GSETTINGS_SCHEMA_DIR
    if [[ -n ${XDG_DATA_DIRS_VSCODE_SNAP_ORIG:-} ]]; then
        export XDG_DATA_DIRS="$XDG_DATA_DIRS_VSCODE_SNAP_ORIG"
    else
        export XDG_DATA_DIRS=/usr/local/share:/usr/share
    fi
    # Systémové knihovny nesmí proces považovat za aplikaci Snapu.
    for variable in ${!SNAP@}; do
        unset "$variable"
    done
    printf 'Odstraňuji zděděné cesty ke knihovnám a modulům Snapu.\n'
fi
unset snap_environment variable

fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ ${1:-} == --help ]]; then
    printf 'Použití: ./run.sh [argumenty pro tauri dev]\n'
    printf 'Na Ubuntu/Debianu doinstaluje závislosti a spustí aplikaci.\n'
    exit 0
fi

[[ $EUID -ne 0 ]] || fail 'Spusť skript jako běžný uživatel, bez sudo. O sudo si řekne instalace balíčků.'
[[ -r /etc/os-release ]] || fail 'Automatická instalace podporuje Ubuntu/Debian.'
# shellcheck disable=SC1091
source /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *' debian '*|*' ubuntu '*) ;;
    *) fail "Automatická instalace zatím nepodporuje ${PRETTY_NAME:-tento systém}. Viz https://v2.tauri.app/start/prerequisites/" ;;
esac

# Systémové závislosti dle https://v2.tauri.app/start/prerequisites/
packages=(build-essential pkg-config curl wget file ca-certificates openssh-client sshpass xdg-utils python3 openssl iproute2
    libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libssl-dev
    libayatana-appindicator3-dev librsvg2-dev)

# Vite 7 vyžaduje Node.js 20.19+ nebo 22.12+.
node_supported() {
    command -v node >/dev/null 2>&1 && node -e '
        const [major, minor] = process.versions.node.split(".").map(Number);
        process.exit((major === 20 && minor >= 19) ||
            (major === 22 && minor >= 12) || major > 22 ? 0 : 1);
    ' >/dev/null 2>&1
}
if ! node_supported; then packages+=(nodejs); fi
if ! command -v npm >/dev/null 2>&1; then packages+=(npm); fi

missing=()
for package in "${packages[@]}"; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        missing+=("$package")
    fi
done
# Nainstalovaný, ale starý Node.js zkusíme aktualizovat z repozitáře.
if ! node_supported && [[ " ${missing[*]} " != *' nodejs '* ]]; then
    missing+=(nodejs)
fi
if ((${#missing[@]})); then
    command -v sudo >/dev/null 2>&1 || fail "Chybí sudo. Správce musí nainstalovat: ${missing[*]}"
    printf 'Instaluji systémové balíčky: %s\n' "${missing[*]}"
    sudo apt-get update --error-on=any
    if ! apt-get --simulate --no-remove install -- "${missing[@]}"; then
        printf '\nAPT nedokáže sestavit instalační plán. Dostupné verze WebKitu:\n' >&2
        apt-cache policy libwebkit2gtk-4.1-dev libwebkit2gtk-4.1-0 >&2
        printf '\nBalíčky blokované přes apt-mark hold:\n' >&2
        apt-mark showhold >&2
        if [[ ${ID:-} == ubuntu ]]; then
            printf '\nZkontroluj, že oficiální zdroje Ubuntu obsahují %s, %s-updates a %s-security.\n' \
                "${VERSION_CODENAME:-<vydání>}" "${VERSION_CODENAME:-<vydání>}" "${VERSION_CODENAME:-<vydání>}" >&2
        fi
        fail 'Nejdřív oprav zdroje balíčků nebo konkrétní konfliktní hold a spusť run.sh znovu.'
    fi
    sudo apt-get --no-remove install -y -- "${missing[@]}"
fi
node_supported || fail 'Aktivní Node.js je příliš starý. Nainstaluj Node.js 22.12+ nebo 24 LTS a spusť skript znovu; repozitář systému nebo aktuální PATH neposkytuje potřebnou verzi.'

# Přidáme i existující rustup, který ještě není v PATH aktuálního terminálu.
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if ! cargo --version >/dev/null 2>&1 || ! rustc --version >/dev/null 2>&1; then
    if command -v rustup >/dev/null 2>&1; then
        rustup toolchain install stable --profile minimal
        rustup default stable
    else
        printf 'Instaluji Rust přes rustup do uživatelského účtu…\n'
        installer=$(mktemp)
        trap 'rm -f -- "$installer"' EXIT
        curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o "$installer"
        sh "$installer" -y --profile minimal --default-toolchain stable --no-modify-path
        rm -f -- "$installer"
        trap - EXIT
    fi
fi

for command in node npm cargo rustc cc c++ make pkg-config; do
    "$command" --version >/dev/null 2>&1 || fail "Nástroj $command není funkční ani po instalaci."
done
pkg-config --exists 'webkit2gtk-4.1 >= 2.40' gtk+-3.0 openssl librsvg-2.0 ||
    fail 'Systémové knihovny nejsou dostupné přes pkg-config nebo je WebKitGTK starší než 2.40.'

if [[ ! -x node_modules/.bin/tauri || ! -x node_modules/.bin/vite ]] || ! npm ls --depth=0 >/dev/null 2>&1; then
    printf 'Instaluji npm závislosti…\n'
    npm install
fi

# WebKitGTK může na NVIDIA selhat při předávání DMA-BUF bufferů.
# https://v2.tauri.app/develop/debug/linux-graphics/
# Explicitní nastavení uživatele má přednost (0 workaround vypne).
if [[ -r /proc/driver/nvidia/version && ! -v WEBKIT_DISABLE_DMABUF_RENDERER ]]; then
    export WEBKIT_DISABLE_DMABUF_RENDERER=1
    printf 'NVIDIA: zapínám workaround WebKitGTK (WEBKIT_DISABLE_DMABUF_RENDERER=1).\n'
fi

exec npm run tauri -- dev "$@"
