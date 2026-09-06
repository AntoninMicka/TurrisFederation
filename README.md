# Turris Federation

Desktopový orchestrátor a routerový agent pro bezpečnou správu federace Turris Omnia.

Stav implementace a další kroky: [roadmapa a TODO seznam](ROADMAP.md).

Rozhraní je rozdělené do záložek **Routery**, **Notebooky**, **Síť**,
**Synchronizace**, **Audity** a **Nastavení**. Zobrazuje se vždy obsah jedné
záložky; rozpracované formuláře zůstávají při přepínání zachované. Routery
a místní řídicí notebook mají samostatné přehledy.

V záložce **Notebooky** lze zapnout discovery a šifrovanou synchronizaci
konfigurace i řídicí identity mezi vzájemně spárovanými notebooky.
Postup párování a řešení konfliktů: [synchronizace notebooků](docs/notebook-sync.md).

Spuštění na Ubuntu/Debianu:

```bash
./run.sh
```

Skript zkontroluje systémové knihovny a nástroje, chybějící balíčky
nainstaluje přes `sudo apt-get` a chybějící Rust přes oficiální `rustup`
do uživatelského účtu. Potom doplní npm závislosti a spustí desktopovou
aplikaci. Skript spouštěj bez `sudo`; při instalaci balíčků může požádat o heslo.
Vyžaduje připojení k internetu při instalaci a prvním sestavení.
Pokud repozitář systému neposkytuje dostatečně nový Node.js (20.19+ nebo 22.12+),
skript skončí s pokyny k aktualizaci. Argumenty předává příkazu `tauri dev`.

Při detekci ovladače NVIDIA skript nastaví `WEBKIT_DISABLE_DMABUF_RENDERER=1`
kvůli známým problémům vykreslování WebKitGTK. Nastavení platí jen pro spuštěnou
aplikaci a lze ho přepsat: `WEBKIT_DISABLE_DMABUF_RENDERER=0 ./run.sh`.

Při spuštění z terminálu editoru instalovaného přes Snap wrapper odstraní
zděděné cesty dynamických knihoven a GTK/GIO modulů a obnoví systémové datové
cesty. Tím zabrání míchání knihoven Snapu se systémovým WebKitem; změna platí
jen pro proces skriptu a jeho potomky.

U uloženého draftu zvolte **Připojit**, porovnejte zobrazené SHA256 otisky
SSH klíčů s routerem a při prvním připojení potvrďte důvěru. Zadejte SSH heslo.
Úspěšné ověření změní stav draftu na **SSH ověřeno**; nejde o trvalou relaci.
**Auditovat skutečný stav** si vyžádá heslo pro načtení stavu routeru.
Hesla se neukládají do databáze ani do argumentů příkazové řádky. SSH používá
potvrzené klíče; změna klíče vyžaduje nové ověření a potvrzení. Připojení
používá přímo adresu, port a uživatele z draftu, bez aliasů v `~/.ssh/config`.
Wrapper doplní potřebné balíčky `openssh-client` a `sshpass`.

ZeroTier lze zkontrolovat, podle potřeby nainstalovat a trvale připojit do
uložené sítě. Aplikace otevře ZeroTier Central v systémovém prohlížeči pro
autorizaci routeru. Podrobný postup a rozsah změn: [ZeroTier](docs/zerotier.md).

V inventáři je automaticky uveden také **Tento notebook**, pouze jako řídicí
uzel s ruční kontrolou místního ZeroTier členství. Nepřidává se do WireGuardu.
Kontrola vyžaduje přístup místního uživatele k ZeroTier službě.

**Známá závada:** nasazení ZeroTier podle posledního hlášení nefunguje;
oprava je zatím v [TODO](ROADMAP.md). Implementovaný deploy byl zkontrolován
lokálními testy, nikoli nasazením na skutečné routery.

Instalace a aktualizace agenta jsou povolené pouze přes **přímou LAN**
(Ethernet/Wi-Fi notebooku, číselná IPv4 routeru). Změna připojení nebo artefaktu
vyžaduje novou validaci plánu. Přes ZeroTier se synchronizuje síťové nastavení
a stav, nikoli software. Podrobnosti a omezení: [deploy](docs/deploy-sync.md).

LAN deploy a aktualizace instalují také **webový přehled na routeru** a dlaždici
**Turris Federation** na jeho úvodní obrazovku. Adresa je
`https://<router>/turris-federation/`, s přihlášením přes systémové heslo routeru.
Podrobnosti: [webový přehled](docs/router-web.md).
