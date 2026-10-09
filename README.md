# Turris Federation

Routerová aplikace pro propojení a správu federace Turris Omnia přes NetBird.

**Cílová architektura běží pouze na Turrisech.** Notebooky a telefony jsou běžné
NetBird klienty; notebooková aplikace, tray backend a vlastní VPN orchestrace se
po bezpečné migraci odstraní. Současná desktopová implementace zůstává dočasně
v repozitáři jako migrační nástroj a rollback, nikoli jako cílový produkt.
Podrobnosti a podmínky odstranění:
[router-only architektura](docs/router-only-architecture.md).

Stav implementace a další kroky: [roadmapa a TODO seznam](ROADMAP.md).

Níže popsané desktopové rozhraní dokumentuje současnou legacy implementaci během
migrace. Rozhraní je rozdělené do záložek **Routery**, **Notebooky**, **Síť**,
**Synchronizace**, **Audity** a **Nastavení**. Zobrazuje se vždy obsah jedné
záložky; rozpracované formuláře zůstávají při přepínání zachované. Routery
a místní řídicí notebook mají samostatné přehledy.

Plánovaný model rozlišuje **administrátorské notebooky** pro správu, audit a
deploy routerů a **uživatelské notebooky** určené jen k síťovému připojení.
Oba jsou koncové VPN uzly bez routování mezi VPN a fyzickou sítí a svou
dostupnost kontrolují pouze lokálně. Notebookový backend má běžet trvale jako
uživatelská služba nezávislá na okně aplikace; stavová lišta zobrazí připojení
a umožní otevřít UI. Návrh, bezpečnostní hranice a stav implementace popisují
[role notebooků](docs/notebook-node-roles.md).
Uživatelská role má zobrazit read-only přehled odpovídající stránce na routeru,
zatímco administrátorská zachová dnešní plné UI. Produkční balíček a onboarding
jsou navržené v dokumentu [instalace notebooku](docs/notebook-installation.md).

V záložce **Notebooky** lze zapnout discovery a šifrovanou synchronizaci
konfigurace i řídicí identity mezi vzájemně spárovanými notebooky.
Postup párování a řešení konfliktů: [synchronizace notebooků](docs/notebook-sync.md).
Pokud se žádost o přijetí v místní síti neobjeví, pokračujte podle diagnostiky
[firewallu při přidávání notebooku](docs/notebook-firewall.md). Debian může
používat `firewalld`, i když příkaz `ufw` vůbec není dostupný.

Spuštění na Ubuntu/Debianu:

```bash
./run.sh
```

Skript zkontroluje systémové knihovny a nástroje, chybějící balíčky
nainstaluje přes `sudo apt-get` a chybějící Rust přes oficiální `rustup`
do uživatelského účtu. Potom doplní npm závislosti, sestaví samostatný testovací
klient s vloženým frontendem pro automatický start po přihlášení, nainstaluje
nebo aktualizuje úzce omezenou systémovou
[síťovou službu notebooku](docs/notebook-network-service.md) a spustí
vývojovou desktopovou aplikaci. Skript spouštěj bez `sudo`; při instalaci
balíčků nebo změně systémové služby může požádat o heslo.
Vyžaduje připojení k internetu při instalaci a prvním sestavení.
Pokud repozitář systému neposkytuje dostatečně nový Node.js (20.19+ nebo 22.12+),
skript skončí s pokyny k aktualizaci. Argumenty předává příkazu `tauri dev`.

Při detekci ovladače NVIDIA skript nastaví `WEBKIT_DISABLE_DMABUF_RENDERER=1`
kvůli známým problémům vykreslování WebKitGTK. Nastavení platí jen pro spuštěnou
aplikaci a lze ho přepsat: `WEBKIT_DISABLE_DMABUF_RENDERER=0 ./run.sh`.

Při spuštění z terminálu editoru instalovaného přes Snap wrapper odstraní
zděděné cesty dynamických knihoven a GTK/GIO modulů a obnoví systémové datové
cesty. Revizně závislá Snap data aplikace při prvním běhu bez přepsání cíle
zkopíruje do stabilního `~/.local/share/cz.turris.federation`, aby backend i
klient spuštěný po přihlášení používaly stejnou identitu. Tím také zabrání
míchání knihoven Snapu se systémovým WebKitem; změna prostředí platí jen pro
proces skriptu a jeho potomky.

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

Notebooky jsou v podepsané topologii samostatné koncové WireGuard uzly s rolí
administrátora nebo uživatele. Neinzerují fyzickou LAN a router pro každý z nich
přijímá pouze jeho tunelovou `/32`. Po jednorázové instalaci úzce omezené
systémové služby uživatelský backend průběžně odvozuje požadovaný VPN profil z
ověřené podepsané topologie. Služba jej vytvoří, aktivuje a obnovuje při změně
Wi-Fi, hotspotu nebo restartu; nevytváří výchozí trasu ani forwarding. Ruční
polkit instalační tok dočasně zůstává jako nouzová cesta do fyzické akceptace
automatického reconcile.

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
