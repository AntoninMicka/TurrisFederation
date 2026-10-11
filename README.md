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
dostupnost kontrolují pouze lokálně. Legacy notebookový backend nyní běží jen
jako proces aktuální desktopové relace a skončí při úplném ukončení aplikace;
desktop neinstaluje systemd jednotku ani autostart. Historický návrh,
bezpečnostní hranice a stav implementace popisují
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
do uživatelského účtu. Potom doplní npm závislosti a spustí vývojovou
desktopovou aplikaci. Nevytváří ani nepovoluje uživatelskou či systémovou
systemd jednotku a nepřidává automatický start po přihlášení. Skript spouštěj
bez `sudo`; o heslo může požádat pouze instalace systémových závislostí.
Vyžaduje připojení k internetu při instalaci a prvním sestavení.
Pokud repozitář systému neposkytuje dostatečně nový Node.js (20.19+ nebo 22.12+),
skript skončí s pokyny k aktualizaci. Argumenty předává příkazu `tauri dev`.

Vývojovou instalaci z notebooku odebere interaktivní příkaz:

```bash
./run.sh uninstall
```

Pokud se má odstranit jen legacy desktopový backend, tray autostart a vývojový
klient, ale zachovat systémová síťová služba, VPN profily i identita, použijte:

```bash
./run.sh uninstall-desktop
```

Příkaz `uninstall-desktop` slouží pouze k úklidu pozůstatků starší instalace.
Po prvním potvrzení příkazu `uninstall` zastaví a odstraní vlastní uživatelské i systémové služby,
tray autostart, vývojový klient, spravovaný WireGuard profil a vlastní nftables
tabulku. Uživatelskou identitu a data ponechá pro obnovu; odvolání členství je
samostatná administrátorská operace. Pokud najde externí balíček ZeroTier One,
zeptá se na jeho odebrání samostatně podruhé, protože jej mohou používat i jiné
sítě.

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

ZeroTier je pouze volitelný legacy transport. Instalace ani validace routeru
nevyžaduje balíček, službu nebo členství ZeroTier a sama jej neinstaluje.
Historický ruční postup zůstává v dokumentu [ZeroTier](docs/zerotier.md).

Notebookové WireGuard uzly a jejich privilegovaná síťová služba jsou nyní pouze
legacy rollback implementace. Desktop ji už neinstaluje ani neaktualizuje;
historický kontrakt zůstává popsaný v dokumentu
[síťové služby notebooku](docs/notebook-network-service.md). Cílová architektura
používá na koncových zařízeních oficiální NetBird klient bez routování fyzické
LAN.

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

Pro úzce řízené zpřístupnění vybraných lokálních HTTP(S) služeb je připravena
[aplikační LXC HTTPS gateway](docs/lxc-https-proxy.md). Kontejner může být běžný
LAN host; přístup ke konkrétní HTTP(S) službě a volitelný Basic Auth se spravují
přímo v editoru Zlatých stránek. Deploy Turrisu na externím `/srv` automaticky
vytvoří, připojí do NetBirdu a následně aktualizuje `tf-proxy`; další aktualizace
nepřepisují jeho certifikáty, klíče ani VPN identitu.
Kontejner má vlastní NetBird peer, neroutuje LAN a přebírá krátce platný
podepsaný seznam pouze z lokálního Turrisu.
