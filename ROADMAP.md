# Turris Federation — roadmapa a TODO

Aktualizováno: 5. 9. 2026.

## Cíl a podklady

Desktopová aplikace pro správu federace routerů Turris Omnia: vytvořit draft
uzlů a sítí, připojit se přes SSH, zjistit skutečný stav, porovnat jej s návrhem
a následně řízeně aplikovat změny. Projekt počítá se ZeroTier, WireGuardem
a routerovým agentem.

Podklady: požadavky v dosavadní konverzaci, [README](README.md), datový model
a aktuální implementace. Samostatné podrobné zadání v repozitáři zatím není.
Budoucí etapy níže jsou návrhem rozpracování tohoto rozsahu; neznamenají,
že je jejich detailní architektura již rozhodnutá.

`[x]` = implementováno v repozitáři, `[ ]` = zbývá dokončit nebo ověřit.
Implementace sama o sobě neznamená ověření na skutečném routeru.
Priority: **P0** blokuje první spolehlivé použití, **P1** základní funkce,
**P2** navazující rozvoj. Etapy určují pořadí, zatím bez termínů.

## Kontrola deploye a aktuální TODO (5. 9. 2026)

- [x] Doplnit webový přehled na routeru a dlaždici Turris Federation do WebApps;
  instalovat i aktualizovat přes LAN, chránit přístup PAM přihlášením.
- [x] Ověřit návrat původních webových souborů při chybné konfiguraci lighttpd.
- [ ] Na skutečném Turrisu ověřit dlaždici, HTTPS/PAM přihlášení, restart webové
  instance a aktualizaci vedle existujících webových aplikací.
  Podrobnosti: [webový přehled](docs/router-web.md).

- [x] Omezit instalaci a aktualizaci agenta na přímou fyzickou LAN cestu;
  kontrolovat trasu před každým SSH krokem a vázat plán na LAN a artefakt.
- [x] ZeroTier synchronizaci omezit na síťový dokument a provozní stav;
  odmítat dodatečná pole pro software/příkazy. Publikování neinstaluje agenta.
- [ ] Ověřit LAN instalaci i aktualizaci na routeru, ztrátu LAN během aktualizace
  a odmítnutí přechodu na ZeroTier. Doplnit automatickou obnovu softwaru při
  neúspěšné aktualizaci (dosud se uchovává předchozí soubor agenta).

- [x] Deploy controller a routerový agent jsou implementované: podepsané revize,
  validace plánu, SSH instalace, UCI záloha a watchdog, synchronizace přes ZeroTier.
- [x] Opravit souběh přijetí nové revize a nepotvrzené změny: nová revize musí
  počkat na potvrzení/rollback; potvrzení musí patřit právě aplikované revizi.
- [x] Přidat tento notebook do přehledu jako místní řídicí uzel pouze pro kontrolu
  ZeroTier. Nemá WireGuard peery, tunelovou adresu ani routerový deploy.
- [ ] **P0: Nasazení ZeroTier podle hlášení uživatele nefunguje.** Získat výstup
  selhání a verzi Turris OS, reprodukovat, opravit instalaci/nastavení a ověřit
  autorizaci i restart. Oprava ZeroTier je zatím odložená do TODO.
- [ ] **P0: Ověřit deploy na dvou skutečných routerech**, včetně výpadku SSH,
  firewallu, restartu během změny a obnovení ze zálohy. Lokální testy toto nenahrazují.
- [ ] **P0: Ověřit první skutečné WireGuard propojení dvou přijatých routerů.**
  Na jednom testovacím routeru je nyní nasazen agent a vytvořen `tf_wg`, zatímco
  druhý router má zatím pouze ZeroTier a v návrhu federace zůstává v draft stavu;
  absence WireGuard peeru na prvním routeru je proto v této fázi očekávaná.
- [x] Při deployi druhé Omnie automaticky předat novou podepsanou konfiguraci
  ostatním přijatým routerům přes ZeroTier. Notebook po úspěšném deployi zkusí
  doručení; agenti opakovaně revize odesílají i stahují, takže první router
  může přijmout nového člena bez návratu notebooku do jeho LAN.
  Nedostupnost nebo nepotvrzená předchozí změna vede k pozdějšímu opakování.
- [ ] Ověřit přechod protistrany `draft → member` a že teprve poté agent vytvoří
  odpovídající WireGuard peery na obou nasazených routerech.
- [ ] Pro první end-to-end test použít ZeroTier IPv4 jako transport WireGuardu;
  RFC4193 IPv6 adresy jsou přidělené, ale end-to-end IPv6 konektivita zatím nebyla
  úspěšně ověřena a její použití jako WG transportu je odloženo.
- [ ] Ověřit firewall ZeroTier underlaye: zóna `vpn_zerotier` má zůstat restriktivní
  (`input REJECT`, `forward REJECT`) a Federation má explicitně povolit jen vlastní
  služby, zejména řídicí TCP/8844, diagnostický ICMP a WireGuard UDP/51830.
- [ ] Po přijetí druhého routeru ověřit `wg show`, vznik peerů, `latest handshake`,
  obousměrný ping přes `tf_wg`, přechod `waiting_peers → active` a následně LAN routing.
- [ ] Ověřit odebrání/odvolání člena, odstranění jeho WireGuard peeru a později také
  rotaci WireGuard klíčů bez přerušení nebo se bezpečně řízeným přerušením federace.
- [x] **P1: Zkrátit kritické sekce agenta.** Předběžné kontroly `stage`, health
  kontrola `confirm` i periodická health kontrola běží mimo zámek; před zápisem
  se znovu kontroluje stav. Aplikování zamyká jednotlivé příkazy, ověřuje token
  a omezuje timeout zbývající dobou operace. Timeout ukončuje i potomky příkazu.
  Regresní testy pokrývají souběh s rollbackem a odmítnutí zastaralého zápisu.
- [ ] Na routeru ověřit časování rollbacku při zaseknuté službě. Limit 120 s
  je lhůta potvrzení, nikoli tvrdá horní mez dokončení obnovy konfigurace/služeb.
- [x] **P1: Oddělit obsluhu HTTP od synchronizační smyčky.** HTTP běží
  v samostatném vlákně; lokální regresní test ověřuje odpovědi na konfiguraci
  i podepsaný stav během čekající synchronizace a úklid při jejím ukončení.
- [ ] Na routerech ověřit souběh sousedů, zotavení a potvrzení změn bez notebooku.
  Obsluha HTTP může čekat na jednotlivý příkaz aplikování nebo obnovu konfigurace.
- [ ] Automatická rotace nakonfigurovaných WireGuard klíčů a šifrovaná záloha
  kořenové identity notebooku zůstávají neimplementované.

Podrobnosti kontroly a rozsah implementace: [deploy](docs/deploy-sync.md).
Starší seznam etap níže je plán; položky překryté touto aktualizací nejsou
spolehlivým přehledem aktuálního kódu.

## Implementovaný základ

- [x] Desktopová aplikace Tauri 2 + Vue + TypeScript.
- [x] Lokální SQLite: uzly, pozorování z auditů a potvrzené SSH klíče routerů.
- [x] Vytváření a výpis draftů: název, SSH adresa, port, uživatel, LAN sítě a veřejný endpoint.
- [x] `run.sh`: kontrola a doplnění závislostí na Ubuntu/Debianu, spuštění aplikace.
- [x] Workaround WebKitGTK pro NVIDIA a čištění prostředí zděděného ze Snap editoru.
- [x] Ikona potřebná pro sestavení Tauri a oprava typových závislostí frontendu.
- [x] Dialog SSH přihlášení heslem; heslo se neukládá do databáze ani argumentů procesu.
- [x] Načtení SHA256 otisků, potvrzení prvního nebo změněného SSH klíče a kontrola klíče při spojení.
- [x] Samostatné ověření připojení, chybové hlášky a časové limity.
- [x] Základní SSH audit systému, adres, tras, ZeroTier, WireGuard a UCI konfigurace.
- [x] Základní seznam odchylek a stavy draft / ověřeno / odchylky / v pořádku / připojení selhalo.
- [x] U odchylek zobrazit očekávaný i načtený stav příslušné kontroly, uzel a čas auditu.
- [x] Při nepodporovaném `ip -j` použít textový výstup BusyBoxu; sledovat návratové kódy načítání adres a tras.
- [x] Uložené ZeroTier Network ID pro federaci a volba nového/Legacy Central.
- [x] Kontrola služby ZeroTier, konkrétního členství, autorizace, adres a UCI persistence; uchování posledního výsledku.
- [x] Instalace přes opkg, záloha UCI, nastavení členství pro staré/nové schéma a start služby po potvrzení kroků.
- [x] Otevření ZeroTier Central v systémovém prohlížeči a obnovení stavu po ruční autorizaci.
- [x] Ověřen build frontendu a šest Rust testů včetně předání hesla přes skutečný `sshpass` s testovacím SSH procesem.

**Současné omezení:** připojení ověřuje jednotlivý SSH příkaz, neudržuje trvalou
relaci ani neotevírá terminál. Audit používá převážně hledání textu ve výstupu.
Seznam odchylek zatím není proveditelný plán změn.
Routerový agent a aplikování konfigurace jsou implementované, ale dosud neověřené na routerech.

## 1. P0 — dokončit první připojení a spolehlivý audit

- [ ] Ověřit nový dialog přihlášení heslem na skutečném Turris Omnia; poslední hlášené neúspěšné připojení zatím nemá doložené vyřešení na routeru.
- [ ] Zaznamenat konkrétní chybu při selhání a rozlišit nedostupný host, port, autentizaci a nesouhlas klíče.
- [ ] Ověřit výchozí i vlastní SSH port, správné i chybné heslo a změnu klíče routeru.
- [ ] Ověřit celý tok: restart aplikace → uložený draft → přihlášení → audit → aktualizace stavu.
- [ ] Zamezit ukládání privátních klíčů a dalších tajných údajů z auditu: současné `wg show all dump` a `uci export network` je mohou obsahovat. Omezit sběr na potřebná pole a prověřit již uložená pozorování.
- [ ] Oddělit výstupy a návratové kódy jednotlivých auditních příkazů; selhání sběru nesmí vést ke stavu „V pořádku“.
- [ ] Ověřit podporu příkazů na cílové verzi Turris OS, zejména JSON výstupu `ip` a dostupnosti `ubus`, `opkg`, `uci`, `wg` a `zerotier-cli`.
- [ ] Přidat regresní testy parsování pro chybějící nástroje, neúplný výstup a nedostatečná oprávnění.

**Hotovo, když:** skutečný router lze přihlásit heslem a opakovaně auditovat;
neúplný audit je jasně označený a uložená data neobsahují tajné klíče.

## 2. P1 — dokončit inventář a porovnání se skutečností

- [ ] Editace a odstranění uloženého uzlu s potvrzením odstranění.
- [ ] Validace LAN CIDR, endpointů, duplicit a překrývajících se sítí napříč uzly.
- [ ] Oddělit požadovanou konfiguraci draftu od naposledy pozorovaného stavu.
- [ ] Strukturovaně parsovat systém, rozhraní, adresy, trasy, ZeroTier, WireGuard a firewall.
- [ ] Zobrazit detail uzlu, poslední úspěšné ověření připojení a stáří auditu.
- [ ] Ukládat a zobrazovat nálezy podle uzlu a běhu auditu; zachovat historii po restartu.
- [x] Porovnávat normalizované IPv4/IPv6 sítě z JSON i textového výstupu adres a tras místo hledání podřetězce CIDR.
- [ ] Doplnit zrušení probíhajícího připojení/auditu a ověřit ukončení podřízených SSH procesů.
- [ ] Doplnit testy migrací SQLite a zachování existujících draftů.

**Hotovo, když:** uživatel upraví návrh, vidí skutečný stav každého uzlu
a rozumí konkrétním rozdílům i tomu, z jak starého auditu pocházejí.

## 3. P1 — navrhnout síť federace a plán změn

- [ ] Potvrdit role ZeroTier a WireGuard: discovery/správa, datový provoz a požadovaná topologie.
- [ ] Doplnit model federace: členství, síťové identifikátory, adresní plán a vztahy mezi uzly.
- [x] Implementovat ZeroTier členství ve společné uložené síti a ruční autorizaci routerů na webu Central.
- [ ] Ověřit instalaci, autorizaci a zachování ZeroTier identity/členství po restartu na skutečném Turris OS.
- [ ] Navrhnout WireGuard peery, endpointy, `AllowedIPs`, směrování a pravidla firewallu.
- [ ] **Ověřit životní cyklus WireGuard peeru podle členství:** draft uzel nesmí
  být nasazen jako peer; po přijetí člena musí vzniknout peer na relevantních
  routerech a po odvolání musí být bezpečně odstraněn.
- [ ] **První ověřený transport:** použít ZeroTier IPv4 adresu peeru jako WG endpoint
  a ověřit handshake přes UDP/51830 ještě před zapnutím routování LAN sítí.
- [ ] **Firewall underlaye:** nepovyšovat ZeroTier zónu na důvěryhodnou LAN; místo
  toho generovat minimální explicitní pravidla potřebná pro Federation a WireGuard.
- [ ] **Budoucí adresní plán WireGuardu:** současný overlay ponechat IPv4; následně
  doplnit volitelný dual-stack s interními IPv6 adresami WireGuard peerů, bez
  nutnosti měnit IPv4 LAN routing.
- [ ] **Oddělit transport a overlay WireGuardu:** umožnit, aby WG endpoint běžel
  přes ZeroTier IPv4/IPv6 nebo přímé IPv4/IPv6 spojení, zatímco routované sítě
  a interní WG adresace zůstanou na transportní vrstvě nezávislé.
- [ ] **Transportní preference/failover:** navrhnout pořadí přímé IPv6 → přímé IPv4
  → ZeroTier a bezpečnou změnu aktuálního endpointu peeru bez změny `AllowedIPs`.
- [ ] **IPv6 LAN routing:** až po zavedení dual-stack overlaye doplnit podporu
  routování IPv6 prefixů mezi lokalitami a odpovídající firewall/health kontroly.
- [ ] **ZeroTier RFC4193 IPv6 transport:** adresy jsou na testovacích uzlech
  automaticky přidělené a routované na ZT rozhraní, ale end-to-end ICMPv6 zatím
  nebylo úspěšně ověřeno; před použitím pro WG endpoint provést samostatný test.
- [ ] Vyhodnocovat konflikty adres, překryvy sítí a dosažitelnost endpointů před návrhem změn.
- [ ] Vytvářet konkrétní plán z rozdílu draftu a auditu: balíčky, konfigurace, routy a firewall.
- [ ] U každé operace ukázat cílový router, současnou a požadovanou hodnotu, závislosti a dopad na připojení.
- [ ] Doplnit náhled výsledné konfigurace bez zápisu do routeru.
- [ ] Před aplikací ověřit, že se skutečný stav od vytvoření plánu nezměnil.

**Hotovo, když:** pro dva testovací routery vznikne srozumitelný a kontrolovatelný
plán propojení, který dosud nic nemění a upozorní na konflikty.

## 4. P1 — aplikování změn a routerový agent

Závisí na dokončení spolehlivého auditu a konkrétního plánu změn.

- [ ] Rozhodnout, které operace provede desktop přes SSH a které routerový agent; určit jejich rozhraní a oprávnění.
- [ ] Implementovat instalaci, kontrolu verze a životního cyklu agenta pro Turris OS.
- [ ] Před zápisem zobrazit konečný plán a vyžádat potvrzení jeho aplikace.
- [ ] Zálohovat dotčenou konfiguraci a připravit návrat před prvním zápisem.
- [ ] Aplikovat kroky v pořadí podle závislostí a průběžně ukládat jejich výsledek.
- [ ] Zajistit idempotenci: opakování dokončeného plánu nesmí vytvářet duplicity.
- [ ] Ochránit správcovské spojení při změnách rout a firewallu; ověřit časovaný rollback při ztrátě dostupnosti.
- [ ] Navrhnout generování a uchování WireGuard klíčů bez jejich zobrazení v logu či běžných exportech.
- [ ] Po aplikaci spustit kontrolní audit a zobrazit skutečný výsledek.
- [ ] Otestovat částečné selhání a obnovení provozu na testovacích routerech.

**Hotovo, když:** potvrzený plán propojí dva testovací routery, kontrolní audit
ověří stav a přerušenou nebo chybnou změnu lze bezpečně vrátit.

## 5. P2 — provoz a distribuce

- [ ] Přehled dostupnosti uzlů a posledních výsledků; volitelné periodické audity.
- [ ] Historie aplikovaných plánů a změn konfigurace.
- [ ] Export/import draftů a záloha lokální databáze s jasným vymezením citlivých dat.
- [ ] SSH klíče a `ssh-agent` jako další metoda přihlášení vedle hesla.
- [ ] Dokumentace přípravy routeru, ověření otisků, propojení dvou uzlů a obnovy po chybě.
- [ ] CI pro build frontendu, Rust testy a testy auditních dat.
- [ ] Balíček desktopové aplikace a ověřená matice podporovaných OS/architektur; začít používaným Ubuntu ARM64.

## 6. Budoucí rozvoj a optimalizace

- [ ] **P2: Cílová transportní architektura — self-hosted NetBird.**
  - [ ] Současnou kombinaci `ZeroTier → tf_wg` zachovat jako funkční baseline pro
    prostředí bez vlastního veřejně dosažitelného uzlu; neinvestovat do ní
    zbytečně funkce, které může později převzít NetBird.
  - [ ] Jakmile bude k dispozici alespoň jeden stabilně veřejně dosažitelný uzel
    (preferovaně přes globální IPv6, případně veřejnou IPv4), ověřit na něm
    self-hosted NetBird control plane a potřebné signal/relay služby.
  - [ ] Centrální NetBird uzel chápat jako koordinační bod, nikoli jako povinný
    datový router: provoz mezi lokalitami má při dostupnosti přímé cesty zůstat
    peer-to-peer přes WireGuard; relay používat pouze jako fallback.
  - [ ] Zavést přechodové režimy transportu: `ZeroTier + tf_wg` → paralelní
    NetBird PoC → `NetBird only`, aby migrace nevyžadovala jednorázový výpadek
    existující federace.
  - [ ] Po úspěšném PoC přesunout do NetBirdu správu WireGuard peerů, klíčů,
    endpoint discovery, NAT traversal, relay fallback a overlay konektivity;
    odstranit vlastní `tf_wg` orchestrace tam, kde ji NetBird plně nahrazuje.
  - [ ] **Federation zachovat jako source of truth síťové topologie:** evidovat
    členství uzlů, jejich LAN prefixy, role, požadovanou dosažitelnost a policy.
    NetBird má být vykonavatelem transportu a rout, nikoli primární evidencí
    logické topologie federace.
  - [ ] Z modelu Federation generovat/aktualizovat NetBird network routes a
    access policies: LAN prefix lokality musí být publikován přes správný Turris
    routing peer a pouze požadovaným členům/skupinám.
  - [ ] Před publikací do NetBirdu nadále validovat duplicity a překryvy LAN
    prefixů, konfliktní routy a neúplnou topologii; chybný model nesmí být
    automaticky propagován do transportní vrstvy.
  - [ ] Preferovat skutečné site-to-site routování bez masquerade tam, kde je
    možné zajistit korektní obousměrné routy; NAT ponechat jako explicitní
    volitelnou vlastnost konkrétního propojení, nikoli výchozí model federace.
  - [ ] Navrhnout abstrakci transportního backendu tak, aby datový model uzlů,
    LAN sítí, membership, validace, health a UI nebyly svázány se ZeroTier ani
    s konkrétní implementací WireGuardu.
  - [ ] Po migraci odstranit z běžného modelu Federation údaje, jejichž jediným
    účelem byla vlastní orchestrace `tf_wg`; zachovat pouze vazbu uzlu na
    odpovídající NetBird peer/identitu.
  - [ ] Health stav Federation skládat z logického stavu požadované topologie a
    skutečného stavu NetBird peerů/rout, aby bylo rozlišitelné „konfigurace je
    správně publikována“ od „transport je právě dostupný“.

- [ ] **P2: Pokročilé síťování a výkon.**
  - [ ] Implementovat IPv4 routování přes IPv6 nexthop ve WireGuardu (provoz bez přidělených IPv4 adres na tunelech).
  - [ ] Šetřit úložiště na Turrisu: minimalizovat zápisy na eMMC, snížit periodu ukládání stavu na minimum.
- [ ] **P2: Discovery a mobilita.**
  - [x] Discovery notebooků: podepsané beacony po 30 s na vybraném IPv4 rozhraní,
    přehled v UI a ruční párovací údaje jako alternativa k multicastu.
  - [ ] Discovery routerů: oznámení po 30 minutách.
  - [x] Obousměrná synchronizace nastavení a řídicí identity mezi vzájemně
    spárovanými notebooky přes mutual TLS, bez centrálního uzlu. Konflikty se
    řeší výslovným výběrem verze; lokální SSH důvěra a audity se zachovávají.
    Viz [postup a omezení](docs/notebook-sync.md).
  - [ ] Ověřit discovery, párování, předání správy a návrat offline notebooku
    na dvou skutečných zařízeních přes LAN a ZeroTier.
  - [ ] Rotace párovacích certifikátů a odvolání již předaného řídicího klíče.

## Nejbližší postup

1. Na routeru ověřit ZeroTier kontrolu → případnou instalaci/nastavení → autorizaci na webu → členství OK a adresu.
2. Potvrdit zachování identity a členství po restartu a dostupnost přes požadovanou správcovskou cestu.
3. Před deployem opravit sběr citlivých dat a zbývající případy neúplného auditu.
4. Navrhnout konkrétní deploy na dvou uzlech: topologii, routy, firewall a WireGuard, včetně náhledu změn.
5. Zavést potvrzenou aplikaci plánu, kontrolní audit a rollback. Implementovaný deploy zatím není ověřený na routerech.
