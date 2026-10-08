# Turris Federation — roadmapa a TODO

Aktualizováno: 8. 10. 2026.

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

## Kontrola deploye a aktuální TODO (20. 9. 2026)

- [x] Doplnit do WebApps veřejné Zlaté stránky a PAM chráněný přehled routeru;
  instalovat i aktualizovat přes LAN a vynutit oddělení cest v lighttpd.
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
  neúspěšné aktualizaci. Aktualizace skutečného routeru `Palackeho` po doplnění
  transakční obnovy prošla 7. 10. 2026; zbývá cíleně ověřit ztrátu LAN,
  odmítnutí přechodu na ZeroTier a obnovu po jednotlivých typech selhání.

- [x] Deploy controller a routerový agent jsou implementované: podepsané revize,
  validace plánu, SSH instalace, UCI záloha a watchdog, synchronizace přes ZeroTier.
- [x] Opravit souběh přijetí nové revize a nepotvrzené změny: nová revize musí
  počkat na potvrzení/rollback; potvrzení musí patřit právě aplikované revizi.
- [x] Přidat tento notebook do přehledu jako místní řídicí uzel pouze pro kontrolu
  ZeroTier. V této původní etapě neměl WireGuard peery, tunelovou adresu ani
  routerový deploy; koncové VPN připojení doplňuje následující úkol.
- [ ] **P1: Rozdělit notebooky na administrátorské a uživatelské síťové uzly.**
  Oba typy budou plnohodnotné koncové uzly VPN, ale bez inzerovaných LAN prefixů,
  forwardingu nebo masquerade mezi VPN a fyzickou sítí. Administrátorský notebook
  navíc smí kontrolovat a nasazovat routery; uživatelský notebook získá pouze
  síťové pověření a nikdy kořenovou řídicí identitu. Dostupnost každého notebooku
  se ověřuje pouze lokálně na něm, ne z routerů. Backend poběží trvale jako
  uživatelská služba oddělená od UI; stavová lišta ukáže stav připojení a otevře
  jedinou instanci UI, zatímco zavření okna službu ani VPN neukončí. Návrh a
  akceptační hranice:
  [role notebooků](docs/notebook-node-roles.md).
  - [x] Implementovat základ `systemd --user` backendu, privátní read-only Unix
    socket, instalaci/odstranění, tray menu a skrytí UI při zavření. Zapnutí
    synchronizace nyní službu automaticky nainstaluje a povolí; dříve pouze
    spustilo proces svázaný s UI, takže po přihlášení backend nenaběhl. Při
    prvním spuštění nové verze se již zapnutý starší backend na službu převede;
    existující vypnutá, zastavená nebo na starou vývojovou cestu odkazující
    jednotka se znovu nastaví, povolí a spustí. Přijetí uživatelské pozvánky
    službu instaluje bez požadavku na adresu místní LAN; administrátorská přímá
    synchronizace přijímá jen stabilní adresu rozhraní ZeroTier. Migrace podle
    platného členství pokrývá i uživatelské notebooky přijaté před zavedením
    automatické instalace a případnou chybu služby ukáže v UI.
  - [ ] Ověřit instalaci, automatický start, restart po pádu, stavovou lištu a
    odstranění služby v reálné grafické uživatelské relaci. První zkouška
    odhlášení/přihlášení na KDE Wayland odhalila uvozovky v poli `TryExec`,
    kvůli kterým systemd XDG generátor hledal neexistující název binárky.
    Pole bylo odstraněno. Instalace i odstranění autostartu navíc provádějí
    `daemon-reload`, protože při zapnutém lingeru uživatelský `systemd` přežívá
    odhlášení. Následné otevření odhalilo, že binárka `tauri dev` vyžaduje Vite
    na localhostu; `run.sh` proto pro autostart atomicky instaluje samostatný
    testovací build s vloženým frontendem. Pokus o zavření okna navíc ukončil
    celý tray proces, proto životní cyklus blokuje implicitní exit a okno
    skryje; proces lze cíleně ukončit jen položkou v tray. Opakovaná zkouška
    potvrdila, že po zavření okna a odhlášení/přihlášení aplikace znovu naběhne
    do stavové lišty. Skutečná zkouška `SIGKILL` hlavního procesu backendu
    potvrdila automatický restart služby (`NRestarts=1`), nový PID, obnovený
    socket s oprávněním `0600`, zachované pověření a stále běžící tray klient.
    Restart celého notebooku a odstranění služby zůstávají k ověření.
  - [x] Doplnit jedinou instanci UI, barevné stavové ikony a potvrzovanou akci
    pro odpojení notebooku přímo ze stavové lišty. Druhé spuštění nyní přes
    privátní uživatelský socket zobrazí existující okno; stav ikony vychází
    z lokálního backendu a čerstvé VPN diagnostiky. Odpojení po potvrzení vrátí
    spravovaný VPN profil a zastaví synchronizační službu bez smazání identity.
  - [~] Uživatelské roli zobrazit read-only přehled odpovídající routerové
    stránce; administrátorské UI už obsahuje stejný read-only přehled jako
    samostatnou úvodní záložku. Backend ověřuje podepsané pověření svázané
    s TLS identitou a federací, administrátorské mutace bez něj odmítá a UI
    skryje správní záložky. Read-only přehled používá samostatné sanitizované
    API sestavené jen z podepsané revize a nevrací SSH ani deploy metadata.
    Uživatelský notebook vytvoří podepsanou žádost bez předchozí znalosti
    federace. Administrátor mu nejprve vydá dočasné podepsané povolení s
    Network ID; notebook se připojí do ZeroTier a po autorizaci podepíše svou
    skutečně přidělenou adresu a Device ID. Teprve druhé potvrzení administrátora
    publikuje členství a vydá finální pověření. Přenáší se jen veřejná
    kotva, podepsané zprávy a topologie, nikdy `root.pem`; nedokončený pokus
    nevytváří člena s odhadnutou adresou.
    Vývojová implementace nyní přenáší jednotlivé fáze automaticky ve stejné
    fyzické LAN: časově omezené multicast discovery, krátký porovnávací kód a
    TCP/8857 pouze z přímo připojeného fyzického subnetu. Cílový notebook si
    zprávy vyzvedává odchozím spojením od administrátora, takže jeho příchozí
    firewall nevyžaduje změnu. Device ID se vrací
    podepsané ještě před autorizací a administrátor zachovává obě potvrzení.
    Ruční přenos celých JSON balíčků zůstává jako nouzový fallback. Přidání
    nového uživatelského notebooku přes skutečnou LAN po opravách discovery,
    výběru rozhraní a enrollment session prošlo 7. 10. 2026. Samostatně ještě
    zbývá fyzická akceptace jeho VPN profilu a end-to-end provozu.
    Podepsané schéma 2 eviduje routery a zvlášť koncové notebooky s rolí, bez
    možnosti inzerovat notebookovou LAN. Bootstrap zapíše administrátorský
    notebook a vydání pozvánky atomicky publikuje uživatelský notebook v nové
    revizi; staré routerové schéma 1 zůstává přijímané. Schéma 3 navíc váže
    notebook na lokálně vytvořený veřejný WireGuard klíč a přidělené ZeroTier/WG
    adresy. Pozvánka vytvoří privátní koncovou konfiguraci; router pro notebook
    přijme jen jeho `/32` a jeho handshake nehodnotí jako dostupnost federace.
    UI nyní před instalací zobrazí deset minut platný plán a přes polkit spouští
    pouze systémový `nmcli`. Plán nejprve ověří přidělenou ZeroTier adresu a
    cesty k routerům přes konkrétní `zt…` rozhraní. NetworkManager profil
    nepřidává výchozí trasu a federované routy mají nižší prioritu než přímo
    připojená fyzická LAN stejného prefixu. Zapnutý nebo neověřitelný IP forwarding je
    viditelné varování, ale instalaci neblokuje ani ho nemění. Předchozí profil
    zůstává jako obnovovací kopie pro automatický i ruční
    rollback. Tok je pokrytý lokálními testy, ale nebyl spuštěný s reálným
    polkit agentem ani VPN. Podepsaný přenosný balíček nyní umožní uživatelskému
    notebooku zobrazit novější revizi a přesný rozdíl rout před potvrzením;
    starou revizi, jinou federaci, cizí WireGuard klíč nebo změnu role odmítne.
    Potvrzená aktualizace vymění NetworkManager profil a přijme topologii až po
    ověření adresy a rout, při selhání obnoví profil i revizi. Místní
    diagnostika nyní kontroluje profil, rozhraní, adresu, forwarding, routy,
    handshake a pět WG pingů; cíle přijímá jen z podepsané revize a výsledek
    označí po 120 sekundách jako zastaralý. Administrátor může uživatelskému
    notebooku po potvrzení odvolat členství novou podepsanou revizí; tím zmizí
    jeho `/32` peer z příštího routerového deploye, ale místní identita ani data
    notebooku se nemažou. Odvolaný notebook přijme podepsanou revizi jen dokud
    je jeho dosavadní členství platné, odpojí spravovaný VPN profil a potom už
    další aktualizace nepřijme. Tok je lokálně otestovaný; zbývá fyzická
    akceptace s reálným polkit agentem, NetworkManagerem, VPN a routerem.
    Finální pozvánka a export aktualizace nyní obsahují také kořenovou identitou
    podepsaný, znovu validovaný read-only snapshot routerových katalogů a verzí
    notebooků. Uživatelský notebook jej může přijmout i při stejné revizi
    topologie bez změny VPN nebo rout. Verze uživatelského notebooku pochází
    z jeho vlastním TLS klíčem podepsaného potvrzení adresy; nepřidává notebook
    mezi administrátorské synchronizační peery. Fyzické předání snapshotu
    mezi dvěma notebooky zůstává k ověření.
    Kontrola na `gx10-efde` po vyřešení konfliktu odhalila, že sync správně
    přenesl podepsanou revizi 10 se členy `Cacke` a `Palackeho`, ale aktivní
    NetworkManager profil zůstal na revizi 9. Generátor instalačního plánu navíc
    dříve znovu použil starý `wireguard.conf`, pokud už existoval. Oprava vždy
    sestaví kandidátní konfiguraci z právě ověřené podepsané revize, porovná
    revizi, adresu, množinu rout i hash celé WireGuard konfigurace s instalačním
    potvrzením a v přehledu zobrazí
    stav **VPN profil vyžaduje aktualizaci**. Tray je do potvrzené výměny profilu
    nejvýše ve stavu omezeného připojení. Živá read-only kontrola opravy na gx10
    rozpoznala instalovanou revizi 9 se dvěma routami proti revizi 10 se čtyřmi
    routami, včetně Palackého `10.203.0.84/32` a `192.168.1.0/24`. Skutečná
    instalace nového profilu a následný end-to-end provoz zůstávají k fyzickému
    ověření po aktualizaci aplikace a routerů.
    Kontrola cestovního notebooku `tony` následně ukázala platné členství,
    běžící backend a ZeroTier, ale žádný uložený NetworkManager profil
    `turris-federation`; všechny federované cíle proto používaly běžnou výchozí
    Wi-Fi trasu. Stav VPN nově porovnává instalační záznam se skutečným profilem
    NetworkManageru a rozlišuje `active`, `inactive`, `missing` a `unknown`.
    Chybějící nebo neaktivní profil zobrazí jako nedokončené/porouchané místní
    nastavení a tray jej nesmí vydávat za připojení. Nová vývojová implementace
    přesouvá instalaci i průběžnou opravu profilu do omezené systémové síťové
    služby. Uživatelský backend jí po lokálním ověření podpisu posílá pouze
    přesné schéma s jednou `/32`, privátními endpointy a nepřekrývajícími se
    privátními routami; služba zakazuje default route, zapíná autoconnect,
    kontroluje skutečnou adresu a routy a při chybě obnoví předchozí profil.
    Statický polkit plán zůstává dočasný fallback. Lokální testy prošly, ale
    automatické vytvoření profilu, změna hotspotu a end-to-end provoz na `tony`
    ještě vyžadují fyzickou akceptaci.
    První živé spuštění na `gx10-efde` odhalilo, že Ubuntu AppArmor profil
    `unprivileged_userns` odmítá backendu spojení k rootem vlastněnému Unix
    socketu navzdory správné skupině a režimu `0660`. Generovaná uživatelská
    jednotka proto nepoužívá mount-namespace direktivy `ProtectSystem`,
    `ProtectHome` ani `PrivateTmp`; ponechává neprivilegovaný proces,
    `NoNewPrivileges`, omezení síťových rodin včetně `AF_NETLINK` potřebného
    nástrojem `ip` a zákaz dalších namespaces.
    Root síťová služba navíc vytváří dočasný WireGuard import ve svém systemd
    `RuntimeDirectory`, protože obecný `/run` je při `ProtectSystem=strict`
    záměrně jen pro čtení.
    Synchronizace spárovaných notebooků po jejich přidání do podepsané topologie
    používá stabilní ZeroTier adresu z této topologie, nikoli historickou LAN
    adresu zachycenou při prvním párování.
  - [ ] Po funkčním ověření na skutečných zařízeních připravit produkční
    instalaci notebooku: podepsaný `.deb` pro první Ubuntu/Debian ARM64,
    dodanou uživatelskou jednotku, autostart tray, jednorázové pozvání, lokální
    identitu a bezpečnou aktualizaci/odinstalaci. Balíčkování do dokončení
    funkčních a end-to-end testů odkládáme. Návrh:
    [instalace notebooku](docs/notebook-installation.md).
  - [~] Oddělit privilegovanou síťovou vrstvu notebooku do systémové služby.
    Vývojová implementace poskytuje sanitizovaný ZeroTier stav, omezené
    join/leave, nftables guard, automatický reconcile NetworkManager/WireGuard
    profilu a instalaci/aktualizaci z `run.sh`; zbývá fyzická akceptace,
    produkční oprávnění socketu a ověření odvolání členství.
    Návrh: [síťová služba notebooku](docs/notebook-network-service.md).
- [ ] **P0: Nasazení ZeroTier podle hlášení uživatele nefunguje.** Získat výstup
  selhání a verzi Turris OS, reprodukovat, opravit instalaci/nastavení a ověřit
  autorizaci i restart. Oprava ZeroTier je zatím odložená do TODO.
- [ ] **P0: Ověřit deploy na dvou skutečných routerech**, včetně výpadku SSH,
  firewallu, restartu během změny a obnovení ze zálohy. Lokální testy toto nenahrazují.
- [x] **P0: Ověřit první skutečné WireGuard propojení dvou přijatých routerů.**
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
- [x] Oddělit ZeroTier do zóny `tf_zt` (input/forward REJECT, output ACCEPT);
  WireGuard UDP/51830, sync TCP/8844 a diagnostický IPv4 ping povolit pouze z IP přijatých peerů.
  Zachovat `lan ↔ tf_fed`, bez obecného forwardingu `tf_zt ↔ lan`.
  Validovat skutečné ZeroTier zařízení a jeho IP; pokrýt regresními testy.
- [~] Na routerech ověřit výsledný firewall a explicitní přístup notebooku.
  Cacké odhalilo duplicitní přiřazení ZeroTier zařízení do `vpn_zerotier` a
  `tf_zt`: první nftables skok obešel pravidla druhé zóny. Generátor nyní bezpečnou
  existující zónu znovu použije a duplicitního vlastníka nevytvoří; opakovaný
  deploy a WireGuard handshake na fyzickém routeru ještě zbývá potvrdit.
- [x] **P1: Webová služba přes ZeroTier port routeru.** Ve Zlatých stránkách u
  místní `http`/`https` služby je dočasná volba pro telefon:
  `ZeroTier IP routeru:vstupní port → LAN IP aplikace:cílový port`. Přístup má
  kterékoliv zařízení v ZeroTier síti i bez členství ve federaci. Správce zadá
  jen vstupní TCP port; rozhraní, zónu, adresu routeru a cíl převezme agent z
  ověřeného stavu a validované služby. Vytvoří pouze konkrétní DNAT, nikdy
  obecný forwarding `tf_zt ↔ lan`, WAN nebo vstup přes `tf_wg`. Podepsaný
  katalog zveřejní endpoint **Přes ZeroTier router**. Změny musí
  odmítat kolize, mít rollback a při odstranění služby uklidit pravidlo.
  Podrobnosti jsou v [Zlatých stránkách služeb](docs/service-directory.md).
- [ ] Na skutečném routeru a telefonu bez členství ve federaci ověřit DNAT,
  restart firewallu, kolizi portu a úklid po odstranění služby.
- [x] Po přijetí druhého routeru ověřit `wg show`, vznik peerů, `latest handshake`,
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
- [x] **P1: Sdílený katalog hostů podle uzlu.** Každý přijatý router oznamuje
  ve svém podepsaném provozním stavu pasivně známé IPv4 sousedy z vlastních LAN
  prefixů. DHCP názvy jsou volitelné, MAC adresy se nesdílejí a aktivní skenování
  se nespouští. Katalog je vidět pod uzlem v desktopu i routerovém WebApps přehledu.
- [ ] Na dvou skutečných routerech ověřit naplnění katalogu, jeho obnovu po změně
  sousedů, stáří při výpadku protějšku a zobrazení v desktopu i WebApps.
- [ ] **P2: Zlaté stránky služeb.** Na každém routeru umožnit místnímu správci
  přiřadit k hostům ve vlastních LAN prefixech pojmenované `tcp`, `http` a
  `https` služby s validním portem. Podepsané katalogy přijatých routerů složit
  do jednoho read-only seznamu dostupného na všech noteboocích a routerech.
  HTTP(S) položky otevírat bezpečně v systémovém prohlížeči; vložené zobrazení
  povolit až po samostatném ověření izolace webview. Návrh dat, oprávnění,
  validace a etap je v [Zlatých stránkách služeb](docs/service-directory.md).
  Zobrazení, filtrování a otevírání služeb je ověřené v desktopové
  aplikaci i na skutečném Turrisu; samotné Zlaté stránky jsou uzavřené.
  Otevřená zůstává fyzická akceptace přenosu katalogu na uživatelský notebook.
  - [x] Implementovat přesný formát, validaci vlastnictví LAN adresy, atomické
    místní úložiště a PAM/CSRF WebApps editor na jednotlivém routeru.
  - [x] Přidat služby do podepsaného provozního reportu, ověřenou agregaci,
    zachování stáří při výpadku a odstranění katalogu po odvolání routeru.
  - [x] Zobrazit jednotný read-only seznam v desktopu a WebApps, doplnit filtry
    a kopírování přesně validovaného endpointu. V desktopu je katalog první
    samostatná záložka pro uživatele i administrátora; na routeru je výchozí
    veřejnou záložkou před PAM chráněným přehledem.
  - [x] HTTP(S) endpoint otevírat v systémovém prohlížeči bez shellu; povolit
    pouze doslovnou IPv4 URL, platný port a validovanou cestu bez přihlašovacích
    údajů, query nebo fragmentu. TCP endpoint zůstává pouze ke kopírování.
  - [x] Zpřístupnit ověřený katalog také uživatelským notebookům bez místní
    administrační cache reportů přes rootem podepsaný read-only snapshot ve
    finální pozvánce a aktualizačním balíčku, bez předání kořenového privátního
    klíče nebo správcovského oprávnění.
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

  - [ ] **Vylepšené porovnání (Diff):** Implementovat přehledné "side-by-side" zobrazení rozdílů mezi návrhem a skutečným stavem routeru pro konfiguraci, adresy i routy.
- [ ] **P1: Návrh a automatizace sítě.**
  - [x] Implementována volba globálních subnetů pro ZeroTier a WireGuard.
  - [x] Implementováno inteligentní navrhování a hromadné doplňování tunelových adres (WireGuard/ZeroTier) s kontrolou kolizí a vazbou na poslední oktet.
  - [ ] Ověřit automatické doplňování adres po reálném auditu routeru se ZeroTier.

## 3. P1 — navrhnout síť federace a plán změn

- [ ] Potvrdit role ZeroTier a WireGuard: discovery/správa, datový provoz a požadovaná topologie.
- [ ] Doplnit model federace: členství, síťové identifikátory, adresní plán a vztahy mezi uzly.
- [x] Implementovat ZeroTier členství ve společné uložené síti a ruční autorizaci routerů na webu Central.
- [ ] Ověřit instalaci, autorizaci a zachování ZeroTier identity/členství po restartu na skutečném Turris OS.
- [ ] Navrhnout WireGuard peery, endpointy, `AllowedIPs`, směrování a pravidla firewallu.
- [ ] **Ověřit životní cyklus WireGuard peeru podle členství:** draft uzel nesmí
  být nasazen jako peer; po přijetí člena musí vzniknout peer na relevantních
  routerech a po odvolání musí být bezpečně odstraněn.
- [x] **První ověřený transport:** použít ZeroTier IPv4 adresu peeru jako WG endpoint
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
- [ ] Balíček desktopové aplikace a ověřená matice podporovaných OS/architektur;
  začít používaným Ubuntu/Debian ARM64. Podrobnosti:
  [instalace notebooku](docs/notebook-installation.md).

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
  - [ ] **Spojit NetBird PoC s mobilním uživatelským uzlem.** Nejprve použít
    oficiální Android klient a na Linux ARM64 telefonu NetBird CLI/daemon;
    aplikace Federation poskytne členství, read-only stav, Zlaté stránky a
    lokální diagnostiku, nikoli druhou vlastní VPN. Telefon nesmí inzerovat svou
    síť, routovat provoz ani získat administrátorská oprávnění. Návrh etap,
    identity, odvolání a akceptace:
    [mobilní klient při migraci na NetBird](docs/mobile-client-netbird.md).

- [ ] **P2: Pokročilé síťování a výkon.**
  - [ ] Implementovat IPv4 routování přes IPv6 nexthop ve WireGuardu (provoz bez přidělených IPv4 adres na tunelech).
  - [ ] Šetřit úložiště na Turrisu: minimalizovat zápisy na eMMC, snížit periodu ukládání stavu na minimum.
- [ ] **P2: Discovery a mobilita.**
  - [x] Discovery notebooků: podepsané beacony na jednom nebo více výslovně
    vybraných fyzických IPv4 rozhraních, přehled aktivních listenerů v UI a
    ruční párovací údaje jako alternativa k multicastu. Registrační discovery
    na UDP/8857 obnovuje členství při změně výběru nebo adresy rozhraní.
  - [ ] Discovery routerů: oznámení po 30 minutách.
  - [x] Obousměrná synchronizace nastavení a řídicí identity mezi vzájemně
    spárovanými notebooky přes mutual TLS, bez centrálního uzlu. Konflikty se
    řeší výslovným výběrem verze; lokální SSH důvěra a audity se zachovávají.
    Viz [postup a omezení](docs/notebook-sync.md).
  - [ ] Ověřit discovery, párování, předání správy a návrat offline notebooku
    na dvou skutečných zařízeních přes LAN a ZeroTier.
  - [ ] Rotace párovacích certifikátů a odvolání již předaného řídicího klíče.
  - [ ] Ověřit roaming mobilního NetBird uzlu mezi Wi-Fi a mobilními daty,
    uspání/restart, background provoz, odvolání a obnovu přímé/relay cesty bez
    změny jeho uživatelské role.
- [ ] **P2: Robustnost a obnova dat.**
  - [ ] Implementovat "Reverse Sync": možnost obnovit lokální databázi notebooku z dat uložených na routerech (routery jako zrcadla konfigurace).
  - [ ] Zjistit příčinu a analyzovat neočekávaně velký objem datových přenosů v rámci federace (monitoring provozu `tf_wg` a `tf_zt`).
  - [ ] Indikace a ošetření offline stavu notebooku v rámci topologie.
  - [ ] Vyřešit stabilitu webového GUI při deployi: prověřit chování `lighttpd` při restartu síťových služeb, aby nedocházelo k "vytuhnutí" UI (točící se kolečko) nebo rozbití LuCI při přerušení spojení či konfliktu modulů.
  - [ ] Detekce a řešení konfliktů při synchronizaci mezi více notebooky.

## Nejbližší postup

1. Na routeru ověřit ZeroTier kontrolu → případnou instalaci/nastavení → autorizaci na webu → členství OK a adresu.
2. Potvrdit zachování identity a členství po restartu a dostupnost přes požadovanou správcovskou cestu.
3. Před deployem opravit sběr citlivých dat a zbývající případy neúplného auditu.
4. Navrhnout konkrétní deploy na dvou uzlech: topologii, routy, firewall a WireGuard, včetně náhledu změn.
5. Zavést potvrzenou aplikaci plánu, kontrolní audit a rollback. Implementovaný deploy zatím není ověřený na routerech.
