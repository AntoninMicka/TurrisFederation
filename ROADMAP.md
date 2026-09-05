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
Routerový agent a aplikování konfigurace nejsou implementované.

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

## Nejbližší postup

1. Na routeru ověřit ZeroTier kontrolu → případnou instalaci/nastavení → autorizaci na webu → členství OK a adresu.
2. Potvrdit zachování identity a členství po restartu a dostupnost přes požadovanou správcovskou cestu.
3. Před deployem opravit sběr citlivých dat a zbývající případy neúplného auditu.
4. Navrhnout konkrétní deploy na dvou uzlech: topologii, routy, firewall a WireGuard, včetně náhledu změn.
5. Zavést potvrzenou aplikaci plánu, kontrolní audit a rollback. Deploy zatím není implementovaný.
