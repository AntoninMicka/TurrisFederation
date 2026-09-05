# Deploy a synchronizace nastavení

Architektonický návrh, aktualizace kontroly 5. 9. 2026. Část chování je již
implementovaná; níže uvedený návrh zahrnuje i dosud nedokončené funkce.

## Instalace a aktualizace pouze v přímé LAN

Instalace i opakovaný deploy (aktualizace agenta) vyžadují notebook připojený
přímo přes fyzický Ethernet nebo Wi-Fi do LAN cílového routeru. SSH adresa
musí být číselná IPv4 z LAN uvedené v draftu. Controller kontroluje skutečnou
trasu bez brány a lokální adresu ve stejném subnetu; odmítá virtuální rozhraní,
ZeroTier, WireGuard i cestu přes jiný router. V této verzi nejsou pro deploy
podporované hostname, IPv6 ani virtuální bridge/VLAN rozhraní notebooku.
Neprokazatelná cesta znamená zastavení, nikoli náhradní cestu přes ZeroTier.

Kontrola se opakuje před každým SSH krokem včetně instalátoru, aktualizace,
potvrzení a restartu služby. SSH je vázané na ověřené rozhraní a zdrojovou
adresu. Plán obsahuje LAN adresy/rozhraní a otisk konkrétního agenta i jeho
služby; změna připojení nebo artefaktu plán zneplatní. Starší plány bez těchto
údajů je nutné znovu validovat. U přijatého uzlu UI nabízí aktualizaci agenta
přes LAN. Aktualizace používá stejné kontroly identity a zachovává klíče;
předchozí soubor agenta je uložen jako `.previous`. Nejde o automatický
rollback softwaru ani o aktualizaci celého Turris OS.

ZeroTier synchronizační kanál přenáší jen podepsané síťové nastavení
(topologii, adresy, členství a veřejné klíče) a provozní potvrzení/stav.
Nemá operaci instalace ani aktualizace softwaru. Dokument s dodatečnými poli
pro software nebo příkazy agent odmítne. Publikování síťových změn nevolá SSH
instalátor. Běžné kontroly routerů přes SSH tímto omezením deploye nejsou změněné.

Webový přehled, ikona a dlaždice na úvodní stránce Turrisu jsou součástí
stejného LAN instalačního/aktualizačního artefaktu. Konfigurace lighttpd se
kontroluje před reloadem; při selhání se obnoví předchozí webové soubory.
Viz [webový přehled](router-web.md).

## Výsledek kontroly implementace

Controller i agent jsou v `router/files/usr/lib/turris-federation/federation.py`,
Tauri rozhraní v `src-tauri/src/deployment.rs`. Implementace zahrnuje podepsané
snímky konfigurace, přijetí routeru přes SSH, validovaný plán s desetiminutovou
platností, kontrolu změny UCI od validace, instalaci, WireGuard přes ZeroTier,
UCI zálohu a rollback a předávání revizí mezi routery. Import slučuje drafty
podle ID a zachovává lokální SSH důvěru; audit již nesbírá privátní WG klíče.

Při kontrole byla opravena záměna revizí během nepotvrzeného deploye:
`accept` odmítne novější revizi, dokud je rozpracovaná předchozí, a `confirm`
kontroluje shodu přijaté a rozpracované revize. Dva regresní testy pokrývají
odmítnutí nové revize i odmítnutí nesprávného potvrzení.

Notebook se zobrazuje automaticky jako místní řídicí uzel. Akce kontroly
čte místní ZeroTier službu a členství v uloženém Network ID. Nevytváří členství,
neinstaluje software ani nemění síť. Notebook není položkou routerového seznamu
`members`, proto se nedostane mezi WireGuard peery ani cíle deploye. Stav se
načítá na vyžádání; nedostupná služba nebo chybějící oprávnění nejsou úspěchem.
Kontrola členství sama neprokazuje dosažitelnost všech routerů.

HTTP obsluha běží v samostatném vlákně a odpovídá i během odchozí
synchronizace. Předběžné kontroly `stage` a kontroly zdraví při potvrzení
či periodické synchronizaci běží mimo zámek. Před uložením výsledku se znovu
ověřuje příslušná revize, rozpracovaná operace a otisk konfigurace; opožděné
potvrzení nesmí přepsat rollback. Fáze `applying` nepřipouští potvrzení.

Zápisové příkazy aplikování se zamykají jednotlivě. Před každým příkazem
se kontroluje token a platnost operace, takže po rollbacku starý proces
nemůže pokračovat v zápisu. Timeout příkazu je nejvýše 30 s a současně
nejvýše zbývající doba do deadline; při timeoutu se ukončí jeho procesní
skupina před uvolněním zámku. Watchdog může provést obnovu mezi příkazy.
Samotná obnova zůstává zamčená, včetně restartu služeb; `ifup`/`ifdown` mají
nově timeout 30 s. Selhání obnovy ponechá rozpracovanou operaci pro další
pokus při restartu. Lhůta 120 s proto není pevnou mezí dokončení obnovy:
přičítá se interval watchdogu, obnova souborů a běh služeb.

Lokální testy ověřují HTTP během synchronizace, rollback během health
kontroly, změnu revize během předběžné kontroly, odmítnutí starého zápisu
po obnově a ukončení potomka zaseknutého příkazu. Časování a zotavení na
skutečných routerech zbývá ověřit. Automatická rotace nakonfigurovaných
WG klíčů, šifrovaná záloha identity a provozní ověření zůstávají otevřené.
Nasazení ZeroTier je podle uživatele nefunkční; oprava je odložená do
[TODO](../ROADMAP.md). Deploy nelze považovat za provozně ověřený.

## Deploy druhé Omnie a aktualizace nastavení první

Notebook nasadí software druhé Omnie přes její přímou LAN a podepíše novou
revizi obsahující oba přijaté členy. Po potvrzení deploye a spuštění služby
zkusí tutéž revizi odeslat ostatním přijatým routerům přes ZeroTier. Chyba
spojení s prvním routerem nezruší úspěšný deploy druhého; v přehledu zůstane
poslední známý stav prvního routeru s chybou dostupnosti.

Agent druhé Omnie v pravidelné synchronizaci nejprve odešle svou podepsanou
revizi sousedovi a pak zkusí stáhnout jeho revizi. To řeší první přijetí:
první Omnia dosud druhou nemá ve svém seznamu členů, a sama by od ní nic
nestahovala. Příjem `/bundle` ověřuje podpis notebooku, proto lze touto cestou
bezpečně doručit i rozšířený seznam členů. Router novou konfiguraci sám
aplikuje a potvrzuje stávajícím mechanismem včetně watchdogu. Přenos ani
potvrzení nevyžadují, aby notebook zůstal připojený.

Při nedostupnosti, odmítnutí starší revize nebo čekající předchozí operaci
se další pokus uskuteční v následujícím synchronizačním cyklu. Odmítnutý
push neblokuje stažení novější konfigurace. Obě zařízení potřebují funkční
ZeroTier IPv4 cestu a povolený TCP/8844. Aktualizace softwaru první Omnie
se tímto neprovádí; ta nadále vyžaduje přímou LAN.

Přijetí revize není potvrzením aplikování ani WireGuard spojení. V přehledu
je nutné porovnat požadovanou, přijatou a aplikovanou revizi. Místní přehled
ukazuje uložené výsledky; akce „Podepsat a synchronizovat opravy“ znovu
zkusí doručení a načte stav dostupných členů. Lokální testy pokrývají přenos
nového členství mezi dvěma úložišti, opakování po nepotvrzené změně,
stažení novější revize po odmítnutém odeslání a deploy s nedostupným prvním
routerem. Ověření celého scénáře na dvou Omniích zbývá provést.

## Původní návrh

Potvrzený rozsah: deploy aplikací přes notebook, notebook jako kotva důvěry,
synchronizace nastavení federace včetně WireGuardu a rout a automatická
rotace komunikačních klíčů mezi routery i bez připojeného notebooku.

## Výchozí stav

Desktop ukládá inventář a ZeroTier nastavení v SQLite a provádí jednotlivé
SSH příkazy s ověřením host klíče. Routerový agent je nyní implementovaný (viz aktualizace výše).
Export/import není synchronizační protokol: aktuální import slučuje drafty
a zachovává SSH důvěru; export obsahuje požadovaná nastavení.
Pro sync je nutné oddělit požadovanou konfiguraci od lokálních pozorování.

## Navržené chování

- Desktop vytváří novou revizi požadované konfigurace federace.
- Router přijme revizi, ověří její původ a uloží ji atomicky. Přijetí
  konfigurace a její aplikování jsou samostatné operace.
- Propojené routery si mohou předat tutéž autorizovanou revizi i při
  vypnutém desktopu. Přeposlání nesmí měnit autora ani obsah revize.
- Desktop po připojení načte stav revizí a výsledky aplikování z routerů.
- Každý router aplikuje jen svou část konfigurace. LAN adresy, identity
  a klíče jednotlivých routerů se nekopírují na ostatní uzly.

Notebook autorizuje členství, aplikace a požadovanou síťovou konfiguraci.
Router může publikovat vlastní provozní stav a rotaci svých komunikačních
klíčů v mezích oprávnění uděleného notebookem. Nemůže tím měnit členství,
cizí klíče ani přidělené LAN sítě. Instalace a aktualizace aplikací probíhá
přes notebook přímo v LAN cílového routeru; automatický sync mezi routery přenáší nastavení a oznámení
klíčů. Provoz již nasazené federace není závislý na dostupnosti notebooku.

## Notebook jako kotva důvěry

Notebook uchovává privátní kořenový podpisový klíč federace. Na routery
instaluje pouze jeho veřejnou část, schválené aplikace a podepsané pověření
konkrétního uzlu. Kořenový klíč není součástí běžného exportu nastavení;
obnova notebooku vyžaduje samostatnou šifrovanou zálohu této identity.

Při prvním deployi se ověří SSH otisk. Agent vytvoří vlastní privátní
identitu přímo na routeru, prokáže její držení a notebook podepíše vazbu
veřejné identity na ID uzlu, federaci a oprávnění. Ostatní routery přijmou
uzel na základě tohoto pověření. Přenos přes ZeroTier tuto kontrolu nenahrazuje.

Ztráta nebo kompromitace identity routeru vyžaduje odvolání pověření
notebookem a nové přijetí zařízení. Rotace běžných komunikačních klíčů
nemění kořenovou důvěru ani dlouhodobou identitu uzlu. Odvolání se šíří
jako podepsaná, verzovaná změna; odpojený uzel ho může uplatnit až po
doručení. Obnova ze zálohy nesmí umožnit vrátit již přijatou verzi důvěry.

## WireGuard, routy a rotace

Notebook podepisuje topologii, tunelové adresy, vlastnictví LAN prefixů,
peery, endpointy a povolené routy. Agent z nich odvodí konfiguraci svého
routeru, včetně `AllowedIPs` a nezbytných pravidel firewallu. Před aplikací
odmítne konfliktní prefixy a neautorizované změny směrování. Výchozí trasa
se nepřesměrovává, pokud ji plán výslovně neobsahuje.

Rozlišujeme tři vrstvy klíčů:

- Kořenová identita notebooku autorizuje federaci.
- Dlouhodobá identita routeru podepisuje jeho provozní oznámení.
- Komunikační klíče se automaticky obnovují podle podepsané politiky.

WireGuard již automaticky obnovuje relační šifrovací klíče pomocí
handshake; tuto část zajišťuje jeho protokol. Viz
[oficiální popis protokolu](https://www.wireguard.com/protocol/).
Nad tím agent zajistí také koordinovanou výměnu nakonfigurovaných
WireGuard klíčů, jejichž veřejná část identifikuje peer. Interval této
výměny bude nastavením politiky, nikoliv pevně zabudovanou hodnotou.

Navržený postup rotace nakonfigurovaného klíče:

1. Router lokálně vygeneruje nový klíč a uloží rozpracovanou rotaci.
   Podepíše veřejný klíč, ID federace a uzlu, účel, rostoucí generaci
   a odkaz na předchozí generaci svou dlouhodobou identitou.
2. Peery ověří pověření, podpis, generaci a oprávnění. Duplicitní zprávu
   potvrdí, starší nebo konfliktní generaci odmítnou.
3. Připraví se souběžná nová cesta se samostatným WireGuard rozhraním,
   portem a testovací adresací; stará cesta zůstává dostupná. Konkrétní
   přidělování těchto prostředků musí být součástí implementace plánu.
4. Po oboustranném potvrzení a ověření datového provozu přepnou peery
   příslušné routy. Samotné přijetí veřejného klíče není potvrzením funkčnosti.
5. Po dokončení přechodu se stará cesta a starý privátní klíč odstraní.
   Politika stanoví konec přechodného období; nedostupný peer nesmí
   prodlužovat platnost starého klíče neomezeně.

Výpadek v přípravě zachová dosavadní funkční spojení v rámci jeho platnosti.
Po restartu agent pokračuje z uloženého stavu. Souběžné rotace sousedů se
musí koordinovat a otestovat. Návrat offline peeru po zániku starého klíče
využije samostatný autentizovaný řídicí kanál přes ZeroTier nebo opětovný
zásah notebooku přes SSH. Řídicí kanál nesmí záviset výhradně na právě
rotovaném WireGuard tunelu; jeho autentizace se opírá o identity federace.

Podepsaná nastavení notebooku a routerová oznámení klíčů mají oddělené
číslování revizí. Synchronizace klíčů tak nevyvolává konflikty konfigurace
a neopravňuje router k publikování nové konfigurace federace.

## Data a důvěra

Sdílený dokument obsahuje verzi schématu, ID federace, ID revize, ID předchozí
revize, autora, členy a požadovaná nastavení. Obsah musí mít jednoznačnou
serializaci, kontrolní otisk a podpis autorizovaného autora. Samotné členství
v ZeroTier síti nenahrazuje ověření oprávnění k publikování konfigurace.

Hesla, privátní SSH/WireGuard/ZeroTier klíče, uložená SSH důvěra a surové
audity nejsou součástí sdíleného dokumentu. Privátní identita vzniká
a zůstává na příslušném zařízení. Přidání člena a změna důvěry musí mít
výslovný postup; nově objevený peer se nestává automaticky autorem změn.

Stejná revize se přijímá idempotentně. Starší revize nesmí přepsat novější.
Dvě různé revize se společným předchůdcem znamenají konflikt, který se
zobrazí v desktopu; čas zařízení nerozhoduje o vítězi. Návrat ke staršímu
obsahu vytvoří novou revizi. Vyřazení člena musí zabránit jeho další účasti
na přenosu a odebrat jeho oprávnění, včetně oprávnění v transportní vrstvě.

## Deploy

1. Ověřit přímou fyzickou LAN cestu a přes ověřené SSH zjistit OS, architekturu, nástroje, místo a oprávnění.
2. Zobrazit konkrétní plán instalace agenta a změn pro cílový router.
3. Nainstalovat ověřený artefakt agenta a jeho službu; uchovat předchozí verzi.
4. Spárovat identitu routeru s federací a ověřit stav agenta.
5. Přenést a validovat revizi, zkontrolovat výchozí stav a uložit zálohu.
6. Po potvrzení plánu aplikovat změny; pro routy a firewall předem spustit
   lokální časovaný rollback nezávislý na desktopu a SSH relaci.
7. Ověřit správcovskou dostupnost i požadovaný síťový stav, teprve potom
   potvrdit úspěch a zrušit rollback.

Desktop ukazuje samostatně požadovanou, přijatou a aplikovanou revizi,
čas posledního kontaktu a chybu. Nedostupný router zůstává čekající;
částečný úspěch federace se nesmí zobrazit jako dokončený deploy.

## Pořadí implementace a ověření

1. Oddělit přenosný model nastavení, opravit sběr citlivých dat při auditu
   a zajistit, aby synchronizace neodstraňovala lokální SSH důvěru.
2. Implementovat revize, kontrolu původu, konflikty a atomické ukládání;
   ověřit duplicity, podvržený obsah, staré revize a přerušený zápis.
3. Doplnit deploy agenta a desktop → router → desktop včetně náhledu
   a zobrazení rozdílu mezi přijetím a aplikováním.
4. Doplnit transport router → router; ověřit dva routery bez desktopu,
   výpadek spojení, opětovné připojení a vyřazeného člena.
5. Implementovat plán WireGuardu, rout a nezbytných pravidel firewallu;
   ověřit rollback při přerušení správcovského spojení.
6. Implementovat automatické rotace podle politiky notebooku; ověřit
   souběžnou rotaci, restart v každé fázi, podvržené oznámení, replay,
   odvolaný uzel a návrat peeru po skončení přechodného období.

Konkrétní transport, balení agenta a podporované verze Turris OS budou
vybrány podle cílových routerů. Nasazení na skutečná zařízení zatím nebylo
provedeno ani ověřeno.
