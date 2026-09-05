# Deploy a synchronizace nastavení

Pracovní návrh, 5. 9. 2026. Popsané chování zatím není implementované.
Potvrzený rozsah: deploy aplikací přes notebook, notebook jako kotva důvěry,
synchronizace nastavení federace včetně WireGuardu a rout a automatická
rotace komunikačních klíčů mezi routery i bez připojeného notebooku.

## Výchozí stav

Desktop ukládá inventář a ZeroTier nastavení v SQLite a provádí jednotlivé
SSH příkazy s ověřením host klíče. Routerový agent zatím chybí.
Export/import není synchronizační protokol: import nahrazuje inventář,
maže pozorování i SSH důvěru. Export navíc obsahuje stav a čas auditu uzlů.
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
přes notebook; automatický sync mezi routery přenáší nastavení a oznámení
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

1. Přes ověřené SSH zjistit OS, architekturu, nástroje, místo a oprávnění.
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
