# Role notebooků jako síťových uzlů

Stav: schválený směr návrhu, dosud neimplementováno.

Notebook je plnohodnotný koncový uzel federované VPN, nikoli router lokality.
Má vlastní identitu a tunelovou adresu a může používat služby dostupné ve
federaci. Nikdy však neinzeruje prefix fyzické sítě, nepředává provoz mezi VPN
a fyzickým rozhraním a nezapíná forwarding ani masquerade.

## Role

Každý notebook má právě jednu z následujících rolí:

- **Administrátorský notebook** je koncový síťový uzel a současně řídicí uzel.
  Smí spravovat návrh federace, podepisovat a publikovat konfiguraci, provádět
  audit a přes přímou LAN instalovat nebo aktualizovat routery. Synchronizace
  mezi administrátorskými notebooky může přenést kořenovou identitu federace
  podle stávajícího oboustranného párování.
- **Uživatelský notebook** je pouze koncový síťový uzel. Smí se připojit do VPN
  a používat povolené federované sítě a služby, ale nesmí získat kořenový klíč,
  návrhy se SSH údaji, auditní data ani rozhraní pro správu a deploy routerů.

Role je samostatná od provozního stavu. Notebook se nestává administrátorským
jen tím, že je dosažitelný, autorizovaný v transportní síti nebo objevený přes
discovery.

## Trvalý backend a stavová lišta

Na každém notebooku běží backend jako uživatelská služba operačního systému,
odděleně od okna aplikace. Na Linuxu ji spravuje `systemd --user`; spouští se
automaticky po přihlášení uživatele, při pádu se řízeně restartuje a nepotřebuje
trvale běžet jako `root`. Úvodní instalace nebo potvrzená změna systémové VPN
konfigurace může použít NetworkManager/polkit nebo úzce omezený instalační krok
s vyšším oprávněním; privilegium se nesmí přenést na běžné API backendu. Běh
bez přihlášené uživatelské relace pomocí lingeru je
samostatná, výslovně zapínaná volba, ne vedlejší efekt instalace.

Backend vlastní síťovou identitu notebooku, koncovou konfiguraci VPN, lokální
diagnostiku a stav připojení. U administrátorského notebooku navíc obsluhuje
řídicí funkce povolené jeho rolí. Samotná instalace nebo spuštění backendu ale
žádné administrátorské oprávnění nevytváří.

Grafická aplikace je klient backendu. Může se zavřít bez zastavení služby,
odpojení VPN nebo ztráty diagnostického stavu. S backendem komunikuje pouze
přes lokální rozhraní svázané s uživatelskou relací, přednostně Unix socket
v `$XDG_RUNTIME_DIR`, chráněný oprávněními a kontrolou UID. Backend nesmí
vystavit neautentizované HTTP API do LAN ani do VPN.

Po přihlášení se spustí také lehká ikona ve stavové liště. Bez otevřeného okna
ukazuje alespoň tyto stavy:

- připojeno a místní kontrola je v pořádku;
- připojeno s omezením nebo zastaralým výsledkem kontroly;
- odpojeno;
- backend neběží nebo hlásí chybu.

Kliknutí nebo položka **Otevřít Turris Federation** zobrazí existující UI a
zaměří jeho okno; nespouští druhou instanci backendu. Nabídka smí obsahovat
obnovení místní kontroly a kopírování stručné diagnostiky. Akce **Ukončit UI**
a **Zastavit službu / odpojit tento notebook** musí být oddělené a druhá z nich
vyžaduje výslovné potvrzení. Administrátorské akce se v uživatelské roli vůbec
nezobrazí, nestačí je pouze vizuálně zakázat.

Instalace služby, její aktualizace a obnova konfigurace musí být atomické a
zachovat předchozí funkční verzi pro rollback. Privátní klíče a pověření zůstávají
v uživatelském úložišti s oprávněním `0600` nebo v systémovém úložišti tajemství;
stavová lišta ani běžné logy je nesmí zobrazit.

## Síťové chování

Router zůstává tranzitním uzlem lokality a může vlastnit jeden či více LAN
prefixů. Notebook je vždy koncový uzel:

- v podepsané topologii má typ `notebook`, roli `administrator` nebo `user`,
  vlastní identitu a jednu tunelovou adresu;
- jeho seznam inzerovaných LAN prefixů musí být prázdný;
- konfigurace notebooku nesmí zapnout IP forwarding ani vytvořit forwarding
  mezi VPN a fyzickým rozhraním;
- router smí pro notebook přidat pouze host route k jeho tunelové adrese,
  nikdy route k síti za notebookem;
- notebook může mít v `AllowedIPs` povolené tunelové adresy ostatních členů
  a federované LAN prefixy podle přístupové politiky;
- přístup notebooku do federovaných LAN je koncový provoz notebooku, nikoli
  routování jeho místní sítě.

První implementace může zachovat ZeroTier jako transport a WireGuard jako
datovou VPN. Rozdělení rolí ale patří do doménového modelu a nesmí být odvozené
z konkrétního transportního backendu.

## Dostupnost a diagnostika

Dostupnost notebooku se zjišťuje pouze lokálně na tomto notebooku. Místní
kontrola smí ověřit stav transportu, WireGuard rozhraní, očekávané routy,
handshake a na výslovné vyžádání také konektivitu k povoleným cílům.

Routery notebook pravidelně nepingají a jeho dostupnost nezařazují do svého
podepsaného provozního hlášení. Administrátorský notebook proto může zobrazit
aktuální stav pouze s označením **místní kontrola**; u ostatních notebooků smí
ukázat členství a poslední sdílenou konfiguraci, ne tvrdit jejich aktuální
dostupnost. Výsledek místní kontroly se nepoužívá jako autorita pro změnu
členství nebo přístupových práv.

## Důvěra a změna role

Uživatelský notebook dostane samostatné podepsané pověření člena s minimálními
oprávněními. Nedostane kořenový soukromý klíč ani certifikát opravňující volat
řídicí operace routerového agenta. Přijetí uživatelského notebooku musí být
výslovně potvrzeno administrátorem; pouhé discovery ani členství v ZeroTier
síti nestačí.

Povýšení na administrátorský notebook je samostatná, výslovně potvrzená operace
s kontrolou otisku na obou zařízeních. Snížení role již jednou spárovaného
administrátorského notebooku samo neodvolá dříve předaný kořenový klíč. Bezpečné
odvolání proto vyžaduje rotaci kotvy důvěry a nové vydání pověření; UI na tuto
skutečnost musí před změnou upozornit.

## Dopad na současnou implementaci

Současný kód modeluje v podepsané konfiguraci jen routery a místní notebook
zobrazuje jako zvláštní řídicí položku pouze s kontrolou ZeroTier. Implementace
tohoto návrhu proto vyžaduje verzovanou změnu protokolu, nikoli jen úpravu textů:

1. Rozšířit společný model uzlu o typ `router | notebook` a u notebooku o roli
   `administrator | user`; staré routerové záznamy migrovat jako `router`.
2. Oddělit členství a síťové pověření notebooku od administrátorského párování.
   Uživatelský notebook nesmí vstoupit do stávající synchronizace řídicí identity.
3. Generovat notebooku koncovou WireGuard konfiguraci a na routerech přijmout
   pro notebook jen jeho `/32`, bez LAN prefixů a bez pravidel pro transit.
4. Přidat lokální instalaci, aktualizaci, obnovu a rollback uživatelské backendové
   služby a konfigurace VPN notebooku bez vzdáleného deploye přes SSH.
5. Přidat klienta ve stavové liště, lokální IPC a otevření jediné instance UI;
   zavření okna nesmí ukončit backend ani VPN.
6. Rozdělit desktopové rozhraní podle oprávnění. Uživatelská role zobrazí pouze
   připojení, místní diagnostiku a povolené cíle; administrátorská role navíc
   inventář, audit, publikování a deploy routerů.
7. Migrovat export/import a notebookovou synchronizaci tak, aby zachovaly typ,
   roli a pověření, ale nikdy nepřenesly řídicí tajemství uživatelskému uzlu.

## Akceptační hranice

Změna je hotová teprve po ověření nejméně jednoho routeru, jednoho
administrátorského a jednoho uživatelského notebooku:

- oba notebooky se připojí jako samostatné VPN uzly a dosáhnou na povolený cíl;
- uživatelský notebook nemůže načíst ani změnit návrh a nemůže spustit audit,
  publikování nebo deploy;
- žádný notebook neinzeruje svou fyzickou síť a provoz mezi fyzickou sítí a VPN
  přes notebook neprojde;
- router má pro notebook pouze host route a nepovažuje jej za routing peer;
- vypnutí notebooku nezhorší stav routerové federace a router ho vzdáleně
  nediagnostikuje;
- místní kontrola na každém notebooku pravdivě rozliší členství, tunel, routy
  a aktuální dosažitelnost a je zřetelně označená jako lokální výsledek;
- backend se po přihlášení spustí bez otevření UI, přežije zavření okna a stavová
  lišta správně zobrazí připojení, omezení, odpojení i chybu služby;
- otevření UI ze stavové lišty použije běžící backend a nevytvoří druhou službu;
- uživatelská služba ani její lokální IPC nejsou dostupné jinému místnímu
  uživateli a neposlouchají na rozhraní LAN nebo VPN;
- restart všech tří zařízení zachová identity, role a síťovou konfiguraci.
