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
4. Přidat lokální instalaci, obnovu a rollback konfigurace VPN notebooku bez
   vzdáleného deploye přes SSH.
5. Rozdělit desktopové rozhraní podle oprávnění. Uživatelská role zobrazí pouze
   připojení, místní diagnostiku a povolené cíle; administrátorská role navíc
   inventář, audit, publikování a deploy routerů.
6. Migrovat export/import a notebookovou synchronizaci tak, aby zachovaly typ,
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
- restart všech tří zařízení zachová identity, role a síťovou konfiguraci.

