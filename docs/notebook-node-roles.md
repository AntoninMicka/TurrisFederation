# Role notebooků jako síťových uzlů

Stav: schválený směr návrhu. Základ trvalé uživatelské služby, lokálního
stavového socketu a ovládání ze stavové lišty je implementovaný na feature
větvi. Podepsaný model už odděluje routery od notebooků a eviduje roli
notebooku. Koncová VPN konfigurace i potvrzovaný instalační tok jsou
implementované; zbývá ověření na skutečných zařízeních.

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

Uživatelský notebook neukládá adresu aktuální Wi-Fi ani fyzické LAN jako svou
identitu a pro běh backendu ji nezadává. Stabilní adresy ZeroTier a WireGuard
dostane v podepsané topologii. Původní přímá synchronizace mezi
administrátorskými notebooky se smí vázat pouze na stabilní adresu rozhraní
ZeroTier, nikdy na adresu právě navštívené LAN.

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

Vývojová instalace vytváří uživatelský XDG autostart
`~/.config/autostart/cz.turris.federation-tray.desktop`, který spouští stejný
klient s parametrem `--background`. `run.sh` pro tento účel sestaví samostatný
testovací klient s vloženým frontendem; binárka `tauri dev` se nepoužívá,
protože po přihlášení není dostupný její Vite server na localhostu. V režimu
`--background` zůstane hlavní okno skryté;
ruční spuštění aplikace nebo položka v menu ikony okno zobrazí.

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

První implementační řez používá jednotku
`turris-federation-backend.service`. Zapnutí synchronizace jednotku atomicky
nainstaluje a povolí; samostatné ovládání v UI zůstává pro opravu instalace a
výslovné odstranění. Při prvním spuštění nové verze se dříve zapnutý backend,
který byl svázaný jen s během UI, převede na uživatelskou službu. Při každém
dalším spuštění UI opraví také existující, ale vypnutou, zastavenou nebo na
starou vývojovou cestu odkazující jednotku. Stejná migrace nainstaluje službu
i již dříve přijatému uživatelskému notebooku, který nemá zapnutou
administrátorskou synchronizaci. Selhání instalace se zobrazí v UI; dočasný
proces svázaný s UI se nesmí vydávat za nainstalovanou službu. Lokální socket přijímá pouze čtení
sanitizovaného stavu, kontroluje UID
klienta a má oprávnění `0600`. Zavření hlavního okna ho skryje; samostatná
položka stavové lišty UI skutečně ukončí, aniž by zastavila nainstalovaný
backend. Druhé spuštění UI přes oddělený privátní socket pouze zobrazí a zaměří
existující okno. Barevná ikona rozlišuje ověřené připojení, omezený nebo
zastaralý stav, odpojení a chybu backendu. Potvrzené odpojení vrátí spravovaný
VPN profil, vypne synchronizaci a zastaví službu, ale nemaže členství ani
identitu. Aktivace a chování stavové lišty v reálné grafické relaci ještě
vyžadují ruční přijetí.

## UI podle role

Uživatelský notebook otevře read-only přehled odpovídající routerové webové
stránce, vykreslený z lokálně ověřených dat backendu. Administrátorské UI už
obsahuje tento přehled jako úvodní záložku a zachovává celé dosavadní desktopové
workflow. Role pochází výhradně z podepsaného
pověření a v uživatelské variantě musí administrátorské příkazy odmítnout i
backend, nejen skryté Vue komponenty. Přesné mapování obsahu, onboarding,
balíček a aktualizace popisuje [instalace notebooku](notebook-installation.md).

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
- podkladový firewall smí z konkrétní podepsané ZeroTier adresy notebooku
  povolit WireGuard UDP/51830 a diagnostický ICMP echo-request; TCP/8844 smí
  povolit pouze notebooku s podepsanou rolí `administrator`;
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

Read-only přehled spouští místní kontrolu pouze explicitním tlačítkem. Backend
sám vybere ZeroTier a WireGuard adresy přijatých routerů z ověřené publikované
revize; UI mu nepředává libovolný cíl. Kontrola ověří NetworkManager profil,
rozhraní, přidělenou adresu, očekávané routy, stav forwardingu, handshake a
provede pět pingů na každé podepsané routerové adrese. Handshake se nejprve čte
bez zvýšení oprávnění a při zamítnutí může polkit spustit pouze systémové
`wg show tf_notebook latest-handshakes`. Privátní klíče se nečtou ani nevracejí
do UI. Výsledek platí jen pro konkrétní revizi a po 120 sekundách se zobrazuje
jako zastaralý.

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

Podepsané schéma 2 zachovává routery v `nodes` a přidává samostatný seznam
`notebooks`. Notebook má otisk své TLS identity, název, roli a volitelné
ZeroTier/WireGuard adresy; formát pro něj vůbec nepřijímá LAN prefixy. Starší
routerové dokumenty schématu 1 zůstávají validní. Jednorázový bootstrap
administrátora jej zapíše do nové revize a vydání uživatelské pozvánky nejprve
idempotentně publikuje oba notebooky, potom vydá pověření svázané s členstvím.
Schéma 3 doplňuje veřejný WireGuard klíč a vyžaduje endpoint buď celý
(ZeroTier adresa, WireGuard adresa a klíč), nebo dosud nepřidělený. Privátní
klíč vzniká a zůstává na cílovém notebooku. Router vytvoří notebookovému peeru
jen host route `/32`, bez endpointu a LAN prefixů. Přístup k synchronizačnímu
API přes TCP/8844 dostane pouze administrátorský endpoint; notebook spojení
iniciuje přes ZeroTier. Handshake notebooku se nekontroluje
v routerovém health stavu.

První autorizační vrstva už ověřuje samostatné podepsané pověření svázané
s TLS identitou notebooku a ID federace. Neplatné, cizí nebo prošlé pověření
selže bez role; párování notebooků, změny routerů, audity a deploy vyžadují
administrátorskou roli také v Tauri backendu. Stávající řídicí notebook může
vydat vlastní administrátorské pověření jen explicitní jednorázovou migrací
z existující kořenové identity a publikované revize. Read-only UI už používá
samostatné členské API sestavené pouze z podepsané revize; neobsahuje SSH cíle,
uživatele, veřejné endpointy, plány, fingerprint kotvy ani interní chyby agenta.
Bez platného členského pověření je odmítnuté. Pozvánky pro nové uživatelské
notebooky používají podepsanou žádost cílového TLS klíče a administrátorem
vydaný balíček s veřejnou kotvou, podepsanou topologií a uživatelským pověřením.
Balíček je svázaný s jednorázovým nonce a lze jej přijmout do 15 minut; nikdy
neobsahuje kořenový privátní klíč. Odvolání a ručně přenositelná bezpečná
aktualizace topologie jsou implementované a lokálně otestované; zbývá jejich
ověření se skutečným routerem, NetworkManagerem, polkit agentem a VPN.

Zbývající kroky:

1. [x] Rozšířit podepsaný model o samostatný typ notebooku a roli
   `administrator | user`; zachovat zpětné přijetí starých routerových revizí.
2. [x] Oddělit členství a podepsané uživatelské pověření notebooku od
   administrátorského párování. Uživatelský notebook nevstupuje do stávající
   synchronizace řídicí identity a nedostane kořenový privátní klíč.
3. [~] Generovat notebooku koncovou WireGuard konfiguraci a na routerech přijmout
   pro notebook jen jeho `/32`, bez LAN prefixů a bez pravidel pro transit.
   Generování, podepsané adresy, routerová konfigurace a potvrzovaný lokální
   NetworkManager/polkit instalační tok s rollbackem i místní diagnostika jsou
   hotové; zbývá end-to-end ověření tunelu na skutečných zařízeních.
4. Přidat lokální instalaci, aktualizaci, obnovu a rollback uživatelské backendové
   služby a konfigurace VPN notebooku bez vzdáleného deploye přes SSH. VPN část
   je implementovaná; balíčkovaná aktualizace a rollback backendu ještě ne.
5. [x] Přidat klienta ve stavové liště, lokální IPC a otevření jediné instance
   UI; zavření okna neukončí backend ani VPN. Reálná grafická relace zůstává
   součástí fyzické akceptace.
6. [x] Přidat ručně přenositelnou podepsanou aktualizaci topologie pro
   uživatelský notebook. Administrátor exportuje pouze veřejnou kotvu a
   podepsanou revizi. Uživatel před potvrzením vidí přidané a odebrané routy;
   přijetí aktivního členství koordinovaně navazuje na výměnu VPN profilu s
   rollbackem. Odvolávající revize VPN odpojí, ale nemaže místní identitu.
7. Rozdělit desktopové rozhraní podle oprávnění. Uživatelská role zobrazí pouze
   připojení, místní diagnostiku a povolené cíle; administrátorská role navíc
   inventář, audit, publikování a deploy routerů.
8. Migrovat export/import a notebookovou synchronizaci tak, aby zachovaly typ,
   roli a pověření, ale nikdy nepřenesly řídicí tajemství uživatelskému uzlu.
9. Až po funkčním ověření předchozích kroků na skutečných zařízeních připravit
   podepsaný `.deb`, dodanou `systemd --user` jednotku, autostart tray a
   průvodce přijetím notebooku podle
   [instalačního návrhu](notebook-installation.md).

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
