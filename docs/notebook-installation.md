# Instalace notebooku a rozhraní podle role

Stav: návrh k implementaci. Vývojový `run.sh` není produkční instalátor.

## Rozhraní podle pověření

Po přihlášení lokálního uživatele načte aplikace roli z platného podepsaného
pověření notebooku. Role se nevybírá v nastavení aplikace a samotné členství
v ZeroTier ani přítomnost kořenového klíče bez odpovídajícího pověření nesmí
odemknout administraci.

### Uživatelský notebook

Uživatelská role otevře read-only přehled se stejným obsahem a vizuální
hierarchií jako webová stránka na routeru:

- stav tohoto notebooku a čas poslední místní kontroly;
- přijatá revize topologie a platnost pověření;
- uzly federace, jejich ZeroTier/WireGuard adresy, LAN prefixy a členství;
- ověřené podepsané katalogy hostů pod příslušnými routery;
- místně naměřená dostupnost povolených cílů přes jednotlivé transporty;
- Network ID a vysvětlení, že notebook je koncový, nikoli tranzitní uzel.

Přehled se nebude načítat jako iframe z konkrétního routeru. Lokální backend
poskytne sanitizovaný datový model a Vue vykreslí notebookovou variantu stejného
přehledu. Tím zůstane použitelný i při nedostupnosti jednoho routeru a nebude
závislý na jeho PAM přihlášení. Sdílená data musí pocházet z ověřené podepsané
konfigurace nebo katalogu; lokální diagnostika musí být zřetelně označená.

Routerové texty a akce se přizpůsobí koncovému uzlu: **Tento router** se změní
na **Tento notebook**, stav routerového agenta na stav notebookového backendu
a ping se spouští pouze lokálně z notebooku a pouze na vyžádání. Uživatelská
role neuvidí formuláře routerů, SSH údaje, export řídicí identity, audit,
publikování ani deploy. Tyto příkazy musí odmítnout také backend; skrytí prvků
ve Vue není bezpečnostní hranice.

### Administrátorský notebook

Administrátorská role zachová současné desktopové UI se záložkami Routery,
Notebooky, Síť, Synchronizace, Audity a Nastavení. Obsahuje také úvodní
read-only přehled shodný s uživatelskou rolí, implementovaný jako samostatná
záložka. Nesmí jím být nahrazené stávající administrační workflow.

Neplatné, chybějící, odvolané nebo prošlé pověření otevře pouze bezpečný stav
**Notebook není připojen k federaci** s možností načíst nové pozvání. Aplikace
v tomto stavu nesmí potichu přejít do administrátorské role.

## Distribuční formát

První podporovaný produkční cíl bude Ubuntu/Debian ARM64, který odpovídá
současnému používanému notebooku. Preferovaný artefakt je podepsaný balíček
`.deb`; další architektury se přidají až po samostatném ověření.

Balíček má vlastnit pouze programové soubory:

- `/usr/bin/turris-federation` — Tauri UI a klient stavové lišty;
- `/usr/lib/turris-federation/` — verzovaný backend a neměnné pomocné soubory;
- `/usr/lib/systemd/user/turris-federation-backend.service` — dodaná uživatelská
  jednotka, nikoli kopie generovaná do domovského adresáře;
- `/etc/systemd/system/turris-federation-network.service` a
  `/usr/lib/turris-federation/notebook_network_service.py` — úzce omezená
  privilegovaná správa ZeroTier a ochrany proti transitnímu routování;
- `/usr/share/applications/cz.turris.federation.desktop` — spouštěč UI;
- `/etc/xdg/autostart/cz.turris.federation-tray.desktop` — spuštění klienta
  stavové lišty s parametrem `--background` po přihlášení;
- ikony a licenční soubory pod `/usr/share`.

Konfigurace, identity, přijatá pověření, databáze a provozní stav patří do
uživatelských XDG adresářů a balíček je při aktualizaci nesmí přepisovat.
Současná feature implementace generuje jednotku pod `~/.config/systemd/user`;
před produkčním balíčkem se migruje na dodanou jednotku v `/usr/lib/systemd/user`,
aby aktualizace kódu nezanechávala zastaralou cestu ke skriptu.
Vývojový `run.sh` už systémovou síťovou službu verzovaně instaluje a
aktualizuje. Její kontrakt a fyzickou akceptaci popisuje
[privilegovaná síťová služba notebooku](notebook-network-service.md).

Instalace balíčku může vyžádat systémové oprávnění, ale backend běží jako běžný
uživatel. `postinst` smí provést pouze systémový `daemon-reload` a instalaci
neměnných souborů; nesmí bez přihlášeného uživatele vytvořit identitu, přijmout
federaci, zapnout VPN ani povolit jeho uživatelskou službu.

## První spuštění a přijetí notebooku

Průvodce prvním spuštěním provede tyto oddělené kroky:

1. Zkontroluje podporovaný systém a architekturu, existující data, dostupnost
   `systemd --user`, NetworkManager/polkit a potřebných transportů.
2. Vytvoří privátní identitu notebooku lokálně s oprávněním `0600`; privátní
   klíč nikdy nevloží do pozvánky ani požadavku na přijetí.
3. Vytvoří časově omezenou podepsanou žádost a nabídne ji administrátorovi ve
   stejné LAN; při nedostupném síťovém přenosu ji lze předat ručně. Notebook
   předem nemusí znát federaci ani její Network ID.
4. Zobrazí přesný plán: roli, federaci, síťové backendy, systémové změny,
   uživatelskou službu, routy a to, že notebook nebude routovat svou fyzickou síť.
5. Po porovnání krátkého kódu odešle veřejnou identitu a důkaz držení privátního
   klíče administrátorovi. První potvrzení povolí vstup do ZeroTier; teprve
   druhé potvrzení skutečné adresy vydá podepsané pověření člena.
6. Po ověření podpisu a otisku uloží pověření a topologii, zapne
   `turris-federation-backend.service` v uživatelské relaci a nakonfiguruje
   koncové VPN připojení. Nutné privilegované síťové kroky projdou samostatným
   potvrzením polkit; backend nezíská obecné oprávnění `root`.
7. Spustí místní kontrolu transportu, WireGuardu, rout a povoleného cíle.
   Úspěch instalace a úspěch připojení zobrazí jako dva oddělené výsledky.
8. Spustí klienta stavové lišty a otevře UI odpovídající podepsané roli.

Implementace kroků 2 až 5 používá primárně automatický přenos ve stejné fyzické
LAN a dvě potvrzení administrátora. Cílový notebook nejprve vytvoří žádost
podepsanou svým TLS klíčem; nemusí znát federaci ani Network ID. Po dobu nejvýše
15 minut ji oznamuje multicastem s krátkým párovacím kódem. Administrátor vidí
zdrojovou LAN adresu, název a stejný kód. Přenos přijímá pouze zdroje z přímo
připojené fyzické IPv4 sítě; rozhraní ZeroTier, WireGuard, kontejnery a bridge
se za místní LAN nepovažují. Podepsané zprávy se mezi notebooky předávají přes
TCP port 8857 a kód musí správce před prvním potvrzením porovnat na obou
obrazovkách.

První odpověď obsahuje veřejnou
kotvu a podepsané Network ID, ale ještě neobsahuje členské pověření ani
notebook nezapisuje do topologie. Notebook se přes omezenou systémovou službu
připojí do sítě a automaticky vrátí podepsané Device ID, aby správce autorizoval
správného člena v ZeroTier Central. Po autorizaci podepíše
skutečně přidělenou IPv4 adresu z konkrétního rozhraní `zt…` a vrátí ji
administrátorovi. Druhé potvrzení zkontroluje vazbu na původní nonce, identitu,
síť, subnet, veřejný WireGuard klíč a unikátnost adresy. Teprve poté publikuje
novou topologii a vydá finální pozvánku. `root.pem` se uživatelskému notebooku
nikdy nepředá. Stejné podepsané JSON balíčky zůstávají v rozhraní jako nouzový
ruční přenos pro sítě bez multicastu nebo s blokovaným portem 8857. Po finálním
přijetí vznikne soukromý soubor `wireguard.conf` s adresou `/32`,
routerovými peery a jejich federovanými LAN prefixy. Soubor se instaluje až po
samostatném deset minut platném plánu a potvrzení v UI. Instalační tok spouští
přes polkit pouze systémový `nmcli`, nikoli skript z uživatelského datového
adresáře. Místní diagnostika může při nedostatečném oprávnění samostatně
vyžádat pouze read-only příkaz systémového `wg` pro časy handshake. Importovaný
profil používá rozhraní `tf_notebook`, `never-default`
pro IPv4 i IPv6 a pouze podepsané routy. Federované routy mají vysokou metriku,
takže právě připojená fyzická LAN stejného prefixu zůstane preferovaná; mimo ni
se použije VPN. Aktivní nebo neověřitelný systémový
IPv4 či IPv6 forwarding se v plánu, stavu a diagnostice zobrazí jako varování,
ale instalaci neblokuje ani toto systémové nastavení nemění. Před změnou se
ověří, že podepsaná ZeroTier adresa i cesty k endpointům routerů skutečně
používají jedno konkrétní rozhraní `zt…`.
Stávající WireGuard profil stejného jména zachová
jako obnovovací kopii; neúspěšná kontrola adresy nebo rout spustí automatický
rollback a UI nabízí také výslovný návrat. Tento tok zatím prošel pouze testy
s nahrazenými systémovými příkazy, nikoli reálným polkit potvrzením a aktivací
tunelu.

Explicitní místní kontrola navíc ověřuje aktivní profil, rozhraní, podepsanou
adresu, všechny očekávané routy a hlásí stav forwardingu. Pět WireGuard pingů pro
každý router míří jen na cíle z podepsané revize; handshake výstup se mapuje na
routery bez zveřejnění jejich veřejných klíčů. Výsledek se po 120 sekundách
označí jako zastaralý a není sdílen jako stav jiných notebooků.

První administrátor představuje zvláštní bootstrap: může vytvořit novou
federaci a její kořenovou identitu pouze v explicitním toku **Vytvořit novou
federaci**. Další administrátorský notebook se přidává pozváním a oboustranným
ověřením otisků; uživatelský notebook nelze lokálně povýšit.

Pro migraci existujícího řídicího notebooku UI nabízí samostatně potvrzenou
akci pouze tehdy, když je lokálně přítomná kořenová privátní identita i platná
publikovaná revize. Vydané pověření je podepsané touto kotvou a svázané s TLS
otiskem notebooku a ID federace. Tento migrační krok není onboarding nového
notebooku a nesmí být nabízen zařízení bez dosavadní řídicí identity.

## Aktualizace, odinstalace a obnova

Aktualizace balíčku nejprve nahradí neměnné soubory, provede `daemon-reload`
a až poté řízeně restartuje aktivní uživatelský backend. Nová verze musí před
migrací dat uložit obnovovací záznam a po startu potvrdit kompatibilitu databáze,
pověření a lokálního socketu. Neúspěch nesmí smazat poslední funkční konfiguraci.

Odinstalace programu a smazání identity jsou dvě různé operace. Běžné odebrání
balíčku odstraní program a jednotku, ale ponechá uživatelská data pro obnovu.
Odpojení notebooku od federace musí nejprve vytvořit požadavek na odvolání,
doručit jej administrátorovi a zobrazit, zda bylo odvolání potvrzeno. Volba
**Smazat místní identitu a data** bude samostatná destruktivní akce s přesným
náhledem a nebude součástí běžného odinstalování.

Pro první implementaci aktualizace administrátor exportuje balíček obsahující
jen veřejnou kotvu a aktuální podepsanou topologii. Uživatelský notebook jej
ověří proti připnuté kotvě a přijme pouze novější revizi stejné federace, která
nemění jeho roli ani WireGuard klíč. Před zápisem zobrazí rozdíl rout a vyžádá
výslovné potvrzení. Aktivní členství se přijme až po úspěšné aktivaci a ověření
nového NetworkManager profilu; při chybě se obnoví předchozí profil, konfigurace
i podepsaná revize. Odvolávající revize nejprve odstraní přesně pojmenovaný
spravovaný profil i jeho federovanou rollback kopii a teprve potom zneplatní
členství; jiných NetworkManager profilů se nedotkne. Privátní TLS a WireGuard
identita zůstávají zachované.

Obnova z existujícího datového adresáře nesmí vytvořit novou identitu ani
přepsat jiné pověření. Při nekompatibilní nebo poškozené konfiguraci backend
zůstane zastavený, tray zobrazí chybu a UI nabídne export diagnostiky bez klíčů.

## Akceptační test instalace

Produkční balíček vznikne až po funkčním a end-to-end ověření vývojové
instalace na skutečném routeru, administrátorském notebooku a uživatelském
notebooku. Následující seznam je proto až druhá, balíčkovací fáze akceptace.

Produkční instalace je přijatá až po ověření na čistém Ubuntu/Debian ARM64:

- instalace a aktualizace podepsaného `.deb` bez vývojového toolchainu;
- první uživatelské přihlášení, přijetí pozvánky a vydání správné role;
- automatický start backendu i tray, jediná instance UI a otevření z tray;
- uživatelský přehled odpovídající routerové stránce a nepřítomnost všech
  administrátorských API i po přímém IPC požadavku;
- administrátorské pověření otevře současné plné UI;
- zavření UI, pád a restart backendu, odhlášení/přihlášení a restart notebooku;
- žádný forwarding mezi fyzickou sítí a VPN a žádný inzerovaný LAN prefix;
- aktualizace se zachováním identity a bezpečný návrat po neúspěšné migraci;
- odinstalace se zachováním dat a samostatné potvrzené smazání identity.
