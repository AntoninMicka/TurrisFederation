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
- `/usr/share/applications/cz.turris.federation.desktop` — spouštěč UI;
- `/etc/xdg/autostart/cz.turris.federation-tray.desktop` — spuštění klienta
  stavové lišty s parametrem `--background` po přihlášení;
- ikony a licenční soubory pod `/usr/share`.

Konfigurace, identity, přijatá pověření, databáze a provozní stav patří do
uživatelských XDG adresářů a balíček je při aktualizaci nesmí přepisovat.
Současná feature implementace generuje jednotku pod `~/.config/systemd/user`;
před produkčním balíčkem se migruje na dodanou jednotku v `/usr/lib/systemd/user`,
aby aktualizace kódu nezanechávala zastaralou cestu ke skriptu.

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
3. Načte jednorázové, časově omezené pozvání vydané administrátorem. Pozvání
   určuje federaci, požadovanou roli, ID notebooku nebo nonce, kořenový veřejný
   klíč a očekávaný otisk administrátora.
4. Zobrazí přesný plán: roli, federaci, síťové backendy, systémové změny,
   uživatelskou službu, routy a to, že notebook nebude routovat svou fyzickou síť.
5. Po potvrzení odešle veřejnou identitu a důkaz držení privátního klíče
   administrátorovi. Teprve jeho výslovné přijetí vydá podepsané pověření člena.
6. Po ověření podpisu a otisku uloží pověření a topologii, zapne
   `turris-federation-backend.service` v uživatelské relaci a nakonfiguruje
   koncové VPN připojení. Nutné privilegované síťové kroky projdou samostatným
   potvrzením polkit; backend nezíská obecné oprávnění `root`.
7. Spustí místní kontrolu transportu, WireGuardu, rout a povoleného cíle.
   Úspěch instalace a úspěch připojení zobrazí jako dva oddělené výsledky.
8. Spustí klienta stavové lišty a otevře UI odpovídající podepsané roli.

První implementace kroků 2 až 5 používá přenositelný JSON: cílový notebook
vytvoří žádost podepsanou svým TLS klíčem, administrátor ji vloží do svého UI
a vydá uživatelskou pozvánku platnou 15 minut. Pozvánka je svázaná s TLS
otiskem a jednorázovým nonce a obsahuje pouze veřejnou kotvu, podepsanou
topologii a uživatelské pověření. Přijetí nejprve ověří všechny podpisy a vazby
a teprve potom zapíše data; `root.pem` se uživatelskému notebooku nepředává.
Žádost obsahuje také pouze veřejný WireGuard klíč vytvořený na cílovém
notebooku. Administrátor přidělí volné adresy z uložených ZeroTier a WireGuard
subnetů. Po přijetí vznikne soukromý soubor `wireguard.conf` s adresou `/32`,
routerovými peery a jejich federovanými LAN prefixy. Soubor se instaluje až po
samostatném deset minut platném plánu a potvrzení v UI. Privilegovaně se přes
polkit spouští pouze systémový `nmcli`, nikoli skript z uživatelského datového
adresáře. Importovaný profil používá rozhraní `tf_notebook`, `never-default`
pro IPv4 i IPv6 a pouze podepsané routy. Instalace odmítne systém s aktivním
IPv4 nebo IPv6 forwardingem a před změnou ověří, že podepsaná ZeroTier adresa
i cesty k endpointům routerů skutečně používají jedno konkrétní rozhraní `zt…`.
Stávající WireGuard profil stejného jména zachová
jako obnovovací kopii; neúspěšná kontrola adresy nebo rout spustí automatický
rollback a UI nabízí také výslovný návrat. Tento tok zatím prošel pouze testy
s nahrazenými systémovými příkazy, nikoli reálným polkit potvrzením a aktivací
tunelu.

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
