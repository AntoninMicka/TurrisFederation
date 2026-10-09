# Cílová router-only architektura

Stav: **schválený cílový směr, migrace není implementovaná ani fyzicky přijatá**.

## Rozhodnutí

Trvalá aplikace Turris Federation poběží pouze na routerech Turris. Notebooky a
telefony budou běžné koncové NetBird peery bez samostatné aplikace Federation,
lokální databáze, synchronizační služby, tray UI nebo vlastní WireGuard
orchestrace. Notebook může použít pouze malý jednorázový instalační skript pro
oficiálního klienta NetBird a následně běží už jen NetBird klient.

Stávající desktopová aplikace zůstává během migrace pouze jako rollback a nástroj
pro bezpečné předání současné federační identity. Nové funkce se do ní nepřidávají.
Odstraní se až po samostatně potvrzené fyzické akceptaci routerové náhrady.

## Odpovědnosti Turrisu

Každý router provozuje:

- oficiální NetBird klient a routing peer pro celý svůj podepsaný LAN prefix;
- místní WebApps rozhraní pro stav, členství, NetBird a Zlaté stránky;
- vlastní routerovou identitu a podepisování provozních reportů;
- autoritativní DNS zónu lokality, například `cacke.internal`;
- přesné DNS záznamy odvozené z místního validovaného `services.json`;
- podmíněné DNS forwardy zón ostatních lokalit přes NetBird;
- synchronizaci podepsané topologie a reportů s ostatními routery.

Zlaté stránky jsou pouze adresář a DNS zdroj. Nemění firewall, routy ani
dosažitelnost. Mezi přijatými federovanými sítěmi se přes NetBird routují celé
LAN prefixy bez filtrování podle katalogových hostů nebo portů.

## Federační autorita

Kořenová federační CA se nesmí bez rozmyslu kopírovat na každý router. Jeden
výslovně zvolený **autoritativní Turris** převezme z dnešního administrátorského
notebooku správu členství a podepisování topologie. Ostatní routery drží jen své
členské identity a podepisují vlastní lokální stav.

Před přesunem CA musí vzniknout šifrovaná offline záloha a ověřený postup obnovy.
Přenos proběhne pouze po přímé LAN a s porovnáním identity na obou stranách.
Výpadek autoritativního routeru nesmí zastavit existující NetBird provoz, DNS
lokalit ani čtení poslední platné topologie; pouze dočasně znemožní změny členství.

## NetBird

Lokální instalace, přihlášení klienta, stav routing peeru a DNS konfigurace se
spravují na příslušném Turrisu. Setup key je jednorázový a po registraci se
neukládá do reportu, konfigurace Federation ani logů.

Změny celého NetBird účtu, například vytvoření Networks a skupin, vyžadují
oddělenou account-level autoritu. Pro první PoC mohou být potvrzené ručně v
NetBird Cloud. Případná pozdější automatizace smí běžet pouze na autoritativním
Turrisu s odděleným NetBird service credentialem; běžné routery jej nepotřebují
pro správu vlastní DNS zóny.

## Koncová zařízení

Jednorázový notebookový skript smí pouze:

1. ověřit podporovaný systém a architekturu;
2. nainstalovat oficiální NetBird klient;
3. spustit interaktivní přihlášení nebo přijmout krátce platný setup key;
4. zobrazit `netbird status` a základní DNS/routing diagnostiku.

Skript nesmí obsahovat federační CA, NetBird PAT, SSH údaje routerů, deploy
logiku ani trvalý backend. Po dokončení není potřeba pro běžný provoz.

## Migrační pořadí

1. Zmrazit rozvoj desktopové a notebookové aplikace; zachovat její funkční stav.
2. Na Cackém read-only ověřit Turris OS, balíček NetBird, místo, síť a DNS.
3. Doplnit routerové nastavení NetBirdu, LAN routing a lokální zónu
   `cacke.internal` odvozenou ze Zlatých stránek.
4. Ověřit jména a celé LAN routy z NetBird klienta i z jiné federované LAN.
5. Doplnit do routerového webu správu členství, bezpečný import federační CA,
   export šifrované zálohy a obnovu.
6. Přenést autoritu na výslovně zvolený Turris a ověřit provoz bez notebookové
   aplikace včetně restartu a výpadku autoritativního routeru.
7. Teprve potom odstranit Tauri frontend/backend, notebookové služby a vlastní
   notebookovou VPN orchestraci z aktivního produktu.

## Akceptace odstranění notebookové aplikace

- Nový router lze přijmout a odvolat z PAM chráněného routerového webu.
- NetBird a DNS se po restartu routerů obnoví bez notebooku.
- Celé federované LAN jsou obousměrně dosažitelné jednou VPN vrstvou.
- Každá lokalita sama publikuje svou zónu a všechny LAN ji umějí přeložit.
- Ztráta notebooku neovlivní provoz ani neznamená ztrátu kořenové identity.
- Záloha CA byla skutečně obnovena v odděleném testu.
- Notebook po jednorázovém skriptu používá pouze oficiální NetBird klient.
