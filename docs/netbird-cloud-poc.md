# NetBird Cloud PoC

Stav: **příprava, bez změny routeru nebo cloudového účtu z repozitáře**.

## Rozsah

První PoC používá spravovaný NetBird Cloud pro ověření transportu mezi jedním
klientem a celou LAN za jedním Turris routerem a pro distribuci DNS názvů Zlatých
stránek.
Na každém migrovaném uzlu je aktivní právě jedna VPN vrstva: NetBird. Provoz se
nesmí tunelovat přes `ZeroTier → tf_wg → NetBird` ani jinou složenou cestu.
Stávající `ZeroTier → tf_wg` zůstává po omezenou dobu pouze vypnutou rollback
variantou a NetBird zatím není automaticky řízen aplikací Turris Federation.

PoC výslovně nezahrnuje:

- exit node nebo výchozí trasu;
- souběžnou aktivní datovou cestu přes ZeroTier, `tf_wg` a NetBird;
- uložení NetBird PAT nebo setup key do databáze, logů, pozvánky či repozitáře;
- změnu členství, rolí nebo podepsané topologie podle stavu cloudového účtu.

Mezi přijatými federovanými LAN NetBird nepoužívá Zlaté stránky jako firewallový
allowlist. Publikuje celé LAN prefixy a nefiltruje jejich provoz podle hosta,
protokolu ani portu. Katalog služeb je pouze zdroj DNS názvů a uživatelského
adresáře.

## Fail-closed pořadí

1. Přihlásit vlastníka účtu přes interaktivní SSO s MFA.
2. Vytvořit výslovnou skupinu federovaných peerů a site-to-site policy. Přístup
   mezi přijatými sítěmi je úplný; výchozí NetBird policy se nepoužívá jako
   náhrada členství Federation.
3. Vytvořit skupinu pro routing peer Cackého a přiřadit mu jeho celý LAN prefix.
4. Android připojit interaktivním SSO. Pro headless router vytvořit krátce platný
   jednorázový setup key omezený pouze na skupinu routing peeru; po registraci jej
   zneplatnit.
5. Na konkrétním Turrisu nejprve read-only ověřit verzi Turris OS/OpenWrt,
   architekturu, volné místo, dostupnou verzi balíčku a konflikt rozhraní `wt0`.
   Instalaci a firewall provést až podle samostatně zkontrolovaného plánu.
6. V NetBird **Networks** publikovat celý podepsaný LAN prefix Cackého přes Cacké
   jako routing peer. Provoz mezi přijatými federovanými sítěmi neomezovat podle
   položek Zlatých stránek.
7. Každému routeru přidělit stabilní doménu v podepsané topologii; pro první PoC
   `cacke.internal`. Cacké je autoritativní pro tuto zónu a z vlastního
   validovaného `services.json` atomicky vytváří přesné záznamy jako
   `neurodiary.cacke.internal`. NetBird API token na routeru není potřeba.
8. Pro NetBird klienty delegovat `cacke.internal` na DNS Cackého. Ostatní
   federované routery přidají podmíněný forward této zóny přes NetBird na Cacké,
   takže stejné názvy fungují i klientům všech LAN přes jejich běžný lokální DNS.
   Cacké obdobně přijme delegace zón ostatních lokalit.
9. NetBird DNS management na routing peeru nastavit tak, aby místní resolver
   routeru zůstal zdrojem vlastní zóny a NetBird nesoupeřil o port 53. Na Cackém
   port 53 obsluhuje Knot Resolver (`kresd`), do kterého routerový agent načítá
   přesné záznamy přes control socket. DNS odpověď neuděluje ani neomezuje
   síťový přístup.
10. Před aktivací NetBirdu na testovaném uzlu odpojit jeho původní VPN transport.
   Návrat znamená NetBird vypnout a obnovit původní transport, ne provozovat oba
   tunely jako jednu vrstvenou nebo současně směrovanou cestu.

## Akceptace

- NetBird klient přeloží plné privátní DNS jméno přes autoritativní DNS Cackého.
  Android `Private DNS` nesmí obcházet resolver VPN.
- Klient dosáhne celý publikovaný LAN prefix Cackého; Zlaté stránky nemění
  povolené hosty, protokoly ani porty.
- Klient v jiné federované LAN přeloží stejné jméno přes svůj lokální router a
  podmíněný forward do autoritativní zóny Cackého.
- Android nemá routing-peer, forwarding ani exit-node roli; síťová dosažitelnost
  sama o sobě mu nedává aplikační přihlašovací údaje nebo deploy oprávnění.
- Odvolání klienta nebo odebrání policy přístup ukončí i po novém připojení.
- `netbird status -d` na routing peeru ukáže očekávaného správce a spojení;
  tajné hodnoty se neukládají do akceptačního protokolu.
- Trasování a stav rozhraní potvrdí, že paket pro testovanou službu prošel pouze
  NetBirdem a nebyl vnořen do ZeroTieru nebo `tf_wg`.
- Vypnutí NetBirdu dovolí řízeně obnovit původní transport bez změny podepsané
  topologie Federation; oba transporty se při tom nepoužívají současně.

## Podklady

- [NetBird Cloud Getting Started](https://docs.netbird.io/get-started)
- [Instalace na Android](https://docs.netbird.io/get-started/install/android)
- [Instalace na OpenWrt](https://docs.netbird.io/get-started/install/openwrt)
- [Networks a resource policies](https://docs.netbird.io/manage/networks)
- [Chování routing peeru](https://docs.netbird.io/manage/networks/how-routing-peers-work)
- [Interní DNS servery](https://docs.netbird.io/manage/dns/internal-dns-servers)
- [Doménové Network resources](https://docs.netbird.io/manage/networks/use-cases/by-resource-type/accessing-entire-domains-within-networks)
