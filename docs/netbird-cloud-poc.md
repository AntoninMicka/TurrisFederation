# NetBird Cloud PoC

Stav: **příprava, bez změny routeru nebo cloudového účtu z repozitáře**.

## Rozsah

První PoC používá spravovaný NetBird Cloud pouze pro ověření transportu mezi
jedním uživatelským Androidem a jednou službou za jedním Turris routerem.
Na každém migrovaném uzlu je aktivní právě jedna VPN vrstva: NetBird. Provoz se
nesmí tunelovat přes `ZeroTier → tf_wg → NetBird` ani jinou složenou cestu.
Stávající `ZeroTier → tf_wg` zůstává po omezenou dobu pouze vypnutou rollback
variantou a NetBird zatím není automaticky řízen aplikací Turris Federation.

PoC výslovně nezahrnuje:

- obecnou routu celé LAN;
- exit node nebo výchozí trasu;
- souběžnou aktivní datovou cestu přes ZeroTier, `tf_wg` a NetBird;
- přístup k LuCI, SSH, backendu Federation nebo jiné službě na routeru;
- uložení NetBird PAT nebo setup key do databáze, logů, pozvánky či repozitáře;
- změnu členství, rolí nebo podepsané topologie podle stavu cloudového účtu.

## Fail-closed pořadí

1. Přihlásit vlastníka účtu přes interaktivní SSO s MFA.
2. V dashboardu odstranit výchozí full-mesh policy dříve, než budou připojené
   PoC uzly používat reálné služby.
3. Vytvořit oddělené skupiny pro mobilní klient a routing peer. Skupina
   routing peeru nesmí být cílem obecné peer-to-peer policy.
4. Android připojit interaktivním SSO. Pro headless router vytvořit krátce platný
   jednorázový setup key omezený pouze na skupinu routing peeru; po registraci jej
   zneplatnit.
5. Na konkrétním Turrisu nejprve read-only ověřit verzi Turris OS/OpenWrt,
   architekturu, volné místo, dostupnou verzi balíčku a konflikt rozhraní `wt0`.
   Instalaci a firewall provést až podle samostatně zkontrolovaného plánu.
6. V NetBird **Networks** vytvořit jediný resource jako přesnou adresu hostu
   `/32`, nikoli celý LAN prefix. Policy povolí pouze potřebný protokol a port ze
   skupiny PoC klientů k tomuto resource.
7. Každému routeru přidělit stabilní doménu v podepsané topologii; pro první PoC
   `cacke.internal`. Cacké je autoritativní pro tuto zónu a z vlastního
   validovaného `services.json` atomicky vytváří přesné záznamy jako
   `neurodiary.cacke.internal`. NetBird API token na routeru není potřeba.
8. V NetBirdu jednorázově vytvořit doménový Network resource
   `*.cacke.internal` s Cackým jako routing peerem a zapnout routing-peer DNS
   resolution. Hvězdička zde deleguje jmenný prostor routeru; Cacké odpovídá jen
   pro skutečné položky Zlatých stránek. NetBird DNS management na routing peeru
   se vypne, aby jeho místní `dnsmasq` zůstal autoritou a nesoupeřil o port 53.
9. Firewall Cackého přijme z rozhraní NetBird pouze DNS forwarder potřebný
   klientům a přes forward chain jen cílové dvojice `hostAddress:port` z katalogu.
   LuCI, SSH, backend Federation, samotná LAN adresa routeru i ostatní porty
   zůstanou zakázané. DNS jméno není bezpečnostní hranice.
10. Ponechat vypnuté lokální forwardování k samotnému routing peeru a nevytvářet
   policy, která by mobilnímu klientovi zpřístupnila router. Pro první PoC lze
   ponechat výchozí masquerade, aby nebyla nutná návratová routa v LAN.
11. Před aktivací NetBirdu na testovaném uzlu odpojit jeho původní VPN transport.
   Návrat znamená NetBird vypnout a obnovit původní transport, ne provozovat oba
   tunely jako jednu vrstvenou nebo současně směrovanou cestu.

## Akceptace

- Android přeloží plné privátní DNS jméno přes autoritativní DNS Cackého na
  vybraný cíl a otevře pouze povolený port. Android `Private DNS` nesmí obcházet
  resolver VPN.
- Jiný port stejného hostu, jiný LAN host, LAN adresa routeru, LuCI a SSH nejsou
  dosažitelné přes NetBird.
- Android nemá routing-peer, forwarding, exit-node ani administrační roli.
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
