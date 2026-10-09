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
7. V NetBird **DNS → Zones** vytvořit privátní zónu distribuovanou pouze skupině
   PoC klientů a routing peeru. Přidat jediný `A` záznam ukazující na stejnou IP
   jako `/32` resource. Nezapínat wildcard ani search domain; klient používá
   plné DNS jméno. Viditelnost DNS záznamu nenahrazuje resource policy. Na
   OpenWrt nesmí NetBird soupeřit s `dnsmasq` o port 53; případný resolver se
   připraví na `127.0.0.1:5053` a `dnsmasq` do něj předá jen zvolenou privátní
   zónu, nikoli všechny DNS dotazy.
8. Ponechat vypnuté lokální forwardování k samotnému routing peeru a nevytvářet
   policy, která by mobilnímu klientovi zpřístupnila router. Pro první PoC lze
   ponechat výchozí masquerade, aby nebyla nutná návratová routa v LAN.
9. Před aktivací NetBirdu na testovaném uzlu odpojit jeho původní VPN transport.
   Návrat znamená NetBird vypnout a obnovit původní transport, ne provozovat oba
   tunely jako jednu vrstvenou nebo současně směrovanou cestu.

## Akceptace

- Android přeloží plné privátní DNS jméno na vybraný `/32` cíl a otevře pouze
  povolený port. Android `Private DNS` nesmí obcházet resolver VPN.
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
- [Privátní DNS zóny](https://docs.netbird.io/manage/dns/custom-zones)
- [DNS aliasy pro routované resources](https://docs.netbird.io/manage/dns/dns-aliases-for-routed-networks)
