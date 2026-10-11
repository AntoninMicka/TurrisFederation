# Izolovana HTTPS proxy v LXC

Stav: implementovany format podepsaneho manifestu, fail-closed reconciler nginx a
systemd timer. Vytvoreni LXC, firewall na skutecnem Turrisu, certifikat a NetBird
policy zatim nebyly fyzicky prijaty.

## Bezpecnostni hranice

Proxy je samostatny LXC a samostatny NetBird peer. Neni routing peerem pro LAN,
neinzeruje LAN prefix a nema forwarding. Nginx posloucha jen na NetBird IP
kontejneru, ne na jeho LAN/management adrese. Klientska NetBird skupina dostane
peer-to-peer policy jen na tento proxy peer TCP/443; nedostane resource cele LAN.

LXC se nepripojuje do bezneho `lan` bridge. Pouziva izolovany point-to-point
segment, v priklade `10.89.0.2/30` (LXC) a `10.89.0.1/30` (Turris), ve vlastni
OpenWrt zone `tf_proxy` s `input REJECT`, `forward REJECT`, `output ACCEPT`.
Turris povoli z proxy jen:

- TCP/22 na `10.89.0.1` pro omezeny pull manifestu;
- DNS na `10.89.0.1`, pokud jej kontejner potrebuje;
- jednotliva pravidla `10.89.0.2 -> hostAddress:port` pro prave publikovane
  lokalni sluzby;
- odchozi provoz proxy do WAN nutny pro jeji vlastni NetBird peer, nikdy obecny
  forwarding do `lan`.

Samotny LXC proto nema pristup do cele site ani tehdy, kdyz zna jeji adresy.
Seznam a firewall musi Turris aplikovat ve stejne transakci; odebrana sluzba se
nejdriv odebere z manifestu/nginx a pote z firewallu. Pri nedostupnosti Turrisu
proxy pouzije posledni podepsany manifest nejvyse do jeho expirace (120 sekund),
pak atomicky nasadi prazdnou konfiguraci bez upstreamu.

## Zdroj seznamu

Na lokalnim Turrisu vybere spravce pouze HTTP(S) ID z jeho vlastniho
`services.json`:

```sh
printf '["neurodiary","chatbot"]' |
  python3 /usr/lib/turris-federation/federation.py proxy-select /etc/turris-federation
```

`tcp` sluzby ani cizi/federovane katalogy vybrat nelze. LXC pouziva vlastni SSH
klic, pripina host key a na routeru ma klic v `authorized_keys` s vynucenym
prikazem:

```text
restrict,command="python3 /usr/lib/turris-federation/federation.py proxy-manifest /etc/turris-federation" ssh-ed25519 AAAA... tf-proxy
```

Manifest je podepsany clenskou identitou lokalniho Turrisu, obsahuje pouze
vybrane endpointy a plati 120 sekund. Proxy navic pripina verejnou identitu a
`nodeId` tohoto routeru. SSH klic proxy tedy neumozni shell ani vyber jineho
routeru a podvrzeny seznam neprojde.

## LXC a proxy

Na Turrisu ukladejte bezny linuxovy LXC na externi SSD/HDD, ne na interni eMMC.
Oficialni Turris postup pouziva LXC utilities a `lxc-create`; kontejner pridejte
do `/etc/config/lxc-auto` az po overeni rucniho startu. Vychozi LXC je pripojeny
do LAN bridge, proto jeho sitovou konfiguraci pred prvnim produkcnim startem
zmente na izolovany `tf_proxy` bridge.

Uvnitř Debian/Ubuntu LXC nainstalujte `nginx`, `openssh-client`, `openssl`,
`ca-certificates`, Python 3 a oficialniho NetBird klienta. Potom:

1. zkopirujte `proxy/tf_proxy.py` do
   `/usr/local/lib/turris-federation-proxy/tf_proxy.py`;
2. zkopirujte obe systemd jednotky z `proxy/` do `/etc/systemd/system/`;
3. vytvorte `/etc/turris-federation-proxy/config.json` podle
   `proxy/config.example.json` a vsechny klice/certifikaty nastavte na `0600`;
4. do systemoveho trust store pridejte CA HTTPS upstreamu; `proxy_ssl_verify`
   se nikdy nevypina;
5. vydejte certifikat pro `*.proxy.cacke.internal` a pripnete odpovidajici DNS
   jmena na NetBird IP proxy;
6. zaregistrujte LXC jako samostatny NetBird peer jednorazovym setup key a klic
   potom neukladejte;
7. spustte `systemctl enable --now nginx netbird turris-federation-proxy.timer`
   a rucne `systemctl start turris-federation-proxy.service`.

Kazda sluzba je dostupna jako `https://<id>.proxy.cacke.internal/`. Nginx mapuje
koren verejneho hostu na deklarovanou `basePath`, predava WebSocket upgrade,
overuje TLS upstreamu a neznamy Host odmita kodem 421. Aplikace s pevnym
kanonickym URL, Domain cookies nebo vlastni Host validaci potrebuje samostatnou
akceptaci; samotny uspesny TLS handshake nestaci.

## Akceptace na skutecnem zarizeni

- `lxc-info`, autostart a restart Turrisu potvrdi samostatny bezici kontejner;
- nginx posloucha jen na NetBird IP a certifikat projde `openssl s_client` pro
  kazde publikovane jmeno;
- klient ve schvalene NetBird skupine vidi TCP/443 proxy, ale ne LAN prefix;
- klient mimo skupinu proxy neotevre;
- z LXC projdou jen SSH/DNS na lokalni Turris, WAN pro NetBird a vybrane
  upstream IP:port; jina LAN IP i jiny port selzou;
- pridani a odebrani ID se projevi v nginx i router firewallu;
- podvrzeny, prosly, cizim routerem podepsany nebo syntakticky vadny manifest se
  odmitne; po 120 sekundach bez obnovy nezustane zadny upstream;
- restart LXC/Turrisu a rollback zachovaji posledni potvrzenou konfiguraci bez
  rozsireni opravneni.

Podklady k nasazeni: [Turris LXC dokumentace](https://docs.turris.cz/geek/lxc/lxc/)
a [NetBird Networks](https://docs.netbird.io/manage/networks).
