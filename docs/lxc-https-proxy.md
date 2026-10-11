# Aplikační HTTPS gateway v LXC

Stav: implementovany format podepsaneho manifestu, fail-closed reconciler nginx a
systemd timer. Vytvoření LXC, certifikát a NetBird policy zatím nebyly fyzicky
přijaty.

## Bezpecnostni hranice

Proxy je samostatný LXC v běžné LAN a samostatný NetBird peer. Je to aplikační
gateway, nikoli L3 router: neinzeruje LAN prefix, nemá IP forwarding ani NAT a
není NetBird routing peerem. Nginx poslouchá pouze na NetBird IP kontejneru,
nikoli na jeho LAN adrese. Klientská NetBird skupina dostane peer-to-peer policy
jen na tento peer a TCP/443; nedostane LAN resource ani cestu do LAN.

LXC tedy smí jako běžný LAN host navazovat spojení k lokálním službám. VPN klient
však nikdy neposílá LAN pakety skrz kontejner: ukončí TLS na nginx a nginx vytvoří
nové aplikační spojení pouze k endpointu z podepsaného allowlistu. Kompromitovaný
root uvnitř LXC by měl LAN oprávnění tohoto hostu; volitelný egress firewall
omezující cíle na publikované `hostAddress:port` je proto vhodná druhá vrstva,
nikoli podmínka aplikačního gateway modelu.

Při nedostupnosti Turrisu proxy používá poslední podepsaný manifest nejvýše do
jeho expirace (120 sekund), pak atomicky nasadí prázdnou konfiguraci bez upstreamu.

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

Na Turrisu ukládejte běžný linuxový LXC na externí SSD/HDD, ne na interní eMMC.
Oficiální Turris postup používá LXC utilities a `lxc-create`; kontejner přidejte
do `/etc/config/lxc-auto` až po ověření ručního startu. Výchozí připojení do LAN
bridge tomuto návrhu vyhovuje. Přidělte kontejneru stabilní LAN adresu, zakažte
v něm IPv4/IPv6 forwarding a nevytvářejte pro něj žádný LAN resource v NetBirdu.

Uvnitř Debian/Ubuntu LXC nainstalujte `nginx`, `openssh-client`, `openssl`,
`ca-certificates`, Python 3 a oficialniho NetBird klienta. Potom:

1. zkopirujte `proxy/tf_proxy.py` do
   `/usr/local/lib/turris-federation-proxy/tf_proxy.py`;
2. zkopirujte obe systemd jednotky z `proxy/` do `/etc/systemd/system/`;
3. zkopírujte `proxy/90-turris-federation-proxy.conf` do `/etc/sysctl.d/`,
   načtěte jej přes `sysctl --system` a ověřte obě hodnoty;
4. vytvorte `/etc/turris-federation-proxy/config.json` podle
   `proxy/config.example.json` a vsechny klice/certifikaty nastavte na `0600`;
5. do systemoveho trust store pridejte CA HTTPS upstreamu; `proxy_ssl_verify`
   se nikdy nevypina;
6. vydejte certifikat pro `*.proxy.cacke.internal` a pripnete odpovidajici DNS
   jmena na NetBird IP proxy;
7. zaregistrujte LXC jako samostatny NetBird peer jednorazovym setup key a klic
   potom neukladejte;
8. spustte `systemctl enable --now nginx netbird turris-federation-proxy.timer`
   a rucne `systemctl start turris-federation-proxy.service`.

Kazda sluzba je dostupna jako `https://<id>.proxy.cacke.internal/`. Nginx mapuje
koren verejneho hostu na deklarovanou `basePath`, predava WebSocket upgrade,
overuje TLS upstreamu a neznamy Host odmita kodem 421. Aplikace s pevnym
kanonickym URL, Domain cookies nebo vlastni Host validaci potrebuje samostatnou
akceptaci; samotny uspesny TLS handshake nestaci.

## Akceptace na skutecnem zarizeni

- `lxc-info`, autostart a restart Turrisu potvrdi samostatny bezici kontejner;
- `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` vrátí dvě nuly a
  kontejner neprovádí NAT;
- nginx posloucha jen na NetBird IP a certifikat projde `openssl s_client` pro
  kazde publikovane jmeno;
- klient ve schvalene NetBird skupine vidi TCP/443 proxy, ale ne LAN prefix;
- klient mimo skupinu proxy neotevre;
- z VPN klienta neprojde ping, TCP ani UDP přímo na žádnou LAN adresu;
- LXC načítá manifest pouze z lokální LAN adresy vlastního Turrisu a připnutý
  host key zabrání záměně routeru;
- přidání a odebrání ID se projeví v nginx; při použití volitelného egress
  firewallu se stejný allowlist promítne i do něj;
- podvrzeny, prosly, cizim routerem podepsany nebo syntakticky vadny manifest se
  odmitne; po 120 sekundach bez obnovy nezustane zadny upstream;
- restart LXC/Turrisu a rollback zachovaji posledni potvrzenou konfiguraci bez
  rozsireni opravneni.

Podklady k nasazeni: [Turris LXC dokumentace](https://docs.turris.cz/geek/lxc/lxc/)
a [NetBird Networks](https://docs.netbird.io/manage/networks).
