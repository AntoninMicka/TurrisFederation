# Aplikační HTTPS gateway v LXC

Stav: implementovaný podepsaný manifest, volba služby a volitelný Basic Auth
přímo ve Zlatých stránkách, fail-closed reconciler nginx a automatické vytvoření,
onboarding a aktualizace LXC při deployi routeru. Celý tok zatím nebyl fyzicky
přijat na skutečném Turrisu, LXC a NetBird síti.

## Bezpecnostni hranice

Proxy je samostatný LXC v běžné LAN a samostatný NetBird peer. Je to aplikační
gateway, nikoli L3 router: neinzeruje LAN prefix, nemá IP forwarding ani NAT a
není NetBird routing peerem. Nginx poslouchá pouze na dvou explicitních adresách
kontejneru: NetBird IP pro vzdálené klienty a LAN IP pro místní klienty; nikdy
nepoužívá wildcard `0.0.0.0`. Klientská NetBird skupina dostane peer-to-peer
policy jen na tento peer a TCP/443; nedostane LAN resource ani cestu do LAN.

LXC tedy smí jako běžný LAN host navazovat spojení k lokálním službám. VPN klient
však nikdy neposílá LAN pakety skrz kontejner: ukončí TLS na nginx a nginx vytvoří
nové aplikační spojení pouze k endpointu z podepsaného allowlistu. Kompromitovaný
root uvnitř LXC by měl LAN oprávnění tohoto hostu; volitelný egress firewall
omezující cíle na publikované `hostAddress:port` je proto vhodná druhá vrstva,
nikoli podmínka aplikačního gateway modelu.

Při nedostupnosti Turrisu proxy používá poslední podepsaný manifest nejvýše do
jeho expirace (120 sekund), pak atomicky nasadí prázdnou konfiguraci bez upstreamu.

## Zdroj seznamu

Na lokálním Turrisu správce ve Zlatých stránkách otevře editor služby, zapne
„Přístup přes HTTPS proxy“ a volitelně zadá uživatelské jméno a heslo. Bez jména
je endpoint publikovaný bez Basic Auth. Heslo se nikdy neukládá v otevřeném
textu: router uloží pouze salted `{SSHA}` verifier do soukromého
`proxy-access.json`; veřejný katalog `services.json` ani provozní report jej
neobsahuje. Prázdné heslo při další editaci zachová dosavadní verifier.

Starší výběr pouze podle ID lze jednorázově migrovat příkazem:

```sh
printf '["neurodiary","chatbot"]' |
  python3 /usr/lib/turris-federation/federation.py proxy-select /etc/turris-federation
```

`tcp` sluzby ani cizi/federovane katalogy vybrat nelze. LXC pouziva vlastni SSH
klic, pripina host key a na routeru ma klic v `authorized_keys` s vynucenym
prikazem:

```text
no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,command="python3 /usr/lib/turris-federation/federation.py proxy-manifest /etc/turris-federation" ssh-ed25519 AAAA... tf-proxy
```

Manifest je podepsaný členskou identitou lokálního Turrisu, obsahuje pouze
vybrané endpointy, případný verifier pro nginx a platí 120 sekund. Proxy navíc připíná veřejnou identitu a
`nodeId` tohoto routeru. SSH klic proxy tedy neumozni shell ani vyber jineho
routeru a podvrzeny seznam neprojde.

## LXC a proxy

Turris musí mít `/srv` na externím SSD/HDD. Uživatel v jeho LXC rozhraní ručně
vytvoří kontejner s přesným názvem `tf-proxy` ze stabilního Debian Trixie.
Při validaci routeru aplikace zjistí stav kontejneru a nainstalované verze.
Pokud kontejner existuje, potvrzený deploy si vyžádá doménu proxy a jednorázový
NetBird setup key a potom automaticky:

1. spustí existující `tf-proxy`, pokud je zastavený;
2. nainstaluje nginx, Python, OpenSSH, OpenSSL a oficiální NetBird CLI;
3. předá setup key pouze přes stdin procesu, zaregistruje samostatný peer a klíč
   neuloží do plánu, databáze, routeru ani konfigurace;
4. vytvoří omezený SSH klíč s forced command pouze pro podepsaný manifest;
5. vytvoří lokální CA s šifrovaným privátním klíčem a serverový wildcard
   certifikát, přičemž veřejnou CA nabídne ke stažení na přihlášeném přehledu;
6. zakáže IP forwarding, vygeneruje konfiguraci, ověří nginx a zapne timer.

Opakovaný deploy kontejner ani identity nevytváří znovu. Aktualizuje jen
projektové skripty, systemd jednotky, závislosti a sysctl profil; zachová
`config.json`, SSH klíče, TLS CA, serverový klíč a NetBird identitu. Jiný název
lze před prvním deployem uvést v `/etc/turris-federation/proxy-lxc-name`.
Artefakty se přenášejí jednotlivě do dočasného stagingu a každý se ověří přes
SHA-256. Původní spravované soubory se před výměnou zálohují; neúspěšný reload
je obnoví a staging uklidí. Úspěšná verze se zapíše až nakonec do receipt, takže
přerušený deploy zůstane při příští validaci označený k aktualizaci a bezpečně
se dokončí opakováním.

Setup key má proxy automaticky zařadit do samostatné cílové skupiny. NetBird
policy musí zdrojovým klientům povolit pouze tento peer a TCP/443; proxy nesmí
být routing peer ani dostat LAN resource. DNS zóna domény musí směrovat názvy
`<id>.<doména>` na NetBird IP proxy. Tato cloudová policy/DNS část se při fyzické
akceptaci musí ověřit proti konkrétnímu NetBird účtu.

V místní LAN agent automaticky přidá do Knot Resolveru přesné záznamy pouze pro
služby povolené ve Zlatých stránkách. Stejné jméno `<id>.<doména>` tam ukazuje
na LAN IP LXC. Doména proxy musí být platná `.internal` zóna. Pokud se shoduje
s místní zónou služeb, proxy alias povolené služby nahradí její přímý LAN záznam,
aby jedno jméno nikdy neukazovalo současně na upstream i LXC. Zakázaná nebo
odstraněná služba se při dalším reconcile odstraní; wildcard nevzniká. Tyto
proxy aliasy fungují i bez zapnutí obecné místní DNS zóny Zlatých stránek.

Každá služba je dostupná jako `https://<id>.<zadaná-doména>/`. Nginx mapuje
koren verejneho hostu na deklarovanou `basePath`, predava WebSocket upgrade,
overuje TLS upstreamu a neznamy Host odmita kodem 421. Aplikace s pevnym
kanonickym URL, Domain cookies nebo vlastni Host validaci potrebuje samostatnou
akceptaci; samotny uspesny TLS handshake nestaci.

## Akceptace na skutecnem zarizeni

- `lxc-info`, autostart a restart Turrisu potvrdi samostatny bezici kontejner;
- `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` vrátí dvě nuly a
  kontejner neprovádí NAT;
- nginx posloucha jen na explicitni NetBird a LAN IP a certifikat projde
  `openssl s_client` pro kazde publikovane jmeno;
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
