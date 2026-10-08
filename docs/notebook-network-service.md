# Privilegovaná síťová služba notebooku

Stav: schválený návrh a první vývojová implementace pro Linux. Nasazení
spravovaného profilu na notebook a následná dostupnost routeru `Palackeho` byly
fyzicky potvrzené 8. 10. 2026. Úplná akceptace nftables, ZeroTier,
NetworkManageru a provozních hraničních stavů zůstává otevřená.

`turris-federation-network.service` odděluje privilegované síťové operace od
uživatelského backendu a grafické aplikace. Běží jako systémová služba a vlastní
jen následující úzký rozsah:

- sanitizované čtení stavu ZeroTier bez zveřejnění `authtoken.secret`;
- `join` a `leave` pro syntakticky validované šestnáctimístné Network ID;
- nftables guard, který zahazuje každý forwardovaný paket vstupující nebo
  vystupující přes `tf_notebook`;
- čtení přítomnosti `tf_notebook`, jeho IPv4 rout a systémového forwardingu;
- průběžnou obnovu chybějících nebo změněných pravidel guardu;
- vytvoření a průběžný reconcile jediného NetworkManager/WireGuard profilu
  `turris-federation` z požadovaného stavu předaného notebookovým backendem;
- automatickou aktivaci profilu po restartu služby, ztrátě profilu nebo změně
  fyzického připojení notebooku.

Služba neobsahuje kořenový klíč federace, notebookové TLS klíče, SSH údaje ani
obecné rozhraní pro spouštění příkazů. WireGuard privátní klíč potřebný pro
spravovaný profil přijme pouze přes lokální socket od povoleného UID a uloží jej
do root-only požadovaného stavu; nepředává jej v argumentech procesu.
Neautorizuje zařízení
v ZeroTier Central a nemění forwarding pro ostatní rozhraní. Docker, libvirt a
jiné lokální sítě proto mohou dál používat systémový forwarding; guard blokuje
jen transit, jehož vstupem nebo výstupem je `tf_notebook`. Provoz místního hostu
v řetězcích input/output pravidla nemění.

## Lokální API a oprávnění

Socket je `/run/turris-federation/notebook-network.sock`. Vlastní jej `root` a
primární skupina UID z `/etc/turris-federation/notebook-network.json`, má režim
`0660` a server každý požadavek znovu ověřuje pomocí `SO_PEERCRED`. Povolené
akce jsou pouze `status`, `reconcile`, `zerotier_join`, `zerotier_leave` a
`vpn_reconcile`.
Požadavek je jeden JSON řádek s limitem 64 KiB. Služba neimplementuje shell ani
nepřijímá cesty či argumenty systémových příkazů.

`vpn_reconcile` přijímá jen přesné schéma `tf-notebook-system-vpn-1`: klíče
WireGuard, jednu privátní IPv4 `/32`, revizi a nejvýše 128 peerů. Endpoint musí
být privátní číselná IPv4 na pevném portu 51830. Každý peer smí mít nejvýše 64
nepřekrývajících se privátních IPv4 prefixů; výchozí, veřejné, IPv6 a
překrývající se routy služba odmítne. Backend tento stav odvozuje pouze z
lokálně ověřené podepsané topologie. Root služba sama podpis neověřuje, proto je
socket záměrně omezený na jediné instalační UID a root.

Uživatelská jednotka backendu záměrně nepoužívá filesystemové sandboxovací
direktivy `ProtectSystem`, `ProtectHome` ani `PrivateTmp`. Na Ubuntu s AppArmor
by pro uživatelskou službu vytvořily profil `unprivileged_userns`, který odmítá
spojení k rootem vlastněnému socketu jako „disconnected path“, i když skupina a
režim socketu odpovídají. Backend zůstává neprivilegovaný, používá
`NoNewPrivileges`, `UMask=0077`, omezené rodiny adres včetně `AF_NETLINK`
potřebného pro read-only síťové kontroly příkazem `ip` a zákaz vytváření dalších
namespaces; systémové soubory nadále chrání běžná unixová oprávnění.

Vývojový instalátor uděluje tuto lokální síťovou autoritu jednomu UID, které
výslovně spustilo `run.sh` a potvrdilo `sudo`. Produkční balíček má stejné
oprávnění vyjádřit polkit politikou a systémovou skupinou; nesmí rozšířit API na
obecné root operace.

## Instalace a aktualizace

`run.sh` nejprve ověří obsah instalovaného skriptu, systemd jednotky,
konfiguraci UID a aktivní stav. Jen při rozdílu vyvolá:

```bash
sudo python3 scripts/install_notebook_network_service.py --uid "$UID"
```

Instalátor zapisuje soubory atomicky, provede `systemctl daemon-reload`, jednotku
povolí pro start systému a restartuje ji. Instaluje:

- `/usr/lib/turris-federation/notebook_network_service.py`;
- `/etc/systemd/system/turris-federation-network.service`;
- `/etc/turris-federation/notebook-network.json`.

Runtime socket vytváří systemd `RuntimeDirectory`; poslední sanitizovaná účtenka
je v `/var/lib/turris-federation-notebook-network/state.json`. Požadovaný VPN
stav včetně privátního klíče je pouze pro root v
`/var/lib/turris-federation-notebook-network/vpn.json`; uživatelský stav obsahuje
jen revizi, hash a očekávané routy. Pravidla jsou v
samostatné tabulce `inet turris_federation_notebook` a jejich nahrazení probíhá
jednou nft transakcí. Služba cizí nftables tabulky nemění.
Dočasný WireGuard import vzniká s režimem `0600` pouze uvnitř zapisovatelného
`RuntimeDirectory` a po importu se vždy odstraní; obecný `/run` zůstává díky
`ProtectSystem=strict` jen pro čtení.

## Akceptace

Na skutečném notebooku je nutné ověřit:

1. opakovaný `run.sh` nevyžádá `sudo`, pokud se artefakt ani stav nezměnil;
2. běžný uživatel získá sanitizovaný ZeroTier stav, ale nepřečte token;
3. cizí UID je socketem i kontrolou `SO_PEERCRED` odmítnuté;
4. pravidla přežijí restart a služba je po ručním odstranění obnoví;
5. host dosáhne z `tf_notebook` na povolené cíle, ale pakety se mezi
   `tf_notebook` a fyzickým/Docker rozhraním nepřeposílají;
6. změna Wi-Fi/hotspotu nevyžaduje nový instalační plán a profil se automaticky
   znovu aktivuje;
7. změna podepsané topologie atomicky vymění profil, ověří jeho `/32` i všechny
   routy a při chybě obnoví předchozí profil;
8. vypnutí nebo chyba služby nesmaže existující guard pravidla.

Body 6 a 7 jsou pokryté lokálními testy s nahrazenými systémovými příkazy.
První skutečné nasazení spravovaného profilu a dostupnost routeru `Palackeho`
po nasazení byly potvrzené 8. 10. 2026. Změna hotspotu, samostatný záznam
handshaku a rout, zákaz forwardingu, obnova profilu a ostatní body výše zatím
nejsou fyzicky ověřené jako celek.

Úspěšný reconcile na novou podepsanou revizi zahodí uloženou místní diagnostiku
starší revize. Diagnostika se nepřenáší mezi notebooky a nová kontrola se spouští
výslovně, aby UI nezaměnilo staré pingy a handshake za aktuální měření.
