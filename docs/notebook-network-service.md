# Privilegovaná síťová služba notebooku

Stav: schválený návrh a první vývojová implementace pro Linux. Fyzická
akceptace instalace, nftables, ZeroTier a NetworkManageru zůstává otevřená.

`turris-federation-network.service` odděluje privilegované síťové operace od
uživatelského backendu a grafické aplikace. Běží jako systémová služba a vlastní
jen následující úzký rozsah:

- sanitizované čtení stavu ZeroTier bez zveřejnění `authtoken.secret`;
- `join` a `leave` pro syntakticky validované šestnáctimístné Network ID;
- nftables guard, který zahazuje každý forwardovaný paket vstupující nebo
  vystupující přes `tf_notebook`;
- čtení přítomnosti `tf_notebook`, jeho IPv4 rout a systémového forwardingu;
- průběžnou obnovu chybějících nebo změněných pravidel guardu.

Služba neobsahuje kořenový klíč federace, notebookové TLS/WireGuard privátní
klíče, SSH údaje ani obecné rozhraní pro spouštění příkazů. Neautorizuje zařízení
v ZeroTier Central a nemění forwarding pro ostatní rozhraní. Docker, libvirt a
jiné lokální sítě proto mohou dál používat systémový forwarding; guard blokuje
jen transit, jehož vstupem nebo výstupem je `tf_notebook`. Provoz místního hostu
v řetězcích input/output pravidla nemění.

## Lokální API a oprávnění

Socket je `/run/turris-federation/notebook-network.sock`. Vlastní jej `root` a
primární skupina UID z `/etc/turris-federation/notebook-network.json`, má režim
`0660` a server každý požadavek znovu ověřuje pomocí `SO_PEERCRED`. Povolené
akce jsou pouze `status`, `reconcile`, `zerotier_join` a `zerotier_leave`.
Požadavek je jeden JSON řádek s limitem 64 KiB. Služba neimplementuje shell ani
nepřijímá cesty či argumenty systémových příkazů.

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
je v `/var/lib/turris-federation-notebook-network/state.json`. Pravidla jsou v
samostatné tabulce `inet turris_federation_notebook` a jejich nahrazení probíhá
jednou nft transakcí. Služba cizí nftables tabulky nemění.

## Akceptace

Na skutečném notebooku je nutné ověřit:

1. opakovaný `run.sh` nevyžádá `sudo`, pokud se artefakt ani stav nezměnil;
2. běžný uživatel získá sanitizovaný ZeroTier stav, ale nepřečte token;
3. cizí UID je socketem i kontrolou `SO_PEERCRED` odmítnuté;
4. pravidla přežijí restart a služba je po ručním odstranění obnoví;
5. host dosáhne z `tf_notebook` na povolené cíle, ale pakety se mezi
   `tf_notebook` a fyzickým/Docker rozhraním nepřeposílají;
6. vypnutí nebo chyba služby nesmaže existující guard pravidla.
