# ZeroTier: kontrola, nastavení a autorizace

## Postup v aplikaci

1. V části **Síť federace** zadejte 16znakové Network ID a uložte nastavení.
   ID je společné pro tuto federaci a zůstává uložené v místní SQLite databázi.
   Vyberte také web, který používáte: nový ZeroTier Central nebo Legacy Central.
2. U routeru stiskněte **Zkontrolovat ZeroTier** a přihlaste se přes SSH.
   Kontrola nic nemění. Zobrazí dostupnost klienta a služby, ZeroTier ID zařízení,
   členství ve vybrané síti, přidělené adresy a nastavení startu po rebootu.
3. Pokud je potřeba, zvolte **Nainstalovat a nastavit ZeroTier** nebo
   **Nastavit a připojit ZeroTier**. Dialog ukáže kroky a cílové Network ID.
   Zadáním hesla a tlačítkem **Provést nastavení ZeroTier** spustíte změny na routeru.
   Pro nastavení je potřeba SSH uživatel `root`.
4. Po nastavení se podle zaškrtnuté volby otevře systémový prohlížeč.
   Web lze otevřít i tlačítkem **Autorizovat na webu**. Přihlaste se do Central,
   vyberte síť se stejným Network ID a autorizujte konkrétní router podle jeho
   zobrazeného ZeroTier ID. Aplikace neukládá přihlašovací údaje ani API token Central.
5. Vraťte se do aplikace a stiskněte **Obnovit stav ZeroTier**. Kontrola si vyžádá
   SSH heslo pro nový pokus. Ověřte stav členství `OK` a přidělené adresy.

Samotné `ONLINE` potvrzuje spojení služby s infrastrukturou ZeroTier, nikoli
autorizaci ve vybrané síti. `ACCESS_DENIED` vyžaduje autorizaci; při
`REQUESTING_CONFIGURATION` chvíli počkejte a obnovte stav. Viz
[stavy ZeroTier CLI](https://docs.zerotier.com/cli/) a
[postup autorizace pro obě verze Central](https://docs.zerotier.com/quickstart/).

## Co provede nastavení na routeru

- Pokud chybí `zerotier-cli`, spustí `opkg update` a `opkg install zerotier`.
- Rozpozná starší UCI schéma se seznamem `join` nebo novější se sekcí `global`
  a jednotlivými sekcemi `network`. Neznámé schéma odmítne místo zápisu odhadem.
- Zálohuje `/etc/config/zerotier` do soukromého souboru pod
  `/etc/turris-federation/backups/`. Obsah zálohy neopouští router.
- Doplní členství a zapne službu při startu. Existující identitu a ostatní
  sítě zachová; opakované spuštění nepřidává duplicitní členství.
- Spustí službu, pokud neodpovídá, a připojí zvolenou síť přes CLI.
- Povolí spravované adresy a trasy (`allowManaged`) a vypne převzetí výchozí trasy,
  veřejných rozsahů a DNS (`allowDefault`, `allowGlobal`, `allowDNS`).
- Načte konečný stav; úspěšný příkaz `join` sám o sobě neznamená autorizaci.

UCI postup vychází ze
[staršího schématu balíčku](https://github.com/mwarning/zerotier-openwrt/wiki/Old-ZeroTier-setup-guide)
a [současné implementace služby OpenWrt](https://github.com/openwrt/packages/blob/master/net/zerotier/files/etc/init.d/zerotier).
U čerstvé instalace s novým schématem odstraní dodaný příklad sítě Earth před
prvním spuštěním. Již existující konfiguraci dalších sítí neodstraňuje.

## Hranice tohoto kroku

Uložení jiného Network ID v aplikaci nemění routery a neodpojuje je od předchozí
sítě. Starší výsledek kontroly je označený jako výsledek pro jinou síť.
Poslední kontrola se uchovává v databázi včetně času, nejde o živý monitoring.

Nastavení má limit pěti minut. Při selhání může zůstat nainstalovaný balíček nebo
již uložená část konfigurace; před opakováním obnovte stav. Automatický rollback
celé instalace zatím není implementovaný. Neuložené UCI změny a více aktivních
instancí ve starém schématu jsou důvodem k zastavení konfigurace.

Tento krok nemění firewall ani neprovádí propojení LAN sítí či deploy WireGuardu.
Samotné členství v ZeroTier proto nezaručuje průchod správcovského provozu přes
firewall routeru. Návrh těchto pravidel navazuje v deploy fázi.

## Ověření implementace

```bash
cargo test --manifest-path src-tauri/Cargo.toml --offline
python3 scripts/test_zerotier.py
npm run build
```

Shellové testy simulují router v dočasném adresáři. Ověřují obě UCI schémata,
opakované spuštění, zachování jiných sítí a identity, instalaci, start a selhání.
Neprovádějí změny na skutečném routeru. Před deployem zbývá potvrdit funkčnost
na cílovém Turris OS včetně zachování identity a členství po restartu.
