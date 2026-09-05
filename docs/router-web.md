# Webový přehled na Turrisu

Po novém LAN deployi nebo aktualizaci agenta se na úvodní obrazovce Turrisu
objeví dlaždice **Turris Federation**. Přehled je dostupný na
`https://<LAN-adresa-routeru>/turris-federation/`. Přístup používá systémové
přihlášení routeru přes PAM (HTTP Basic Auth); nepřebírá přihlašovací relaci
reForisu. Používejte HTTPS webserveru routeru.

Web zobrazuje místní přijatou a aplikovanou revizi, poslední výsledek agenta,
čas jeho kontroly, čekající protějšky a uzly s LAN/ZeroTier/WireGuard adresami.
Členství ostatních uzlů není vydáváno za aktuální dosažitelnost. Tlačítko
„Obnovit stav“ znovu načte uložený stav, nespouští síťový audit. Web funguje
nezávisle na synchronizační smyčce a zobrazuje i dosud nenakonfigurovaný router.

Jde o přehled pouze pro čtení. Nevystavuje soukromé ani veřejné klíče, surové
soubory, synchronizační API ani instalaci nebo změnu konfigurace. Při poškozené
konfiguraci vrací chybu bez interních podrobností. Změny sítě se nadále podepisují
v notebooku; instalace a aktualizace softwaru nadále vyžadují přímou LAN.

## Instalované součásti

- `/etc/turris-webapps/80-turris-federation.json`: definice dlaždice.
- `/www/webapps-icons/turris-federation.svg`: ikona dostupná přes `/icons/`.
- `/etc/lighttpd/conf.d/turris-federation.conf`: přihlášení a proxy webového přehledu.
- Druhá instance procd služby `turris-federation` spouští web na `127.0.0.1:8845`.
  Synchronizační agent používá samostatnou instanci a port 8844.

Nasazení vyžaduje standardní webové prostředí Turrisu (WebApps a lighttpd).
Instalátor doplní moduly `lighttpd-mod-proxy`, `lighttpd-mod-auth`,
`lighttpd-mod-authn_pam` a `lighttpd-mod-authn_file`. Neotvírá další port ve
firewallu. Před reloadem spustí `lighttpd -tt`; při selhání vrátí původní
webové soubory a jejich oprávnění. Opakovaná instalace nahrazuje stejnou dlaždici
bez duplikace. Na konci deploye ověří HTTP odpověď místního webového procesu.
Obsah webu, konfigurace a ikony je zahrnutý do otisku deploy artefaktu.

Implementace registrace a proxy vychází z
[oficiální specifikace Turris WebApps](https://gitlab.nic.cz/turris/webapps/-/blob/master/README.md).
Lokální testy pokrývají vykreslení, escapování, HTTP cesty, zákaz zápisu,
opravení oprávnění nových souborů a návrat při chybě aktualizace.
Zobrazení dlaždice, PAM přihlášení a souběh s ostatními webovými aplikacemi
je ještě potřeba ověřit na skutečném Turrisu.
