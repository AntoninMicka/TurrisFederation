# Webový přehled na Turrisu

Po novém LAN deployi nebo aktualizaci agenta se na úvodní obrazovce Turrisu
objeví dlaždice **Turris Federation**. Přehled je dostupný na
`https://<LAN-adresa-routeru>/turris-federation/`. Přístup používá systémové
přihlášení routeru přes PAM (HTTP Basic Auth); nepřebírá přihlašovací relaci
reForisu. Používejte HTTPS webserveru routeru.

Web zobrazuje místní přijatou a aplikovanou revizi, poslední výsledek agenta,
čas jeho kontroly, čekající protějšky a uzly s LAN/ZeroTier/WireGuard adresami.
U přijatých protějšků jsou samostatné semafory pingu přes ZeroTier a WireGuard,
měřené z tohoto routeru. Tlačítko **Spustit ping · 5 paketů** odešle právě
5 pingů každou cestou ke každému přijatému protějšku. Nový požadavek nahrazuje
předchozí měření; výsledky se nesčítají do historie. Vlastní router a drafty
se neměří. Zelená znamená 95–100 %, žlutá 80 až méně než 95 %, červená méně
než 80 %: při pěti paketech tedy 5/5 zelená, 4/5 žlutá, 3/5 a méně červená.
Web uvádí počet odpovědí a stáří měření. Bez vzorků, při chybě spuštění pingu
nebo po více než 120 s je semafor šedý. Při změně konfigurace se staré výsledky
nezobrazují. Členství samo neprokazuje aktuální dosažitelnost.

Měření běží na pozadí a stránka během něj obnovuje uložený stav. Současně
může běžet jen jeden požadavek na routeru. Obnovení stránky ani tlačítko
**Obnovit stav** nový ping nespouštějí. Pravidelná kontrola agenta neposílá ICMP;
pasivně ověřuje WireGuard identitu, peery, routy a stáří posledního handshake
(nejvýše 180 s). Tato kontrola nenahrazuje test ztrátovosti.

Web umožňuje číst stav a spustit diagnostiku. Jediný povolený POST je
`/turris-federation/diagnostics` s tokenem z formuláře; cíle určuje podepsaná
aplikovaná konfigurace. Výsledky ukládá odděleně do `diagnostics.json`, takže
nepřepisuje stav deploye. Změna konfigurace během měření výsledky zneplatní.
Web nevystavuje klíče, surové soubory, synchronizační API ani instalaci nebo
změnu konfigurace. Při poškozené konfiguraci vrací chybu bez interních podrobností.
Změny sítě se nadále podepisují v notebooku; aktualizace softwaru vyžadují přímou LAN.

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
Lokální testy pokrývají vykreslení, escapování, HTTP cesty, omezení zápisů na diagnostiku,
opravení oprávnění nových souborů a návrat při chybě aktualizace.
Zobrazení dlaždice, PAM přihlášení a souběh s ostatními webovými aplikacemi
je ještě potřeba ověřit na skutečném Turrisu.
