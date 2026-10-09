# Webové řízení na Turrisu

Cílově jde o jediné trvalé rozhraní Turris Federation. Vedle dnešního přehledu a
Zlatých stránek převezme správu členství, NetBirdu, podepsané topologie a obnovy
federační autority. Současný stav níže je užší a tyto správní funkce ještě nemá.

Po novém LAN deployi nebo aktualizaci agenta se na úvodní obrazovce Turrisu
objeví dlaždice **Turris Federation**. Přehled je dostupný na
`https://<LAN-adresa-routeru>/turris-federation/`. Výchozí první záložka
**Zlaté stránky** je read-only a dostupná bez přihlášení. Druhá záložka
**Přehled** vede na `/turris-federation/overview/` a používá systémové
přihlášení routeru přes PAM (HTTP Basic Auth); nepřebírá přihlašovací relaci
reForisu. Na Omnii nejsou další záložky. Používejte HTTPS webserveru routeru.

Přehled obsahuje také místní nastavení DNS lokality. Správce může zapnout zónu
končící `.internal`, například `cacke.internal`, nebo ji vypnout. Agent do Knot
Resolveru načítá pouze přesná `<id-sluzby>.<zona>` jména z validovaných místních
Zlatých stránek. Tato volba nemění firewall, routy, DHCP ani NetBird Cloud.

Samostatná část **NetBird Cloud · jednorázové zprovoznění** umí připravit
Network lokality, její celé LAN prefixy, wildcard doménový resource, tento
router jako routing peer a policy z vybrané zdrojové skupiny. První požadavek je
pouze read-only náhled. Aplikování token vyžádá znovu a proběhne jen tehdy, když
se přepočtený plán shoduje s náhledem. Použitý token se neukládá do souboru,
HTML ani logu. Při dílčí chybě se mažou v opačném pořadí pouze objekty vytvořené
daným pokusem; existující cloudová konfigurace zůstává nedotčená.

Před cloudovým krokem část **Místní NetBird klient** vytvoří read-only plán
instalace balíčku z oficiálního OpenWrt feedu, povolení a spuštění procd služby,
UCI rozhraní `wt0` a plného forwardingu mezi NetBird zónou a `lan`. Aplikování
registrace vyžaduje jednorázový setup key. Web jej neukládá ani nevkládá do
argumentů procesu; klient jej přečte z anonymní děděné pipe přes
`--setup-key-file`. Při chybě se vrátí nově přidané UCI sekce a původně vypnutá
služba, ale již stažený balíček zůstane pro diagnostiku a bezpečné opakování.
Setup key a Network Admin PAT jsou oddělená pověření: užší PAT spravuje cloudové
Networks až po úspěšné místní registraci a neumí vytvářet setup keys.

Web zobrazuje místní přijatou a aplikovanou revizi, poslední výsledek agenta,
čas jeho kontroly, čekající protějšky a uzly s LAN/ZeroTier/WireGuard adresami.
U každého routeru uvádí otisk verze agenta a čas vytvoření instalované kopie.
Shodná verze je zelená, rozdílná červená a chybějící údaj ze staršího agenta
je zvýrazněný jako neznámý. Metadata protějšků pocházejí z jejich podepsaných
provozních reportů.
Pod každým přijatým uzlem zobrazuje také jeho podepsaný katalog pasivně známých
IPv4 sousedů v příslušných LAN sítích a čas pozorování. Jméno se doplní z DHCP
lease, pokud je dostupné. Agent hosty aktivně neskenuje a mezi routery neposílá
MAC adresy; proto prázdný seznam neprokazuje, že je LAN bez dalších zařízení.
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

Přihlášený přehled umožňuje číst stav, spravovat místní definice služeb a
spustit diagnostiku. Diagnostický POST vede na
`/turris-federation/overview/diagnostics` a vyžaduje token z formuláře; cíle
určuje podepsaná aplikovaná konfigurace. Editor používá stejně chráněné cesty
pod `/turris-federation/overview/services/`. Výsledky diagnostiky ukládá
odděleně do `diagnostics.json`, takže
nepřepisuje stav deploye. Změna konfigurace během měření výsledky zneplatní.
Web nevystavuje klíče ani surové soubory. Při poškozené konfiguraci vrací chybu
bez interních podrobností. V současné legacy implementaci se změny sítě ještě
podepisují v notebooku a aktualizace softwaru vyžadují přímou LAN. Router-only
migrace přesune podepisování na výslovně zvolený autoritativní Turris, aniž by
zpřístupnila kořenový klíč webovému procesu nebo ostatním routerům.

## Instalované součásti

- `/etc/turris-webapps/80-turris-federation.json`: definice dlaždice.
- `/www/webapps-icons/turris-federation.svg`: ikona dostupná přes `/icons/`.
- `/etc/lighttpd/conf.d/turris-federation.conf`: veřejná proxy Zlatých stránek
  a PAM chráněná proxy přehledu.
- Druhá instance procd služby `turris-federation` spouští web na `127.0.0.1:8845`.
  Synchronizační agent používá samostatnou instanci a port 8844.

Nasazení vyžaduje standardní webové prostředí Turrisu (WebApps a lighttpd).
Instalátor doplní moduly `lighttpd-mod-proxy`, `lighttpd-mod-auth`,
`lighttpd-mod-authn_pam` a `lighttpd-mod-authn_file`. Neotvírá další port ve
firewallu. Před reloadem spustí `lighttpd -tt`; při selhání vrátí původní
webové soubory a jejich oprávnění. Opakovaná instalace nahrazuje stejnou dlaždici
bez duplikace. Na konci deploye ověří veřejnou odpověď Zlatých stránek a PAM
výzvu chráněného přehledu.
Obsah webu, konfigurace a ikony je zahrnutý do otisku deploy artefaktu.

Implementace registrace a proxy vychází z
[oficiální specifikace Turris WebApps](https://gitlab.nic.cz/turris/webapps/-/blob/master/README.md).
Lokální testy pokrývají vykreslení, escapování, veřejnou a chráněnou HTTP cestu,
omezení zápisů na diagnostiku, editor a místní NetBird plán,
validaci podepsaného katalogu, opravení oprávnění nových souborů a návrat při chybě aktualizace.
Zobrazení dlaždice, PAM přihlášení a souběh s ostatními webovými aplikacemi
je ještě potřeba ověřit na skutečném Turrisu.
