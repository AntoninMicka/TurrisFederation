# Zlaté stránky služeb

Stav: místní editor, podepsaná agregace, read-only seznam a otevírání HTTP(S)
v systémovém prohlížeči jsou implementované a ověřené v desktopové
aplikaci i na skutečném Turrisu. Administrátor může uživatelskému notebooku
předat kořenovou identitou podepsaný read-only snapshot katalogů a verzí jako
součást finální pozvánky nebo aktualizačního balíčku. Fyzická akceptace tohoto
přenosu na dvou noteboocích zůstává otevřená.

## Cíl

Router, který už oznamuje pasivně známé hosty ve své LAN, umožní místnímu
správci pojmenovat služby dostupné na těchto hostech. Ověřené katalogy všech
přijatých routerů se v desktopové aplikaci a samostatné první záložce
routerového WebApps rozhraní složí do jednoho seznamu **Zlaté stránky
služeb**.

Příklady po výběru hosta:

- `Ollama`, protokol `tcp`, port `11434`;
- `Chatbot`, protokol `https`, port `8080`;
- `Home Assistant`, protokol `http`, port `8123`, cesta `/lovelace`.

Zkrácený zápis `ollama:11434` znamená název a port na již vybraném hostu.
Zápis `https:chatbot:8080` navíc určuje protokol. Port je vždy celé číslo
v rozsahu `1–65535`; větší hodnoty se odmítnou.

## Vlastnictví a datový model

Definice je místní údaj oznamujícího routeru, nikoli automaticky objevená
vlastnost hosta. Router ji smí publikovat jen pro IPv4 adresu uvnitř některého
ze svých podepsaných LAN prefixů. Navržená položka obsahuje:

```json
{
  "id": "ollama-main",
  "name": "Ollama",
  "hostAddress": "192.168.100.20",
  "protocol": "tcp",
  "port": 11434,
  "path": null
}
```

- `id` je stabilní lokální identifikátor pro úpravy a odstranění;
- `name` je zobrazovaný název bez řídicích znaků;
- `hostAddress` musí patřit oznamujícímu routeru; editor dovolí novou službu
  přiřadit pouze hostu z jeho pasivně propagovaného seznamu;
- `protocol` je v první verzi pouze `tcp`, `http` nebo `https`;
- `port` je povinný v rozsahu `1–65535`;
- `path` je volitelná absolutní cesta pouze pro `http` a `https`, bez údajů
  uživatele, hesla, query nebo fragmentu.

První verze omezí počet položek na 128 na router a délku názvu na 80 znaků.
Duplicitní `id` se odmítne; shodný endpoint může mít více názvů jen po výslovném
potvrzení správce.

## Uložení a publikování

Místní editor je součástí přihlášené záložky **Přehled** daného routeru.
Zápis vyžaduje PAM přihlášení, CSRF token, přesný tvar požadavku a atomické
uložení do samostatného souboru vlastněného službou. Definice nemění UCI ani
firewall.
Editor nemění konfiguraci cílového hosta, firewall ani přímo nevolá NetBird API.
Navržená NetBird integrace promítne platný katalog místním agentem pouze do DNS
zóny vlastněné routerem. Správce nejdřív vybere
propagovaného hosta, potom vidí jen jeho služby a může k němu doplnit další.
Host s existujícími
definicemi zůstane v editoru dostupný i při dočasném výpadku z pasivního
pozorování, aby šlo jeho služby opravit nebo odstranit.
Každý existující záznam má akci **Upravit**; formulář předvyplní všechna pole a
zachová stabilní `id`, takže úprava nevytvoří vedlejší novou službu.

Router přidá validovaný seznam do svého podepsaného provozního reportu vedle
katalogu hostů. Příjemce ověří podpis routeru, členství, vlastnictví cílové IP,
protokol, port, limity a přesný tvar každé položky. Neplatný katalog se celý
odmítne; nesmí částečně prosáknout do globálního seznamu.

Routerový agent umí být zdrojem vlastní stabilní DNS
zóny uložené v podepsané topologii, například `cacke.internal`. Místní agent z
validovaného `services.json` atomicky složí přesné `A` záznamy podle ID
služby. Změna nebo odstranění položky se projeví jen v této zóně. Router nedostane
NetBird management token a nebude moci měnit DNS jiného uzlu. Centrální
konfigurace NetBirdu pouze jednou přiřadí wildcard domain resource danému routing
peeru; hvězdička deleguje prostor, ale místní DNS neodpoví na názvy bez
odpovídající položky katalogu. Ostatní federované routery tuto zónu podmíněně
forwardují přes NetBird, takže záznamy fungují klientům NetBirdu i ve všech LAN.
Zlaté stránky nevytvářejí firewallová pravidla a neomezují vzájemný provoz
federovaných sítí.

Na Turris OS 9.1 agent používá podporovaný `hints` control socket běžícího Knot
Resolveru. Zdrojový hosts soubor i seznam naposledy načtených jmen ukládá
atomicky; čitelnou běhovou kopii vytváří jen v `/tmp/kresd`. Každých 30 sekund
záznamy obnoví, takže přežijí restart resolveru. Spravuje
jen vlastní přesná jména; nevkládá wildcard a nemění UCI resolveru, DHCP ani
firewall. Zapnutí, změna a vypnutí zóny je v PAM chráněném WebApps přehledu.
Zóna musí končit `.internal` a ID služby použité jako DNS label smí obsahovat jen
malá písmena, číslice a vnitřní pomlčky.

Uložení nebo odstranění místní služby aktualizuje stejný snapshot v provozním
reportu okamžitě. Přijaté routery jej stáhnou v následujícím periodickém
synchronizačním cyklu; editor proto nesmí čekat na zdravotní kontrolu, než
změnu začne publikovat.

Rollback síťové konfigurace nesmí katalog vymazat ani zastavit jeho obnovování.
Agent zachová poslední ověřenou dvojici `hosts`/`hostsObservedAt` a
`services`/`servicesObservedAt` a pokračuje v samostatném periodickém stažení
katalogů i tehdy, když síťová revize zůstala v rollbacku;
při každém podepsaném dotazu navíc znovu složí hosty z pasivní tabulky sousedů
a DHCP lease a služby z autoritativního `services.json`. Neprovádí přitom
aktivní skenování. Režim **Pouze software** u již přijatého routeru nový agent
ověří a spustí bez jakékoli změny sítě; kompletní aktualizace jej spustí ještě
před změnou sítě. I případný následný rollback proto vrací katalog a verzi
nového agenta.

Všechny cesty, které zapisují stav nasazení nebo distribuovaný report, slučují
části katalogu nezávisle. Chybějící pole znamená „tato odpověď údaj neobsahuje“
a nesmí smazat dříve ověřenou hodnotu; teprve explicitní prázdný seznam s novým
časem pozorování autoritativně odstraní hosty nebo služby. To platí pro průběžné
obnovení, distribuci nové revize, fázi potvrzování, úspěšné potvrzení i rollback.
Síťové dotazy se přitom neprovádějí pod zámkem místního stavu, aby se dva uzly
v rollbacku navzájem nezablokovaly.

Agregovaný záznam navíc vždy nese identitu a název oznamujícího routeru,
čas pozorování a stav čerstvosti. Při nedostupnosti routeru lze zobrazit poslední
ověřený seznam jako zastaralý. Odebrání routeru z členství odstraní i jeho služby.

## Zobrazení a otevírání

Společný seznam umožní filtrovat podle názvu služby, protokolu, hosta a lokality.
Každá položka ukáže alespoň:

- název služby a endpoint;
- hosta a oznamující router;
- protokol a stáří posledního ověřeného reportu;
- zda je cílový LAN prefix z tohoto notebooku routovatelný.

Pro `tcp` aplikace nabídne kopírování `host:port`. Pro `http` a `https` sestaví
URL pouze z validovaných polí a nabídne **Otevřít v systémovém prohlížeči**.
Tato akce sama nepotvrzuje dostupnost služby ani důvěryhodnost jejího TLS
certifikátu.

Volba **Otevřít v aplikaci** je samostatná pozdější fáze. Vložený obsah musí být
izolovaný od Tauri API, místního backendu a přihlašovacích údajů aplikace, nesmí
dostat privilegovaná oprávnění ani možnost navigovat na `file:`, `data:`, vlastní
aplikační schémata nebo jiné nevalidované cíle. Chyba certifikátu se nesmí
automaticky obcházet. Pokud takovou izolaci použitý webview spolehlivě neposkytne,
zůstane podporované jen otevření v systémovém prohlížeči.

## Bezpečnostní hranice

- Read-only Zlaté stránky na routeru jsou dostupné bez přihlášení. Síťový
  přehled, diagnostika a editor služeb jsou na samostatné cestě chráněné PAM;
  oddělení vynucuje lighttpd, nikoli pouze skrytí prvků v HTML.
- Položka Zlatých stránek nevytváří firewallová pravidla ani nové routy.
- Router neprovádí plošný scan portů. Položka je tvrzení místního správce,
  nikoli důkaz, že služba právě odpovídá.
- Budoucí kontrola dostupnosti smí být jen jednotlivá, uživatelem vyžádaná
  kontrola přesně vybraného endpointu s krátkým timeoutem.
- URL nepřijímá uživatelské údaje, vlastní schéma ani libovolný hostname mimo
  ověřený host katalog/LAN adresu oznamujícího uzlu.
- Uživatelský notebook smí číst ověřený globální seznam a používat služby,
  ale nesmí tím získat právo měnit katalog na routeru.
- Katalog nesmí obsahovat tokeny, hesla, hlavičky, cookies, MAC adresy ani obsah
  odpovědí služby.

## Navržené pořadí implementace

- [x] Formát, validace, atomické místní úložiště a PAM/CSRF editor na routeru.
- [x] Podepsaný přenos v reportu, agregace, stáří a odstranění po odvolání uzlu.
- [x] Jednotný read-only seznam v desktopu a WebApps, filtry a kopírování endpointu.
- [x] Doplnit autentizovaný přenos ověřeného katalogu na uživatelské notebooky,
  které nemají lokální administrační cache provozních reportů.
- [x] Bezpečné otevírání `http`/`https` v systémovém prohlížeči.
- [x] Místní `.internal` zóna z přesných záznamů Zlatých stránek pro Knot Resolver,
  včetně WebApps nastavení a vypnutí.
- [ ] Samostatné bezpečnostní posouzení izolovaného zobrazení uvnitř aplikace.
- [ ] Test na dvou routerech a notebooku včetně neplatných portů, cizích LAN adres,
   podvržených reportů, zastaralého katalogu a odvolaného routeru.
