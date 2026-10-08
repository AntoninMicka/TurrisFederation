# Mobilní klient při migraci na NetBird

Stav: **návrh k ověření, není implementováno ani provozně přijato**.

## Cíl

Migraci transportu ze současného `ZeroTier → tf_wg` na self-hosted NetBird
spojit s podporou telefonu jako uživatelského koncového uzlu. Telefon smí
používat výslovně povolené federované služby a zobrazit ověřený read-only stav,
ale nesmí se stát routerem lokality ani administrátorským notebookem.

NetBird zajišťuje VPN transport, NAT traversal, relay fallback a vynucení
síťových politik. Turris Federation zůstává zdrojem pravdy pro členství, role,
lokality, LAN prefixy, katalog služeb a požadovaná oprávnění. Samotná položka ve
Zlatých stránkách nikdy automaticky neuděluje síťový přístup; oprávnění musí být
samostatně a výslovně potvrzené administrátorem.

Přístup telefonu ke službám nebude nahrazovat dočasné přesměrování portů přes
router. Každý dostupný cíl musí mít samostatnou, cílenou NetBird resource policy;
samotná dosažitelnost transportu ani záznam ve Zlatých stránkách přístup neudělí.

## Platformní varianta

### Android

První PoC použije oficiální NetBird aplikaci připojenou k self-hosted management
serveru. Mobilní aplikace Turris Federation nebude v první etapě implementovat
vlastní VPN ani vkládat NetBird engine. Bude samostatným klientem pro:

- přijetí uživatelského členství ve federaci;
- zobrazení stavu připojení, povolených lokalit, hostů a Zlatých stránek;
- bezpečné otevření validovaného HTTP(S) endpointu v systémovém prohlížeči;
- lokální diagnostiku bez administrátorských operací.

Android dovoluje jen jedno aktivní VPN rozhraní. Mobilní uzel proto nebude
současně používat ZeroTier, vlastní `tf_wg` a NetBird. V paralelní migrační fázi
se NetBird zapne pouze vybraným mobilním testovacím uzlům; běžící routerová
federace může zatím zůstat na dosavadním transportu.

### Linuxový telefon

Linuxová varianta použije NetBird CLI/daemon pro ARM64 a omezenou systémovou
službu obdobnou notebookové síťové službě. Uživatelské UI nesmí dostat obecný
root shell ani možnost předávat libovolné argumenty klientovi. Upstream GUI
balíček NetBird není v době návrhu pro ARM64 k dispozici, proto na něm návrh
nesmí záviset.

Stejný aplikační kontrakt má fungovat na klasickém Linuxovém notebooku i
telefonu: rozdílná bude instalace, integrace na pozadí a oprávnění operačního
systému, nikoli role nebo význam podepsaných dat Federation.

## Identita a přijetí zařízení

Mobilní zařízení zůstává existujícím uživatelským koncovým uzlem; nevzniká mu
nová administrátorská role. Datový model může později doplnit typ platformy a
vazbu na NetBird peer ID, ale oprávnění musí stále vycházet z role a explicitní
policy, nikoli z názvu platformy.

Přijetí zařízení použije krátce platný jednorázový NetBird setup key nebo
interaktivní SSO. Dlouhodobý NetBird PAT, kořenový klíč federace ani opakovaně
použitelný setup key nesmí být v QR kódu, pozvánce, podepsané topologii, logu ani
mobilní aplikaci. Setup key vytváří serverová integrační služba s omezeným
oprávněním; mobilní aplikace nesmí získat obecné oprávnění spravovat NetBird.

Federation sváže vlastní ID zařízení s konkrétním NetBird peerem až po ověření
obou stran. Odvolání členství musí odebrat přístupové politiky a peer nebo jeho
pověření, odpojit místní VPN a zabránit dalším aktualizacím. Lokální identita a
uživatelská data se odstraní jen samostatně potvrzenou operací.

## Síťové hranice

Mobilní uzel:

- neinzeruje fyzickou Wi-Fi ani mobilní síť;
- nemá forwarding, masquerade, exit-node ani routing-peer roli;
- nedostává výchozí trasu přes federaci;
- obdrží jen zdroje a protokoly povolené jeho skupině;
- nemá SSH údaje, deploy, audit, root identitu ani administrační API.

Pro nové nasazení se použije NetBird **Networks** a jejich povinné resource
groups/policies, nikoli staré Network Routes bez ACL. Turris router je routing
peer své lokality. Přístup ke službě běžící přímo na routeru a přístup do jeho
LAN jsou dvě samostatná pravidla, protože používají odlišnou vstupní a forward
cestu firewallu.

## Etapy

1. Dokončit fyzickou akceptaci současné federace a zachovat ji jako rollback
   baseline.
2. Zprovoznit self-hosted NetBird control plane a jeden Turris jako testovací
   routing peer bez změny produkční topologie.
3. Připojit běžnou oficiální Android aplikaci a ověřit jednu explicitně
   povolenou službu a jeden LAN zdroj.
4. Navrhnout transportní backend Federation a převod členství, lokalit a
   oprávnění na NetBird peer groups, Networks/resources a policies.
5. Implementovat read-only mobilní klient Federation pro Android; následně
   ověřit Linux ARM64 telefon s CLI/daemonem.
6. Ověřit paralelní provoz a návrat na původní transport, potom postupně převést
   routery a notebooky. `NetBird only` je možný až po samostatném schválení.

## Akceptace mobilního řezu

- Android i zvolený Linux ARM64 telefon přežijí změnu Wi-Fi/mobilních dat,
  uspání a restart a obnoví připojení bez nové dlouhodobé pozvánky.
- Telefon vidí pouze povolené lokality, hosty a služby; zakázané zdroje nemají
  routu ani průchod firewallu.
- Zlaté stránky zobrazují pouze podepsaný katalog a HTTP(S) otevírají v
  systémovém prohlížeči; TCP endpoint pouze kopírují.
- Telefon neinzeruje vlastní síť a nemůže se stát routing peerem ani správcem.
- Odvolání zařízení ukončí jeho přístup i po opětovném připojení k internetu.
- Výpadek control plane neukončí již navázaný přímý provoz, pokud to dovolují
  vlastnosti ověřené verze NetBird; použití relay je v diagnostice viditelné.
- Logy ani exporty neobsahují setup key, PAT, privátní klíč nebo přístupový
  token.

## Otevřená rozhodnutí

- umístění a provozní vlastník veřejně dostupného NetBird control plane;
- SSO versus serverem vydávaný jednorázový setup key pro osobní zařízení;
- distribuce Android klienta Federation (obchod, F-Droid nebo podepsaný APK);
- první podporovaná linuxová mobilní distribuce a její správce služeb;
- zda pozdější sjednocená aplikace smí přímo řídit NetBird klient, nebo zůstane
  bezpečně odděleným read-only klientem.

## Upstream podklady ověřené při návrhu

- [NetBird pro Android](https://docs.netbird.io/get-started/install/android)
- [NetBird na Linuxu](https://docs.netbird.io/get-started/install/linux)
- [Jednorázové setup keys](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys)
- [NetBird Networks a resource policies](https://docs.netbird.io/manage/networks)
- [Android `VpnService`](https://developer.android.com/reference/android/net/VpnService.Builder)
