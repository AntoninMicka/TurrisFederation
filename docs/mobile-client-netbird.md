# Mobilní klient při migraci na NetBird

Stav: **návrh k ověření, není implementováno ani provozně přijato**.

## Cíl

Migraci transportu ze současného `ZeroTier → tf_wg` na NetBird spojit s
podporou telefonu jako uživatelského koncového uzlu. První PoC dočasně použije
spravovaný NetBird Cloud; self-hosted control plane zůstává pozdější cílovou
variantou a nesmí být podmínkou ověření transportu. Telefon smí používat
routované federované LAN a zobrazit ověřený read-only stav, ale nesmí se stát
routerem lokality ani administrátorským notebookem.

NetBird zajišťuje VPN transport, NAT traversal, relay fallback a propojení
federovaných LAN. Turris Federation zůstává zdrojem pravdy pro členství, role,
lokality, LAN prefixy a katalog služeb. Mezi přijatými sítěmi se provoz nefiltruje
podle Zlatých stránek; katalog pouze pojmenovává služby v distribuovaném DNS.

Přístup telefonu ke službám nebude používat přesměrování portů přes router.
Přijatý NetBird klient používá routy do federovaných LAN a stejné DNS názvy jako
klienti uvnitř těchto LAN.

## Platformní varianta

### Android

První PoC použije oficiální NetBird aplikaci připojenou k NetBird Cloud.
Mobilní aplikace Turris Federation nebude v první etapě implementovat
vlastní VPN ani vkládat NetBird engine. Bude samostatným klientem pro:

- přijetí uživatelského členství ve federaci;
- zobrazení stavu připojení, povolených lokalit, hostů a Zlatých stránek;
- bezpečné otevření validovaného HTTP(S) endpointu v systémovém prohlížeči;
- lokální diagnostiku bez administrátorských operací.

Android dovoluje jen jedno aktivní VPN rozhraní. Mobilní uzel proto nebude
současně používat ZeroTier, vlastní `tf_wg` a NetBird. V paralelní migrační fázi
se NetBird zapne pouze vybraným mobilním testovacím uzlům a jejich původní VPN
se předtím vypne. Ostatní uzly mohou dočasně zůstat na dosavadním transportu,
ale žádná datová cesta nesmí skládat nebo současně směrovat více VPN vrstev.

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
- obdrží routy federovaných LAN určené jeho členství;
- nemá SSH údaje, deploy, audit, root identitu ani administrační API.

Každý router je autoritativní pro vlastní stabilní doménu z podepsané topologie,
například `cacke.internal`. Z lokálních Zlatých stránek sám vytváří a odstraňuje
přesné DNS záznamy; nemá proto NetBird API token ani oprávnění měnit zóny jiných
routerů. NetBird pouze jednorázově deleguje odpovídající doménový resource na
správný routing peer. Zápis `*.cacke.internal` označuje delegovaný jmenný prostor,
nikoli univerzální DNS odpověď pro neexistující služby. Překlad jména sám o sobě
nemění síťovou dosažitelnost.

Každý federovaný router poskytuje svou zónu klientům vlastní LAN a ostatním
routerům přes NetBird. Ostatní routery zónu podmíněně forwardují, takže
`neurodiary.cacke.internal` funguje stejně v NetBird síti i ve všech přijatých
LAN bez kopírování jednotlivých záznamů do centrálního DNS.

Pro nové nasazení se použije NetBird **Networks** a jejich povinné resource
groups/policies, nikoli staré Network Routes bez ACL. Turris router je routing
peer své lokality. Přístup ke službě běžící přímo na routeru a přístup do jeho
LAN jsou dvě samostatná pravidla, protože používají odlišnou vstupní a forward
cestu firewallu.

## Etapy

1. Dokončit fyzickou akceptaci současné federace a zachovat ji jako rollback
   baseline.
2. Založit oddělený PoC v NetBird Cloud a připojit jeden Turris jako testovací
   routing peer bez změny produkční topologie. Před přidáním uživatelského
   klienta odstranit výchozí full-mesh policy a nahradit ji explicitními
   skupinami a pravidly. Podrobný postup: [NetBird Cloud PoC](netbird-cloud-poc.md).
3. Připojit běžnou oficiální Android aplikaci, ověřit celý publikovaný LAN prefix
   a stejné DNS jméno z NetBird klienta i jiné federované LAN.
4. Navrhnout transportní backend Federation a převod členství, lokalit a
   oprávnění na NetBird peer groups, Networks/resources a policies.
5. Implementovat read-only mobilní klient Federation pro Android; následně
   ověřit Linux ARM64 telefon s CLI/daemonem.
6. Ověřit řízené přepnutí a návrat mezi původním transportem a NetBirdem bez
   jejich vrstvení, potom samostatně rozhodnout o self-hosted control plane a
   postupně převést routery a notebooky. Každý převedený uzel používá jen
   NetBird; úplné odstranění rollback konfigurace je možné až po samostatném
   schválení.

## Akceptace mobilního řezu

- Android i zvolený Linux ARM64 telefon přežijí změnu Wi-Fi/mobilních dat,
  uspání a restart a obnoví připojení bez nové dlouhodobé pozvánky.
- Telefon vidí federované LAN určené jeho členství; Zlaté stránky tento provoz
  dále nefiltrují podle služeb nebo portů.
- Privátní DNS jméno obslouží autoritativní router pouze pro platnou položku jeho
  Zlatých stránek a stejné jméno funguje přes NetBird i ve všech federovaných LAN.
- Zlaté stránky zobrazují pouze podepsaný katalog a HTTP(S) otevírají v
  systémovém prohlížeči; TCP endpoint pouze kopírují.
- Telefon neinzeruje vlastní síť a nemůže se stát routing peerem ani správcem.
- Odvolání zařízení ukončí jeho přístup i po opětovném připojení k internetu.
- Výpadek control plane neukončí již navázaný přímý provoz, pokud to dovolují
  vlastnosti ověřené verze NetBird; použití relay je v diagnostice viditelné.
- Logy ani exporty neobsahují setup key, PAT, privátní klíč nebo přístupový
  token.

## Otevřená rozhodnutí

- podmínky a postup případného přechodu z NetBird Cloud na self-hosted control
  plane včetně obnovy přístupu při selhání migrace;
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
