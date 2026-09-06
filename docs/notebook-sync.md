# Discovery a synchronizace mezi notebooky

Notebooky sdílejí návrh routerů, globální nastavení ZeroTier a řídicí identitu
federace přímo přes síť. Přenos nepotřebuje centrální server. Funkce je ve
výchozím stavu vypnutá a ovládá se v záložce **Notebooky**.

## První propojení

1. Na původním notebooku ponechte stávající konfiguraci federace. Na druhém
   použijte novou instalaci bez vlastní kořenové identity federace.
2. Spusťte aplikaci na obou zařízeních. V záložce Notebooky načtěte stav,
   vyplňte název a místní IPv4 adresu z LAN nebo ze společné ZeroTier sítě.
3. Na obou zapněte discovery a synchronizaci. Vybrané adresy musí být vzájemně
   dosažitelné; potřebný je TCP/8856. Discovery používá UDP/8856 a multicast
   `239.255.88.56`, oznámení každých 30 sekund, TTL 1.
4. V přehledu porovnejte celý otisk druhého notebooku s otiskem zobrazeným
   přímo na jeho obrazovce. Potvrďte párování a právo správy **na obou stranách**.
   Samotné nalezení notebooku mu nezpřístupní žádná nastavení ani klíče.
5. Nový notebook bez vlastního návrhu a identity při dalším cyklu převezme
   konfiguraci a právo správy. Tlačítkem **Načíst sdílené nastavení** aktualizujte
   seznam routerů a formulář sítě. Rozpracovaný formulář routeru se automaticky
   nepřepisuje; před jeho uložením zohledněte příchozí změny.

Pokud síť nepřenáší multicast, otevřete **Ruční párování** a přeneste veřejné
párovací údaje na druhé zařízení, také v opačném směru. Údaje obsahují adresu,
název a veřejný certifikát; neobsahují soukromý klíč. Potvrzení otisku je i
v tomto případě nutné na obou stranách. Ruční párování nenahrazuje dosažitelnost
TCP/8856. Firewall aplikace sama nemění.

Služba běží při spuštěné aplikaci a po dalším spuštění se obnoví, pokud byla
zapnutá. Discovery běží nezávisle na čekání síťové synchronizace. Přenosy se
opakují po dokončení předchozího cyklu a 30sekundové pauze; nedostupný protějšek
proto neznamená ztrátu uložené konfigurace. Při změně místní adresy vyberte novou
adresu a restartujte službu jejím tlačítkem. Podepsaná oznámení umožní protějšku
zjistit novou adresu, pokud discovery funguje na společné síti.

## Rozsah a oprávnění

Přenášejí se:

- návrhy routerů včetně SSH adres, portů, uživatelů a LAN/tunelových adres;
- globální síťová nastavení;
- kořenový soukromý klíč federace, seznam přijatých členů a podepsaná revize;
- informace potřebné k rozlišení souběžných změn a pokračování číslování revizí.

Každý notebook si ponechává vlastní párovací certifikát a jeho soukromý klíč.
SSH hesla, potvrzené SSH host keys, audity, provozní hlášení a seznam důvěryhodných
notebooků se nepřenášejí. Přijetí nového člena do skupiny notebooků je tedy nutné
potvrdit u každého požadovaného přímého protějšku. Notebooky nevstupují mezi
WireGuard routerové peery.

Kořenový klíč poskytuje plné právo podepisovat a publikovat nastavení na routery.
**Odpojení synchronizace neodvolá kopii tohoto klíče**, kterou již notebook získal.
Odvolání jeho řídicího oprávnění vyžaduje samostatnou rotaci kotvy důvěry, kterou
tato funkce neimplementuje. Notebook s jiným existujícím kořenovým klíčem nebude
automaticky přepárován ani při volbě příchozí konfigurace.

Přenos používá TLS s certifikáty na obou stranách a výslovně potvrzenými otisky.
Soukromé klíče nejsou součástí discovery ani odpovědí pro UI. Lokálně se ukládají
v adresáři dat aplikace se soubory režimu 0600, stejně jako dosavadní řídicí klíč;
nejde o šifrovanou zálohu na disku. Párovací certifikát má platnost deset let,
automatická rotace této identity zatím není implementovaná.

## Souběžné změny

Každý notebook vede čítač svých změn. Příchozí dokument převezme automaticky,
pokud navazuje na celý známý stav. Při souběžných úpravách zobrazí konflikt a
ponechá místní konfiguraci. Porovnejte oba návrhy v detailu a vyberte místní
nebo příchozí verzi; potvrzení se zneplatní, jestliže mezitím přibude další změna.

První verze řeší konflikt celého návrhu, neslučuje automaticky jednotlivá pole.
Příchozí dokument nesmí odstranit lokální routery, aby nezanikla jejich místní
historie. Pokud některé chybějí, nejdřív slučte návrhy běžným importem/exportem.
Pokud obě větve publikovaly různé podepsané revize, řešení konfliktu vynutí při
příštím publikování vyšší číslo než obě větve. Po vyřešení použijte běžnou akci
**Podepsat a synchronizovat opravy**. Samotný notebookový sync nespouští deploy
ani publikování do routerů. Současné offline publikování ze dvou notebooků může
na routerech narazit na konflikt stejné revize; nejde o distribuovaný konsenzus.

Databáze a soubory federace se mění pod společným zámkem s controllerem. Před
zápisem vzniká záznam obnovy. Po přerušení se přenos dokončí při dalším načtení
stavu nebo spuštění synchronizace; do té doby controller odmítne deploy.
Pokud po přerušení vznikly další místní úpravy mimo dokončený přenos, obnova
zápis zastaví, aby je neztratila. Takový stav vyžaduje individuální obnovu dat.

## Ověření a omezení

Automatické testy používají dvě samostatné služby, dočasné databáze a skutečné
TLS spojení přes loopback. Ověřují přenos identity, oběma směry provedené úpravy,
odmítnutí nespárovaného klienta, konflikty, restart obnovy a zachování auditů a
SSH důvěry. Síťové objevování a provoz přes skutečnou LAN/ZeroTier je potřeba
ověřit na dvou noteboocích. Podporováno je nejvýše 32 přímo spárovaných notebooků.

Tato změna zavádí discovery notebooků; roadmapová oznámení routerů každých
30 minut zůstávají samostatným otevřeným úkolem.
