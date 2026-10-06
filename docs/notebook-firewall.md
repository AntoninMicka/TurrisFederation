# Firewall při přidávání notebooku

Automatické přijetí uživatelského notebooku ve stejné fyzické LAN používá dva
oddělené transporty:

- oba notebooky přijímají multicast `239.255.88.56` přes UDP/8857;
- cílový notebook otevírá TCP/8857 směrem k administrátorskému notebooku a
  vyzvedává si podepsané zprávy.

Administrátorský notebook proto musí přijmout TCP/8857 z důvěryhodné místní
LAN. Oba notebooky musí přijmout UDP/8857 z této LAN. Cílový notebook
nepotřebuje kvůli běžnému toku obecně povolit příchozí TCP/8857.

V aplikaci lze pro registrační discovery zaškrtnout jedno nebo více aktivních
fyzických IPv4 rozhraní. Multicastové členství i odchozí beacon se zakládají
zvlášť pro každé z nich; loopback, ZeroTier, WireGuard, tunely a běžná
kontejnerová rozhraní se do nabídky nezařazují. TCP/8857 zůstává dostupné pro
přímý přenos, ale registrační požadavky přijímá jen ze subnetů vybraných
rozhraní.

Po přijetí uživatelský notebook každých 30 sekund otevírá stejné odchozí
TCP/8857 spojení na podepsanou ZeroTier adresu administrátora. Posílá jím svůj
podepsaný report verze a přijímá kořenově podepsaný read-only přehled verzí,
hostů a služeb. Administrátorský notebook proto musí TCP/8857 přijmout také z
podepsané ZeroTier adresy uživatele (nebo z přesně vymezeného federovaného
ZeroTier subnetu). Uživatelský notebook ani pro tento tok příchozí TCP pravidlo
nepotřebuje.

## Důležitý diagnostický rozdíl

Příkaz

```bash
nc -vz ADRESA_ADMINA 8857
```

ověřuje pouze TCP. Výsledek `open` nepotvrzuje průchod UDP ani multicastu. DNS
hláška `inverse host lookup failed` sama o sobě konektivitu neblokuje; znamená
jen, že adresa nemá zpětný DNS záznam.

Pokud připojování zůstává ve fázi `requesting`, ale TCP test je úspěšný,
zkontrolujte zejména příchozí UDP/8857 na cílovém notebooku. Ověřte také, že
oba backendy běží a naslouchají:

```bash
ss -lntup | grep ':8857'
systemctl --user status turris-federation-backend.service
```

## Debian a firewalld

Nepřítomnost UFW neznamená, že host nemá aktivní firewall. Debian může používat
`firewalld` nad nftables. Nejprve zjistěte aktivní zónu a její pravidla:

```bash
sudo firewall-cmd --state
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=home --list-all
sudo firewall-cmd --zone=home --list-rich-rules
```

`home` nahraďte skutečně aktivní zónou. Následující příklad omezuje UDP/8857 na
důvěryhodnou LAN `192.168.100.0/24`; subnet vždy nahraďte vlastní sítí:

```bash
sudo firewall-cmd --zone=home --add-rich-rule='rule family="ipv4" source address="192.168.100.0/24" port port="8857" protocol="udp" accept'
sudo firewall-cmd --zone=home --permanent --add-rich-rule='rule family="ipv4" source address="192.168.100.0/24" port port="8857" protocol="udp" accept'
```

Na administrátorském notebooku povolte ze stejného LAN subnetu také TCP/8857:

```bash
sudo firewall-cmd --zone=home --add-rich-rule='rule family="ipv4" source address="192.168.100.0/24" port port="8857" protocol="tcp" accept'
sudo firewall-cmd --zone=home --permanent --add-rich-rule='rule family="ipv4" source address="192.168.100.0/24" port port="8857" protocol="tcp" accept'
```

Po přijetí přidejte na administrátorském notebooku stejně omezené pravidlo pro
konkrétní podepsanou ZeroTier adresu uživatele. Zónu zvolte podle výstupu
`--get-active-zones` pro rozhraní `zt…`; zde je pouze příklad pro adresu
`10.43.192.59`:

```bash
sudo firewall-cmd --zone=home --add-rich-rule='rule family="ipv4" source address="10.43.192.59/32" port port="8857" protocol="tcp" accept'
sudo firewall-cmd --zone=home --permanent --add-rich-rule='rule family="ipv4" source address="10.43.192.59/32" port port="8857" protocol="tcp" accept'
```

První příkaz v každé dvojici mění běžící konfiguraci, druhý její trvalou kopii.
Není proto nutné dělat okamžitý `--reload`, který by mohl ovlivnit jiná aktivní
spojení. Po dokončení lze pravidla ověřit opakovaným `--list-rich-rules`.

## UFW a přímé nftables

Pokud běží UFW, ověřte ho pomocí `sudo ufw status verbose` a povolte stejné
protokoly pouze z místního subnetu. Pokud neběží ani UFW, ani firewalld,
zkontrolujte skutečná pravidla pomocí `sudo nft list ruleset`; samotná
nepřítomnost obou frontendů nevylučuje ručně spravovaná nftables pravidla.

Turris Federation tato hostitelská pravidla automaticky nevytváří ani nemaže.
Volba správné zóny a důvěryhodného LAN nebo ZeroTier zdroje zůstává explicitním
rozhodnutím správce. Pokud síť multicast nepřenáší ani po opravě lokálního firewallu,
použijte v UI nouzový ruční přenos podepsaných balíčků.
