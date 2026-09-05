# Turris Federation

Desktopový orchestrátor a routerový agent pro bezpečnou správu federace Turris Omnia.

Spuštění na Ubuntu/Debianu:

```bash
./run.sh
```

Skript zkontroluje systémové knihovny a nástroje, chybějící balíčky
nainstaluje přes `sudo apt-get` a chybějící Rust přes oficiální `rustup`
do uživatelského účtu. Potom doplní npm závislosti a spustí desktopovou
aplikaci. Skript spouštěj bez `sudo`; při instalaci balíčků může požádat o heslo.
Vyžaduje připojení k internetu při instalaci a prvním sestavení.
Pokud repozitář systému neposkytuje dostatečně nový Node.js (20.19+ nebo 22.12+),
skript skončí s pokyny k aktualizaci. Argumenty předává příkazu `tauri dev`.

Při detekci ovladače NVIDIA skript nastaví `WEBKIT_DISABLE_DMABUF_RENDERER=1`
kvůli známým problémům vykreslování WebKitGTK. Nastavení platí jen pro spuštěnou
aplikaci a lze ho přepsat: `WEBKIT_DISABLE_DMABUF_RENDERER=0 ./run.sh`.

Při spuštění z terminálu editoru instalovaného přes Snap wrapper odstraní
zděděné cesty dynamických knihoven a GTK/GIO modulů a obnoví systémové datové
cesty. Tím zabrání míchání knihoven Snapu se systémovým WebKitem; změna platí
jen pro proces skriptu a jeho potomky.
