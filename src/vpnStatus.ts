import type { NotebookVpnStatus } from "./domain";

export function vpnHeadline(status: NotebookVpnStatus | null): string {
  if (status?.state === "installed" && status.updateAvailable) return "VPN profil vyžaduje aktualizaci";
  if (status?.state === "installed") return "VPN profil je nainstalovaný";
  if (status?.state === "rolled_back") return "Předchozí profil byl obnoven";
  if (status?.state === "revoked") return "Členství bylo odvoláno a spravovaná VPN odstraněna";
  if (status?.state === "error") return "Poslední instalace selhala";
  return "VPN profil zatím není nainstalovaný";
}

export function vpnPlanLabel(status: NotebookVpnStatus | null, busy: boolean): string {
  if (busy) return "Pracuji…";
  return status?.updateAvailable ? "Připravit aktualizaci VPN" : "Zobrazit instalační plán";
}
