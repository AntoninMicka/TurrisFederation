import { describe, expect, it } from "vitest";
import type { NotebookVpnStatus } from "./domain";
import { vpnHeadline, vpnPlanLabel } from "./vpnStatus";

function status(overrides: Partial<NotebookVpnStatus> = {}): NotebookVpnStatus {
  return { state: "installed", updateAvailable: false, profileState: "active",
    setupRequired: false, repairRequired: false, ...overrides };
}

describe("notebook VPN update state", () => {
  it("makes a synchronized but stale installed profile explicit", () => {
    const stale = status({ revision: 9, topologyRevision: 10, updateAvailable: true });

    expect(vpnHeadline(stale)).toBe("VPN profil vyžaduje aktualizaci");
    expect(vpnPlanLabel(stale, false)).toBe("Připravit aktualizaci VPN");
  });

  it("keeps a matching installed profile in the normal state", () => {
    const current = status({ revision: 10, topologyRevision: 10 });

    expect(vpnHeadline(current)).toBe("VPN profil je nainstalovaný");
    expect(vpnPlanLabel(current, false)).toBe("Zobrazit instalační plán");
  });

  it("does not mistake a stored receipt for an installed system profile", () => {
    const missing = status({ profileState: "missing", setupRequired: true, repairRequired: true });

    expect(vpnHeadline(missing)).toBe("VPN profil chybí");
    expect(vpnPlanLabel(missing, false)).toBe("Nainstalovat VPN");
  });
});
