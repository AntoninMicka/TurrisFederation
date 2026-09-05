import { invoke } from "@tauri-apps/api/core";
import type { AuditFinding, FederationNode, HostIdentity, SshCredentials, ZeroTierSettings, ZeroTierStatus } from "./domain";

const browserMode = !("__TAURI_INTERNALS__" in window);

export async function listNodes(): Promise<FederationNode[]> {
  return browserMode ? [] : invoke("list_nodes");
}

export async function saveNode(node: FederationNode): Promise<FederationNode> {
  if (browserMode) return node;
  return invoke("save_node", { node });
}

export async function inspectConnection(nodeId: string): Promise<HostIdentity> {
  if (browserMode) throw new Error("SSH připojení je dostupné v desktopové aplikaci.");
  return invoke("inspect_connection", { nodeId });
}

export async function connectNode(nodeId: string, credentials: SshCredentials): Promise<FederationNode> {
  if (browserMode) throw new Error("SSH připojení je dostupné v desktopové aplikaci.");
  return invoke("connect_node", { nodeId, credentials });
}

export async function auditNode(nodeId: string, credentials: SshCredentials): Promise<AuditFinding[]> {
  if (browserMode) throw new Error("Audit skutečného routeru je dostupný v desktopové aplikaci.");
  return invoke("audit_node", { nodeId, credentials });
}

export async function getZeroTierSettings(): Promise<ZeroTierSettings> {
  return browserMode ? { networkId: null, central: "new", zeroTierSubnet: null, wireguardSubnet: null } : invoke("get_zerotier_settings");
}

export async function saveZeroTierSettings(settings: ZeroTierSettings): Promise<ZeroTierSettings> {
  if (browserMode) throw new Error("Ukládání ZeroTier nastavení je dostupné v desktopové aplikaci.");
  return invoke("save_zerotier_settings", { settings });
}

export async function exportSettings(): Promise<string> {
  if (browserMode) throw new Error("Export nastavení je dostupný v desktopové aplikaci.");
  return invoke("export_settings");
}

export async function importSettings(payload: string): Promise<void> {
  if (browserMode) throw new Error("Import nastavení je dostupný v desktopové aplikaci.");
  return invoke("import_settings", { payload });
}

export async function listZeroTierStatus(): Promise<ZeroTierStatus[]> {
  return browserMode ? [] : invoke("list_zerotier_status");
}

export async function manageZeroTier(nodeId: string, credentials: SshCredentials, networkId: string | null, configure: boolean): Promise<ZeroTierStatus> {
  if (browserMode) throw new Error("ZeroTier lze spravovat v desktopové aplikaci.");
  return invoke("manage_zerotier", { nodeId, credentials, networkId, configure });
}

export async function openZeroTierCentral(): Promise<string> {
  if (browserMode) throw new Error("Otevření ZeroTier Central použijte v desktopové aplikaci.");
  return invoke("open_zerotier_central");
}

export async function deploymentAction<T>(action: "overview" | "validate" | "deploy" | "publish", nodeId: string | null = null, credentials: SshCredentials | null = null, planId: string | null = null): Promise<T> {
  if (browserMode) throw new Error("Deploy a synchronizace jsou dostupné v desktopové aplikaci.");
  return invoke("deployment_action", { action, nodeId, credentials, planId });
}

export async function checkNotebookZeroTier(): Promise<ZeroTierStatus> {
  if (browserMode) throw new Error("Kontrola notebooku je dostupná v desktopové aplikaci.");
  return invoke("check_notebook_zerotier");
}
