import { invoke } from "@tauri-apps/api/core";
import type { AuditFinding, FederationNode, HostIdentity, SshCredentials } from "./domain";

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
