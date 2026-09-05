import { invoke } from "@tauri-apps/api/core";
import type { AuditFinding, FederationNode } from "./domain";

const browserMode = !("__TAURI_INTERNALS__" in window);

export async function listNodes(): Promise<FederationNode[]> {
  return browserMode ? [] : invoke("list_nodes");
}

export async function saveNode(node: FederationNode): Promise<FederationNode> {
  if (browserMode) return node;
  return invoke("save_node", { node });
}

export async function auditNode(nodeId: string): Promise<AuditFinding[]> {
  if (browserMode) throw new Error("Audit skutečného routeru je dostupný v desktopové aplikaci.");
  return invoke("audit_node", { nodeId });
}

