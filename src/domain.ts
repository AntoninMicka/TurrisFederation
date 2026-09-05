export type NodeStatus = "draft" | "observed" | "drifted" | "healthy" | "unreachable";

export interface FederationNode {
  id: string;
  name: string;
  sshHost: string;
  sshPort: number;
  sshUser: string;
  lanCidrs: string[];
  zeroTierAddress?: string;
  publicEndpoint?: string;
  wireguardAddress?: string;
  status: NodeStatus;
  lastAuditAt?: string;
}

export interface AuditFinding {
  id: string;
  nodeId: string;
  severity: "info" | "warning" | "error";
  component: "system" | "zerotier" | "wireguard" | "routes" | "firewall";
  summary: string;
  remediation?: string;
  expectedState: string;
  observedState: string;
  observedAt: string;
}

export interface HostIdentity {
  hostKey: string;
  fingerprints: string;
  trust: "new" | "trusted" | "changed";
}

export interface SshCredentials {
  password: string;
  hostKey: string;
  trustHostKey: boolean;
}

export interface ZeroTierSettings {
  networkId: string | null;
  central: "new" | "legacy";
  zeroTierSubnet: string | null;
  wireguardSubnet: string | null;
}

export interface ZeroTierStatus {
  routerId: string;
  networkId: string | null;
  installed: boolean;
  deviceId: string | null;
  version: string | null;
  online: boolean | null;
  networkStatus: string | null;
  networkName: string | null;
  assignedAddresses: string[];
  device: string | null;
  serviceEnabled: boolean | null;
  persistent: boolean;
  state: string;
  summary: string;
  details: string;
  checkedAt: string;
}

export interface DeploymentReport {
  enrolled: boolean;
  state?: "pending" | "error" | "confirming" | "waiting_peers" | "active" | "rollback" | "revoked";
  receivedRevision?: number;
  appliedRevision?: number;
  pendingPeers?: string[];
  error?: string;
  reachable?: boolean;
  checkedAt?: number;
}
export interface DeploymentOverview {
  revision: number;
  unpublishedChanges: boolean;
  fingerprint: string | null;
  nodes: Record<string, DeploymentReport>;
}
export interface DeploymentPlan {
  id: string;
  nodeId: string;
  expiresAt: number;
  steps: string[];
  config: { networkId: string; nodes: { id: string; name: string; lanCidrs: string[]; zeroTierAddress: string | null; wireguardAddress: string | null }[] };
}
