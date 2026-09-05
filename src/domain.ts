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
