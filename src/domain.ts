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

export interface ZeroTierSettings {
  networkId: string | null;
  central: "new" | "legacy";
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
