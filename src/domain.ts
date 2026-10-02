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
  wireguardInterfaceBlocked: boolean | null;
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
  hosts?: { address: string; name: string | null }[];
  hostsObservedAt?: number;
}
export interface DeploymentOverview {
  revision: number;
  unpublishedChanges: boolean;
  fingerprint: string | null;
  nodes: Record<string, DeploymentReport>;
}
export interface DiagnosticMeasurement {
  address: string;
  samples: boolean[];
  checkedAt: number;
  successPercent: number | null;
}
export interface NotebookDiagnostics {
  revision: number;
  state: "idle" | "complete";
  nodes: Record<string, { zerotier?: DiagnosticMeasurement }>;
}
export interface ReadOnlyNode {
  id: string;
  name: string;
  lanCidrs: string[];
  zeroTierAddress: string | null;
  wireguardAddress: string | null;
  enrolled: boolean;
  state?: DeploymentReport["state"];
  reachable?: boolean;
  checkedAt?: number;
  hosts: { address: string; name: string | null }[];
  hostsObservedAt?: number;
}
export interface ReadOnlyNotebook {
  id: string;
  name: string;
  role: "administrator" | "user";
  zeroTierAddress: string | null;
  wireguardAddress: string | null;
}
export interface ServiceDirectoryEntry {
  id: string;
  name: string;
  hostAddress: string;
  hostName: string | null;
  protocol: "tcp" | "http" | "https";
  port: number;
  path: string | null;
  endpoint: string;
  routerId: string;
  routerName: string;
  observedAt: number;
  stale: boolean;
  routeAdvertised: boolean;
}
export interface ReadOnlyOverview {
  revision: number;
  networkId: string;
  nodes: ReadOnlyNode[];
  notebooks: ReadOnlyNotebook[];
  services: ServiceDirectoryEntry[];
  diagnostics: NotebookDiagnostics;
}
export interface NotebookVpnPlan {
  id: string;
  expiresAt: number;
  revision: number;
  connectionName: string;
  interfaceName: string;
  address: string;
  zeroTierAddress: string;
  underlayDevice: string;
  routes: string[];
  currentConnection: boolean;
  forwarding: { ipv4: boolean | null; ipv6: boolean | null };
  steps: string[];
}
export interface NotebookVpnDiagnosticNode {
  name: string;
  address: string;
  handshakeState: "recent" | "stale" | "never" | "unknown";
  handshakeAt: number | null;
  wireguard: DiagnosticMeasurement;
}
export interface NotebookVpnDiagnostics {
  revision: number;
  state: "complete";
  checkedAt: number;
  profile: "active" | "inactive" | "missing" | "unknown";
  interfacePresent: boolean | null;
  addressAssigned: boolean | null;
  routesExpected: number;
  routesActive: number;
  missingRoutes: string[];
  unknownRoutes: string[];
  forwarding: { ipv4: boolean | null; ipv6: boolean | null };
  nodes: Record<string, NotebookVpnDiagnosticNode>;
}
export interface NotebookVpnStatus {
  state: "unconfigured" | "ready" | "installed" | "rolled_back" | "revoked" | "error";
  revision?: number;
  installedAt?: number;
  rolledBackAt?: number;
  address?: string;
  routes?: string[];
  forwarding?: { ipv4: boolean | null; ipv6: boolean | null };
  error?: string;
  rollbackComplete?: boolean;
  diagnostics?: NotebookVpnDiagnostics;
}
export interface TopologyRefreshPlan {
  id: string;
  expiresAt: number;
  kind: "update" | "revoked";
  currentRevision: number;
  revision: number;
  routes: string[];
  addedRoutes: string[];
  removedRoutes: string[];
  currentConnection: boolean;
  connectionName?: string;
  interfaceName?: string;
  address?: string;
  zeroTierAddress?: string;
  underlayDevice?: string;
  forwarding?: { ipv4: boolean | null; ipv6: boolean | null };
  steps: string[];
}
export type DeploymentMode = "full" | "settings";
export interface DeploymentPlan {
  operation: "install" | "update";
  lan: { host: string; device: string; source: string };
  artifactHash: string;
  installedArtifactHash: string | null;
  versionMismatch: boolean;
  availableModes: DeploymentMode[];
  recommendedMode: DeploymentMode;
  stepsByMode: Record<DeploymentMode, string[]>;
  id: string;
  nodeId: string;
  expiresAt: number;
  steps: string[];
  config: { networkId: string; nodes: { id: string; name: string; lanCidrs: string[]; zeroTierAddress: string | null; wireguardAddress: string | null }[] };
}
