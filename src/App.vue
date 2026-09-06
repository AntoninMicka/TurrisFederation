<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, reactive, ref } from "vue";
import { notebookAction, checkNotebookZeroTier, auditNode, connectNode, inspectConnection, listNodes, saveNode, getZeroTierSettings, saveZeroTierSettings, listZeroTierStatus, manageZeroTier, openZeroTierCentral, exportSettings, importSettings, deploymentAction } from "./backend";
import type { NotebookSyncStatus, NotebookPeer } from "./backend";
import type { AuditFinding, FederationNode, HostIdentity, ZeroTierSettings, ZeroTierStatus, DeploymentOverview, DeploymentPlan } from "./domain";

const tabs = [
  { id: 'routers', label: 'Routery' },
  { id: 'notebooks', label: 'Notebooky' },
  { id: 'network', label: 'Síť' },
  { id: 'sync', label: 'Synchronizace' },
  { id: 'audits', label: 'Audity' },
  { id: 'settings', label: 'Nastavení' },
] as const;
type TabId = typeof tabs[number]['id'];
const activeTab = ref<TabId>('routers');

function navigateTabs(event: KeyboardEvent, index: number) {
  let target = index;
  if (event.key === 'ArrowRight') target = (index + 1) % tabs.length;
  else if (event.key === 'ArrowLeft') target = (index + tabs.length - 1) % tabs.length;
  else if (event.key === 'Home') target = 0;
  else if (event.key === 'End') target = tabs.length - 1;
  else return;
  event.preventDefault();
  activeTab.value = tabs[target].id;
  document.getElementById(`tab-${activeTab.value}`)?.focus();
}

const notebookSync = ref<NotebookSyncStatus | null>(null);
const syncBusy = ref(false);
const syncError = ref("");
const syncDraft = reactive({ name: "", address: "" });
const manualInvitation = ref("");
const verifiedPeers = reactive<Record<string, boolean>>({});
const sharedSettingsChanged = ref(false);
const notebookLabels: Record<string, string> = { synced: "Synchronizováno", local_newer: "Místní změny čekají na převzetí", conflict: "Konflikt změn", error: "Přenos se nezdařil" };
let notebookPoll: ReturnType<typeof setInterval> | undefined;

async function notebookOperation(request: Record<string, unknown> = { action: "status" }) {
  if (syncBusy.value) return;
  syncBusy.value = true;
  syncError.value = "";
  try {
    const result = await notebookAction(request);
    if (notebookSync.value && notebookSync.value.configurationVersion !== result.configurationVersion) sharedSettingsChanged.value = true;
    if (!notebookSync.value) Object.assign(syncDraft, { name: result.name, address: result.config.address ?? "" });
    notebookSync.value = result;
    if (request.action === "manual") manualInvitation.value = "";
  } catch (error) { syncError.value = String(error); }
  finally { syncBusy.value = false; }
}

async function resolveNotebook(peer: NotebookPeer, choice: "local" | "remote") {
  if (!window.confirm(choice === "local"
    ? "Použít místní konfiguraci jako společné řešení konfliktu? Protější notebook ji při synchronizaci převezme."
    : "Převzít konfiguraci druhého notebooku? Místní návrh bude nahrazen; místní SSH důvěra a audity zůstanou zachované.")) return;
  await notebookOperation({ action: "resolve", peer: peer.id, choice, token: peer.conflictToken });
}

async function loadSharedSettings() {
  try {
    await reloadSettings();
    plans.value = {};
    sharedSettingsChanged.value = false;
  } catch (error) { syncError.value = String(error); }
}

onMounted(() => {
  if ("__TAURI_INTERNALS__" in window) void notebookOperation();
  notebookPoll = setInterval(() => {
    if ((activeTab.value === "notebooks" || notebookSync.value?.config.enabled) && !syncBusy.value) void notebookOperation();
  }, 5000);
});
onUnmounted(() => { if (notebookPoll) clearInterval(notebookPoll); });

const notebookStatus = ref<ZeroTierStatus | null>(null);
const notebookChecking = ref(false);
const notebookError = ref("");
async function checkNotebook() {
  notebookChecking.value = true;
  notebookError.value = "";
  try { notebookStatus.value = await checkNotebookZeroTier(); }
  catch (error) { notebookStatus.value = null; notebookError.value = String(error); }
  finally { notebookChecking.value = false; }
}

const nodes = ref<FederationNode[]>([]);
const findings = ref<AuditFinding[]>([]);
const auditedNodeName = ref("");
const busyNodeId = ref("");
const message = ref("");
const connectionNode = ref<FederationNode | null>(null);
type ConnectionAction = "connect" | "audit" | "zerotier-check" | "zerotier-setup" | "validate" | "deploy";
const connectionAction = ref<ConnectionAction>("connect");
const actionLabels: Record<ConnectionAction, string> = {
  validate: "Validovat stanoviště", deploy: "Potvrdit a nasadit",
  connect: "Ověřit připojení", audit: "Připojit a auditovat", "zerotier-check": "Zkontrolovat ZeroTier", "zerotier-setup": "Provést nastavení ZeroTier",
};
const ztSettings = ref<ZeroTierSettings>({ networkId: null, central: "new", zeroTierSubnet: null, wireguardSubnet: null });
const ztDraft = reactive({ networkId: "", central: "new" as ZeroTierSettings["central"], zeroTierSubnet: "", wireguardSubnet: "" });
const ztStatuses = ref<Record<string, ZeroTierStatus>>({});
const ztSaving = ref(false);
const ztNetworkForOperation = ref<string | null>(null);
const openCentralAfterSetup = ref(true);
const browserOpening = ref(false);
const identity = ref<HostIdentity | null>(null);
const password = ref("");
const trustHostKey = ref(false);
const connectionError = ref("");
const inspecting = ref(false);
const submitting = ref(false);
const settingsFileInput = ref<HTMLInputElement | null>(null);
const saving = ref(false);
const editing = ref(false);
const deployment = ref<DeploymentOverview | null>(null);
const plans = ref<Record<string, DeploymentPlan>>({});
const deployConfirmed = ref(false);
const publishing = ref(false);
const deploymentError = ref("");
const deploymentLabels: Record<string, string> = { pending: "Přijato · čeká na aplikování", error: "Kontrola nebo aplikování selhalo", confirming: "Čeká na potvrzení", waiting_peers: "Nasazeno · čeká na protějšky", active: "Spojení ověřeno", rollback: "Obnovena záloha", revoked: "Členství odvoláno" };

async function refreshDeployment() {
  if (!ztSettings.value.networkId) { deployment.value = null; return; }
  try {
    deployment.value = await deploymentAction<DeploymentOverview>("overview");
    deploymentError.value = "";
  } catch (error) { deploymentError.value = String(error); }
}

async function publishChanges() {
  publishing.value = true;
  try {
    deployment.value = await deploymentAction<DeploymentOverview>("publish");
    message.value = "Revize je podepsaná a uložená v notebooku. U nedostupných uzlů zůstává čekající; výsledek aplikování sledujte u stanoviště.";
    deploymentError.value = "";
  } catch (error) { deploymentError.value = String(error); }
  finally { publishing.value = false; }
}

async function editNode(node: FederationNode) {
  activeTab.value = "routers";
  Object.assign(draft, { ...node, lanCidrs: [...node.lanCidrs] });
  lanCidrsText.value = node.lanCidrs.join(", ");
  editing.value = true;
  await nextTick();
  document.getElementById("draft-form")?.scrollIntoView({ behavior: "smooth" });
}

function resetDraft() {
  Object.assign(draft, { id: crypto.randomUUID(), name: "", sshHost: "", sshPort: 22, sshUser: "root", lanCidrs: [], status: "draft", zeroTierAddress: "", wireguardAddress: "", publicEndpoint: "", lastAuditAt: undefined });
  lanCidrsText.value = "";
  editing.value = false;
}

const statusLabels: Record<FederationNode["status"], string> = {
  draft: "Draft", observed: "SSH ověřeno", healthy: "V pořádku", drifted: "Odchylky", unreachable: "Připojení selhalo",
};
const draft = reactive<FederationNode>({
  id: crypto.randomUUID(), name: "", sshHost: "", sshPort: 22, sshUser: "root", lanCidrs: [], status: "draft",
});
const lanCidrsText = ref("");

onMounted(async () => {
  try {
    nodes.value = await listNodes();
    ztSettings.value = await getZeroTierSettings();
    Object.assign(ztDraft, {
      networkId: ztSettings.value.networkId ?? "",
      central: ztSettings.value.central,
      zeroTierSubnet: ztSettings.value.zeroTierSubnet ?? "",
      wireguardSubnet: ztSettings.value.wireguardSubnet ?? "",
    });
    await refreshZeroTierStatus();
    await refreshDeployment();
  }
  catch (error) { message.value = String(error); }
});

async function proposeAllAddresses() {
  if (!ztDraft.wireguardSubnet) ztDraft.wireguardSubnet = "10.203.0.0/24";
  if (!ztDraft.zeroTierSubnet) ztDraft.zeroTierSubnet = "10.147.17.0/24";
  
  const wgPrefix = ztDraft.wireguardSubnet.split(".").slice(0, 3).join(".");
  const usedOctets = new Set(nodes.value.map(n => n.wireguardAddress?.split(".").pop()).filter(Boolean).map(Number));
  let nextOctet = 1;

  for (const node of nodes.value) {
    // Try to get ZT address from status if missing
    if (!node.zeroTierAddress && ztStatuses.value[node.id]?.assignedAddresses.length) {
      node.zeroTierAddress = ztStatuses.value[node.id].assignedAddresses[0].split("/")[0];
    }

    if (!node.wireguardAddress) {
      if (node.zeroTierAddress) {
        const lastOctet = parseInt(node.zeroTierAddress.split(".").pop() || "0");
        if (lastOctet > 0 && lastOctet < 255) {
          node.wireguardAddress = `${wgPrefix}.${lastOctet}`;
        }
          }
      
      if (!node.wireguardAddress) {
        while (usedOctets.has(nextOctet)) nextOctet++;
        if (nextOctet < 255) {
          node.wireguardAddress = `${wgPrefix}.${nextOctet}`;
          usedOctets.add(nextOctet);
        }
      }
    }
    await saveNode(node);
  }
  nodes.value = await listNodes();
  message.value = "Adresy tunelů byly doplněny podle dostupných dat a zvoleného subnetu.";
}

function suggestDraftWireguard() {
  const subnet = ztDraft.wireguardSubnet || "10.203.0.0/24";
  const wgPrefix = subnet.split(".").slice(0, 3).join(".");
  
  if (draft.zeroTierAddress) {
    const lastOctet = draft.zeroTierAddress.split(".").pop();
    if (lastOctet) {
      draft.wireguardAddress = `${wgPrefix}.${lastOctet}`;
      return;
    }
  }

  const usedOctets = new Set(nodes.value.map(n => n.wireguardAddress?.split(".").pop()).filter(Boolean).map(Number));
  let nextOctet = 1;
  while (usedOctets.has(nextOctet)) nextOctet++;
  if (nextOctet < 255) {
    draft.wireguardAddress = `${wgPrefix}.${nextOctet}`;
  }
}

async function refreshZeroTierStatus() {
  const statuses = await listZeroTierStatus();
  ztStatuses.value = Object.fromEntries(statuses.map(status => [status.routerId, status]));
}

async function reloadSettings() {
  nodes.value = await listNodes();
  ztSettings.value = await getZeroTierSettings();
  Object.assign(ztDraft, {
    networkId: ztSettings.value.networkId ?? "",
    central: ztSettings.value.central,
    zeroTierSubnet: ztSettings.value.zeroTierSubnet ?? "",
    wireguardSubnet: ztSettings.value.wireguardSubnet ?? "",
  });
  await refreshZeroTierStatus();
  await refreshDeployment();
}

async function doExportSettings() {
  try {
    const payload = await exportSettings();
    const blob = new Blob([payload], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `turris-federation-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    message.value = "Nastavení federace bylo exportováno.";
  } catch (error) {
    message.value = String(error);
  }
}

async function doImportSettings(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  try {
    await importSettings(await file.text());
    plans.value = {};
    await reloadSettings();
    findings.value = [];
    auditedNodeName.value = "";
    message.value = "Drafty byly sloučeny podle ID. Uložená SSH důvěra a historie zůstávají zachované; změny vyžadují novou validaci.";
  } catch (error) {
    message.value = String(error);
  }
}

function suggestSubnets() {
  const used = new Set<string>();
  nodes.value.forEach(n => n.lanCidrs.forEach(cidr => used.add(cidr.split(".")[0] + "." + cidr.split(".")[1])));
  
  if (!ztDraft.wireguardSubnet) {
    const candidates = ["10.203.0.0/24", "10.204.0.0/24", "172.16.203.0/24", "192.168.203.0/24"];
    ztDraft.wireguardSubnet = candidates.find(c => !used.has(c.split(".").slice(0, 2).join("."))) || candidates[0];
  }
  if (!ztDraft.zeroTierSubnet) {
    const candidates = ["10.147.17.0/24", "10.147.18.0/24", "172.27.17.0/24"];
    ztDraft.zeroTierSubnet = candidates.find(c => !used.has(c.split(".").slice(0, 2).join("."))) || candidates[0];
  }
}

async function saveZeroTier() {
  ztSaving.value = true;
  try {
    ztSettings.value = await saveZeroTierSettings({
      networkId: ztDraft.networkId.trim() || null,
      central: ztDraft.central,
      zeroTierSubnet: ztDraft.zeroTierSubnet.trim() || null,
      wireguardSubnet: ztDraft.wireguardSubnet.trim() || null,
    });
    ztDraft.networkId = ztSettings.value.networkId ?? "";
    ztDraft.zeroTierSubnet = ztSettings.value.zeroTierSubnet ?? "";
    ztDraft.wireguardSubnet = ztSettings.value.wireguardSubnet ?? "";
    plans.value = {};
    await refreshDeployment();
    message.value = "Nastavení ZeroTier federace je uložené. U routeru nyní spusťte kontrolu ZeroTier.";
  } catch (error) { message.value = String(error); }
  finally { ztSaving.value = false; }
}

async function openCentral() {
  browserOpening.value = true;
  try {
    await openZeroTierCentral();
    message.value = "V ZeroTier Central vyberte uloženou síť a autorizujte zařízení podle jeho ZeroTier ID. Potom obnovte stav routeru.";
  } catch (error) { message.value = String(error); }
  finally { browserOpening.value = false; }
}

async function addDraft() {
  message.value = "";
  saving.value = true;
  try {
  draft.lanCidrs = lanCidrsText.value.split(",").map((item) => item.trim()).filter(Boolean);
  const saved = await saveNode({ ...draft, lanCidrs: [...draft.lanCidrs] });
  nodes.value = [...nodes.value.filter((node) => node.id !== saved.id), saved];
  plans.value = {};
  resetDraft();
  await refreshDeployment();
  message.value = "Draft uzlu byl uložen. Nyní se můžete připojit přes SSH.";
  } catch (error) { message.value = String(error); }
  finally { saving.value = false; }
}

async function openConnection(node: FederationNode, action: ConnectionAction) {
  connectionNode.value = node;
  connectionAction.value = action;
  deployConfirmed.value = false;
  ztNetworkForOperation.value = ztSettings.value.networkId;
  openCentralAfterSetup.value = true;
  password.value = "";
  identity.value = null;
  trustHostKey.value = false;
  await inspectHost();
}

async function inspectHost() {
  if (!connectionNode.value) return;
  inspecting.value = true;
  connectionError.value = "";
  identity.value = null;
  trustHostKey.value = false;
  try { identity.value = await inspectConnection(connectionNode.value.id); }
  catch (error) { connectionError.value = String(error); }
  finally { inspecting.value = false; }
}

function closeConnection() {
  if (inspecting.value || submitting.value) return;
  password.value = "";
  identity.value = null;
  connectionNode.value = null;
}

async function submitConnection() {
  const node = connectionNode.value;
  const host = identity.value;
  if (!node || !host || !password.value || (host.trust !== "trusted" && !trustHostKey.value)) return;
  if (connectionAction.value === "deploy" && (!deployConfirmed.value || !plans.value[node.id])) return;
  submitting.value = true;
  busyNodeId.value = node.id;
  connectionError.value = "";
  const credentials = { password: password.value, hostKey: host.hostKey, trustHostKey: trustHostKey.value };
  password.value = "";
  try {
    if (connectionAction.value === "validate") {
      plans.value[node.id] = await deploymentAction<DeploymentPlan>("validate", node.id, credentials);
      message.value = `Stanoviště ${node.name} je validované. Zkontrolujte plán a spusťte deploy do 10 minut.`;
    } else if (connectionAction.value === "deploy") {
      deployment.value = await deploymentAction<DeploymentOverview>("deploy", node.id, credentials, plans.value[node.id].id);
      plans.value = {};
      message.value = `Deploy ${node.name} dokončen. Stav spojení s protějšky je uveden u stanoviště.`;
    } else if (connectionAction.value === "audit") {
      findings.value = await auditNode(node.id, credentials);
      auditedNodeName.value = node.name;
      activeTab.value = "audits";
      message.value = findings.value.length ? `Audit ${node.name}: ${findings.value.length} položek.` : `Audit ${node.name} nezjistil odchylky.`;
    } else if (connectionAction.value === "zerotier-check" || connectionAction.value === "zerotier-setup") {
      const configure = connectionAction.value === "zerotier-setup";
      const status = await manageZeroTier(node.id, credentials, ztNetworkForOperation.value, configure);
      ztStatuses.value[node.id] = status;
      message.value = `${node.name}: ${status.summary}`;
      if (configure && openCentralAfterSetup.value && status.deviceId) await openCentral();
    } else {
      const connected = await connectNode(node.id, credentials);
      nodes.value = nodes.value.map(item => item.id === connected.id ? connected : item);
      message.value = `SSH připojení k ${node.name} bylo ověřeno. Nyní můžete spustit audit skutečného stavu.`;
    }
    connectionNode.value = null;
    identity.value = null;
  } catch (error) {
    connectionError.value = String(error);
  } finally {
    credentials.password = "";
    submitting.value = false;
    busyNodeId.value = "";
    try { nodes.value = await listNodes(); await refreshZeroTierStatus(); await refreshDeployment(); }
    catch (error) { message.value = `Nelze obnovit seznam uzlů: ${String(error)}`; }
  }
}
</script>

<template>
  <main class="shell">
    <header><p class="kicker">Turris Omnia</p><h1>Federace routerů</h1><p>Správa routerů, řídicích notebooků a společné sítě.</p></header>
    <section class="summary"><article><strong>{{ nodes.length }}</strong><span>routerů</span></article><article><strong>{{ 1 + (notebookSync?.peers.filter(peer => peer.trusted).length ?? 0) }}</strong><span>notebooků</span></article><article><strong>ZT + WG</strong><span>vrstvy spojení</span></article></section>
    <p v-if="sharedSettingsChanged && activeTab !== 'notebooks'" class="setup-preview" role="status">
      Sdílená konfigurace se změnila.
      <button class="secondary" @click="activeTab = 'notebooks'">Otevřít synchronizaci notebooků</button>
    </p>
    <nav class="tabs" role="tablist" aria-label="Správa federace">
      <button v-for="(tab, index) in tabs" :id="`tab-${tab.id}`" :key="tab.id" type="button"
        role="tab" :aria-selected="activeTab === tab.id" :aria-controls="`panel-${tab.id}`"
        :tabindex="activeTab === tab.id ? 0 : -1" :class="{ selected: activeTab === tab.id }"
        @click="activeTab = tab.id" @keydown="navigateTabs($event, index)">
        {{ tab.label }}
        <span v-if="tab.id === 'routers'" class="tab-count">{{ nodes.length }}</span>
        <span v-else-if="tab.id === 'notebooks'" class="tab-count">{{ 1 + (notebookSync?.peers.filter(peer => peer.trusted).length ?? 0) }}</span>
        <span v-else-if="tab.id === 'audits' && findings.length" class="tab-count">{{ findings.length }}</span>
      </button>
    </nav>
    <div v-show="activeTab === 'routers'" id="panel-routers" class="tab-panel" role="tabpanel" aria-labelledby="tab-routers" tabindex="0">
    <section class="panel">
      <div><p class="kicker">Inventář</p><h2>Routery federace</h2></div>

      <p v-if="!nodes.length" class="muted">Zatím nemáte žádný router. Vytvořte jeho draft ve formuláři níže.</p>
      <div class="node-grid">
        <article v-for="node in nodes" :key="node.id" class="node">
          <div class="node-heading">
          <div><span :class="['status', node.status]">{{ statusLabels[node.status] }}</span><h3>{{ node.name }}</h3><p>{{ node.sshUser }}@{{ node.sshHost }}:{{ node.sshPort }}</p><small>{{ node.lanCidrs.join(' · ') }}</small></div>
          <div class="node-actions">
            <button class="secondary" :disabled="!!connectionNode || publishing" @click="editNode(node)">Upravit draft</button>
            <button :disabled="!!busyNodeId || !!connectionNode" @click="openConnection(node, 'connect')">Připojit</button>
            <button class="secondary" :disabled="!!busyNodeId || !!connectionNode" @click="openConnection(node, 'audit')">Auditovat skutečný stav</button>
          </div>
          </div>
          <div class="zerotier-node">
            <strong>Nasazení stanoviště</strong>
            <p>{{ deployment?.nodes[node.id]?.enrolled ? 'Přijato notebookem' : 'Draft · vyžaduje přijetí z notebooku' }} · {{ deployment?.nodes[node.id]?.reachable === false ? 'Nedostupné · zobrazen poslední známý stav' : deploymentLabels[deployment?.nodes[node.id]?.state ?? ''] ?? 'Zatím nenasazeno' }}</p>
            <p>Požadovaná revize {{ deployment?.revision ?? 0 }} · přijatá {{ deployment?.nodes[node.id]?.receivedRevision ?? '—' }} · aplikovaná {{ deployment?.nodes[node.id]?.appliedRevision ?? '—' }}</p>
            <p v-if="deployment?.nodes[node.id]?.appliedRevision && deployment.nodes[node.id].appliedRevision !== deployment.revision" class="warning">Čeká na opravy z novější revize.</p>
            <p v-if="deployment?.nodes[node.id]?.error" class="error">{{ deployment.nodes[node.id].error }}</p>
            <small v-if="deployment?.nodes[node.id]?.checkedAt">Poslední výsledek: {{ new Date(deployment.nodes[node.id].checkedAt! * 1000).toLocaleString('cs-CZ') }}</small>
            <details v-if="plans[node.id]">
              <summary>Validovaný plán · platný do {{ new Date(plans[node.id].expiresAt * 1000).toLocaleTimeString('cs-CZ') }}</summary>
              <p>LAN: {{ plans[node.id].lan.source }} → {{ plans[node.id].lan.host }} ({{ plans[node.id].lan.device }})</p>
              <ol><li v-for="step in plans[node.id].steps" :key="step">{{ step }}</li></ol>
              <pre>{{ JSON.stringify(plans[node.id].config, null, 2) }}</pre>
            </details>
            <div class="node-actions">
              <button class="secondary" :disabled="!!connectionNode || publishing || !ztSettings.networkId" @click="openConnection(node, 'validate')">Validovat z notebooku</button>
              <button v-if="plans[node.id]" :disabled="!!connectionNode || publishing" @click="openConnection(node, 'deploy')">{{ plans[node.id].operation === 'update' ? 'Aktualizovat agenta přes LAN' : 'Deploy přes LAN' }}</button>
            </div>
          </div>
          <div class="zerotier-node">
            <strong>ZeroTier</strong>
            <template v-if="ztStatuses[node.id]">
              <p :class="{ error: ztStatuses[node.id].state === 'error' || ztStatuses[node.id].state === 'unknown' }">{{ ztStatuses[node.id].summary }}</p>
              <p v-if="ztStatuses[node.id].networkId !== ztSettings.networkId" class="warning">Tento výsledek patří jiné síti. Pro uložené Network ID spusťte novou kontrolu.</p>
              <dl class="zt-facts">
                <div><dt>ZeroTier ID zařízení</dt><dd><code>{{ ztStatuses[node.id].deviceId ?? 'nezjištěno' }}</code></dd></div>
                <div><dt>Network ID při kontrole</dt><dd><code>{{ ztStatuses[node.id].networkId ?? 'nevybráno' }}</code></dd></div>
                <div><dt>Služba / verze</dt><dd>{{ ztStatuses[node.id].online === null ? 'nezjištěno' : ztStatuses[node.id].online ? 'ONLINE' : 'OFFLINE' }} / {{ ztStatuses[node.id].version ?? '—' }}</dd></div>
                <div><dt>Členství v síti</dt><dd>{{ ztStatuses[node.id].networkStatus ?? 'nezjištěno nebo nepřipojeno' }}</dd></div>
                <div><dt>Přidělené adresy</dt><dd>{{ ztStatuses[node.id].assignedAddresses.join(', ') || 'zatím žádné' }}</dd></div>
                <div><dt>Po restartu routeru</dt><dd>{{ ztStatuses[node.id].persistent && ztStatuses[node.id].serviceEnabled ? 'Členství uložené, automatický start zapnutý' : 'Trvalé nastavení nepotvrzeno' }}</dd></div>
              </dl>
              <small>Načteno {{ new Date(ztStatuses[node.id].checkedAt).toLocaleString('cs-CZ') }}</small>
              <details><summary>Načtený výstup ZeroTier</summary><pre>{{ ztStatuses[node.id].details }}</pre></details>
            </template>
            <p v-else class="muted">ZeroTier zatím nebyl zkontrolován.</p>
            <div class="node-actions">
              <button class="secondary" :disabled="!!busyNodeId || !!connectionNode || ztSaving" @click="openConnection(node, 'zerotier-check')">{{ ztStatuses[node.id] ? 'Obnovit stav ZeroTier' : 'Zkontrolovat ZeroTier' }}</button>
              <button v-if="ztStatuses[node.id] && ztStatuses[node.id].networkId === ztSettings.networkId" :disabled="!ztSettings.networkId || !!busyNodeId || !!connectionNode || ztSaving" @click="openConnection(node, 'zerotier-setup')">{{ ztStatuses[node.id].installed ? 'Nastavit a připojit ZeroTier' : 'Nainstalovat a nastavit ZeroTier' }}</button>
              <button v-if="ztStatuses[node.id]?.deviceId" class="secondary" :disabled="browserOpening" @click="openCentral">Autorizovat na webu</button>
            </div>
          </div>
        </article>
      </div>
    </section>
    <section class="panel">
      <div id="draft-form"><p class="kicker">Návrh</p><h2>{{ editing ? "Upravit stanoviště" : "Nový draft stanoviště" }}</h2></div>
      <form class="form" @submit.prevent="addDraft">
        <label>Název<input v-model="draft.name" required placeholder="Praha" /></label>
        <label>SSH adresa<input v-model="draft.sshHost" placeholder="192.168.1.1" /></label>
        <label>SSH port<input v-model.number="draft.sshPort" type="number" min="1" max="65535" required /></label>
        <label>SSH uživatel<input v-model="draft.sshUser" required /></label>
        <label>LAN sítě<input v-model="lanCidrsText" placeholder="192.168.10.0/24, 10.10.0.0/16" /></label>
        <label>IPv4 adresa v ZeroTier<input v-model="draft.zeroTierAddress" placeholder="10.147.17.1" /></label>
        <label>IPv4 adresa WireGuard tunelu
          <div class="input-with-action">
            <input v-model="draft.wireguardAddress" placeholder="10.203.0.1" />
            <button type="button" class="secondary small" @click="suggestDraftWireguard">Navrhnout</button>
          </div>
        </label>
        <label>Veřejný endpoint (rezerva pro přímé spojení)<input v-model="draft.publicEndpoint" placeholder="vpn.example.cz:51820" /></label>
        <small>Draft může být neúplný. Pro deploy doplňte unikátní adresy bez prefixu; WireGuard se v této verzi spojuje přes ZeroTier.</small>
        <button type="button" v-if="editing" class="secondary" @click="resetDraft">Zrušit úpravy</button>
        <button :disabled="saving || !!connectionNode || publishing">{{ saving ? "Ukládám…" : (editing ? "Uložit opravy" : "Uložit draft") }}</button>
      </form>
    </section>
    </div>
    <div v-show="activeTab === 'notebooks'" id="panel-notebooks" class="tab-panel" role="tabpanel" aria-labelledby="tab-notebooks" tabindex="0">
    <section class="panel">
      <div><p class="kicker">Discovery a synchronizace</p><h2>Správa federace z více notebooků</h2></div>
      <p>Spárované notebooky sdílejí návrh routerů, síťové nastavení a kořenovou identitu pro správu federace. Změny se přenášejí přímo a šifrovaně při spuštěné aplikaci.</p>
      <p v-if="syncError" class="error" role="alert">{{ syncError }}</p>
      <p v-if="sharedSettingsChanged" class="warning">Sdílená konfigurace se změnila. Načtení aktualizuje seznam routerů a formulář sítě.</p>
      <button v-if="sharedSettingsChanged" class="secondary" :disabled="!!connectionNode || saving || ztSaving" @click="loadSharedSettings">Načíst sdílené nastavení</button>
      <button v-if="!notebookSync" :disabled="syncBusy" @click="notebookOperation()">{{ syncBusy ? 'Načítám…' : 'Načíst stav synchronizace' }}</button>
      <template v-if="notebookSync">
        <p><strong>{{ notebookSync.running ? 'Synchronizace běží' : 'Synchronizace je vypnutá nebo služba neběží' }}</strong></p>
        <p v-if="notebookSync.error" class="error">{{ notebookSync.error }}</p>
        <form class="form" @submit.prevent="notebookOperation({ action: 'configure', ...syncDraft })">
          <label>Název tohoto notebooku<input v-model="syncDraft.name" required maxlength="80" :disabled="syncBusy" /></label>
          <label>Místní IPv4 adresa pro spojení<input v-model="syncDraft.address" placeholder="LAN nebo ZeroTier IPv4 tohoto notebooku" required :disabled="syncBusy" /></label>
          <small>Použijte rozhraní dosažitelné z ostatních notebooků. Při změně místní adresy zde službu znovu spusťte. Discovery se opakuje každých 30 sekund.</small>
          <button :disabled="syncBusy">{{ notebookSync.running ? 'Použít nastavení a restartovat' : 'Zapnout discovery a synchronizaci' }}</button>
          <button type="button" class="secondary" :disabled="syncBusy || !notebookSync.config.enabled" @click="notebookOperation({ action: 'stop' })">Vypnout synchronizaci</button>
        </form>
        <div><strong>Otisk tohoto notebooku</strong><code class="fingerprints sync-fingerprint">{{ notebookSync.id }}</code></div>
        <details><summary>Ruční párování, pokud se notebooky nenajdou</summary>
          <p>Na druhém notebooku vložte tyto veřejné párovací údaje. Potom údaje přeneste i opačným směrem a na obou zařízeních ověřte otisky.</p>
          <textarea class="pairing-data" readonly aria-label="Veřejné párovací údaje tohoto notebooku" :value="notebookSync.invitation"></textarea>
          <form class="connection-form" @submit.prevent="notebookOperation({ action: 'manual', invitation: manualInvitation })">
            <label>Údaje druhého notebooku<textarea class="pairing-data" v-model="manualInvitation" required></textarea></label>
            <button :disabled="syncBusy">Přidat do přehledu pro ověření</button>
          </form>
        </details>
        <p v-if="!notebookSync.peers.length" class="muted">Zatím nebyl nalezen jiný notebook. Zapněte synchronizaci i na něm a vyberte společně dostupnou síť.</p>
        <article v-for="peer in notebookSync.peers" :key="peer.id" class="node">
          <div><h3>{{ peer.name }}</h3><p>{{ peer.address }} · {{ peer.trusted ? 'Spárovaný notebook' : 'Nalezený notebook · dosud bez přístupu' }}</p></div>
          <code class="fingerprints sync-fingerprint">{{ peer.id }}</code>
          <p v-if="peer.state">{{ notebookLabels[peer.state] ?? peer.state }}</p>
          <p v-if="peer.error" class="error">{{ peer.error }}</p>
          <small v-if="peer.lastSync">Poslední úspěšný přenos: {{ new Date(peer.lastSync * 1000).toLocaleString('cs-CZ') }}</small>
          <template v-if="!peer.trusted">
            <label class="trust-check"><input type="checkbox" v-model="verifiedPeers[peer.id]" />Porovnal(a) jsem otisk přímo na druhém notebooku a povoluji mu synchronizaci i správu federace.</label>
            <button :disabled="syncBusy || !verifiedPeers[peer.id]" @click="notebookOperation({ action: 'pair', peer: peer.id })">Potvrdit párování a právo správy</button>
            <small>Potvrzení proveďte také na druhém notebooku. Nový notebook bez vlastní federace pak automaticky převezme konfiguraci a řídicí identitu.</small>
          </template>
          <template v-else>
            <div v-if="peer.conflictToken" class="setup-preview">
              <strong>Souběžné změny vyžadují rozhodnutí</strong>
              <p>Místní routery: {{ peer.localNodes?.join(', ') || 'žádné' }}</p>
              <p>Routery protějšku: {{ peer.remoteNodes?.join(', ') || 'žádné' }}</p>
              <details><summary>Porovnat nastavení před rozhodnutím</summary>
                <h4>Místní konfigurace</h4><pre>{{ JSON.stringify(peer.localConfig, null, 2) }}</pre>
                <h4>Konfigurace protějšku</h4><pre>{{ JSON.stringify(peer.remoteConfig, null, 2) }}</pre>
              </details>
              <div class="node-actions">
                <button :disabled="syncBusy || !!connectionNode" @click="resolveNotebook(peer, 'local')">Zachovat místní konfiguraci</button>
                <button class="secondary" :disabled="syncBusy || !!connectionNode" @click="resolveNotebook(peer, 'remote')">Převzít konfiguraci protějšku</button>
              </div>
            </div>
            <button class="secondary" :disabled="syncBusy" @click="notebookOperation({ action: 'unpair', peer: peer.id })">Odpojit synchronizaci s notebookem</button>
            <small>Odpojení zastaví další přenosy. Již předaný kořenový klíč na druhém notebooku zůstává; jeho právo správy tím není odvoláno.</small>
          </template>
        </article>
      </template>
    </section>
    <section class="panel">
      <div><p class="kicker">Řídicí uzly</p><h2>Notebooky</h2></div>
      <p>Tento notebook spravuje federaci a kontroluje své připojení přes ZeroTier.</p>
      <div class="node-grid">
        <article class="node">
          <h3>Tento notebook</h3>
          <p>Řídicí uzel · pouze ZeroTier · bez WireGuard spojů</p>
          <p v-if="notebookError" class="error">{{ notebookError }}</p>
          <template v-if="notebookStatus">
            <p>{{ notebookStatus.summary }}</p>
            <p v-if="notebookStatus.networkId !== ztSettings.networkId" class="warning">Nastavení sítě se změnilo. Obnovte kontrolu notebooku.</p>
            <p>Network ID: {{ notebookStatus.networkId ?? 'nevybráno' }}</p>
            <p>ID zařízení: {{ notebookStatus.deviceId ?? 'nezjištěno' }}</p>
            <p>Adresy: {{ notebookStatus.assignedAddresses.join(', ') || 'zatím žádné' }}</p>
            <small>Načteno {{ new Date(notebookStatus.checkedAt).toLocaleString('cs-CZ') }}</small>
          </template>
          <p v-else class="muted">ZeroTier zatím nebyl zkontrolován.</p>
          <button class="secondary" :disabled="notebookChecking || ztSaving" @click="checkNotebook">{{ notebookChecking ? 'Kontroluji…' : 'Zkontrolovat ZeroTier notebooku' }}</button>
          <p><small>Kontrola čte místní ZeroTier. Pokud chybí oprávnění ke službě, stav nelze ověřit.</small></p>
        </article>
      </div>
    </section>
    </div>
    <div v-show="activeTab === 'network'" id="panel-network" class="tab-panel" role="tabpanel" aria-labelledby="tab-network" tabindex="0">
    <section class="panel">
      <div><p class="kicker">ZeroTier</p><h2>Síť federace</h2></div>
      <p>Uložte Network ID ze ZeroTier Central. U každého routeru potom zkontrolujte stav a podle potřeby proveďte instalaci a připojení do sítě.</p>
      <form class="form" @submit.prevent="saveZeroTier">
        <label>Network ID<input v-model="ztDraft.networkId" pattern="[0-9a-fA-F]{16}" maxlength="16" placeholder="16 hexadecimálních znaků" :disabled="!!connectionNode || ztSaving" /></label>
        <label>Web pro autorizaci<select v-model="ztDraft.central" :disabled="!!connectionNode || ztSaving"><option value="new">ZeroTier Central (central.zerotier.com)</option><option value="legacy">Legacy Central (my.zerotier.com)</option></select></label>
        <label>ZeroTier subnet (pro kontrolu)
          <div class="input-with-action">
            <input v-model="ztDraft.zeroTierSubnet" placeholder="10.147.17.0/24" :disabled="!!connectionNode || ztSaving" />
            <button type="button" class="secondary small" @click="suggestSubnets" :disabled="!!connectionNode || ztSaving">Navrhnout subnety</button>
          </div>
        </label>
        <label>WireGuard subnet (pro automatické doplnění)<input v-model="ztDraft.wireguardSubnet" placeholder="10.203.0.0/24" :disabled="!!connectionNode || ztSaving" /></label>
        <small>Pokud vyplníte subnety, aplikace automaticky doplní ZeroTier adresu zjištěnou z routeru a odvodí z ní WireGuard adresu (použije poslední oktet).</small>
        <button :disabled="ztSaving || !!connectionNode">{{ ztSaving ? 'Ukládám…' : 'Uložit nastavení ZeroTier' }}</button>
        <button type="button" class="secondary" @click="proposeAllAddresses" :disabled="ztSaving || !!connectionNode">Doplnit adresy všem uzlům</button>
        <button type="button" class="secondary" :disabled="browserOpening" @click="openCentral">Otevřít ZeroTier Central</button>
      </form>
      <small>Uložená síť: {{ ztSettings.networkId ?? 'zatím nevybraná' }}. Uložení mění pouze místní návrh; router změní až akce „Provést nastavení ZeroTier“.</small>
    </section>
    </div>
    <div v-show="activeTab === 'sync'" id="panel-sync" class="tab-panel" role="tabpanel" aria-labelledby="tab-sync" tabindex="0">
    <section class="panel">
      <div><p class="kicker">Deploy a synchronizace</p><h2>Postupné zprovoznění stanovišť</h2></div>
      <p>Instalaci i aktualizaci agenta proveďte z notebooku připojeného přímo do LAN routeru přes Ethernet nebo Wi-Fi. Zadejte číselnou LAN IPv4 jako SSH adresu a validujte plán. Drafty se přenesou společně s nastavením, do WireGuardu se zapojí až přijaté routery.</p>
      <p v-if="deployment">Podepsaná revize: <strong>{{ deployment.revision || 'zatím žádná' }}</strong> · {{ deployment.unpublishedChanges ? 'Návrh obsahuje nepublikované změny.' : 'Návrh odpovídá podepsané revizi.' }}</p>
      <p v-if="deploymentError" class="error">{{ deploymentError }}</p>
      <details v-if="deployment?.fingerprint"><summary>Kotva důvěry tohoto notebooku</summary><code class="fingerprints">{{ deployment.fingerprint }}</code></details>
      <p>Při deployi druhého routeru se nové členství a síťové nastavení předá prvnímu přes ZeroTier. Routery předání opakují i bez notebooku. Nedostupný uzel zůstává na starší revizi do obnovení spojení; sledujte přijatou a aplikovanou revizi.</p>
      <div class="node-actions">
        <button :disabled="publishing || !!connectionNode || saving || !ztSettings.networkId" @click="publishChanges">{{ publishing ? 'Publikuji a ověřuji…' : 'Podepsat a synchronizovat opravy' }}</button>
        <button class="secondary" :disabled="publishing || !!connectionNode" @click="refreshDeployment">Obnovit místní přehled</button>
      </div>
      <small>Publikování autorizuje aplikování změn na již přijatých uzlech. Přes ZeroTier se přenáší jen síťové nastavení a stav, nikoli aktualizace softwaru. WireGuard automaticky obnovuje relační klíče.</small>
    </section>
    </div>
    <div v-show="activeTab === 'audits'" id="panel-audits" class="tab-panel" role="tabpanel" aria-labelledby="tab-audits" tabindex="0">
    <section class="panel">
      <div><p class="kicker">Odchylky</p><h2>Výsledky auditu</h2></div>
      <p v-if="!auditedNodeName" class="muted">Zatím jste nespustili audit. V záložce Routery vyberte „Auditovat skutečný stav“.</p>
      <p v-else>Poslední audit: <strong>{{ auditedNodeName }}</strong> · {{ findings.length ? `${findings.length} nálezů` : 'Bez zjištěných odchylek' }}.</p>
      <button type="button" class="secondary" @click="activeTab = 'routers'">Přejít na routery</button>
      <ul v-if="findings.length">
        <li v-for="finding in findings" :key="finding.id" :class="finding.severity">
          <strong>{{ finding.component }} · {{ finding.summary }}</strong>
          <small>{{ nodes.find(node => node.id === finding.nodeId)?.name ?? finding.nodeId }} · Načteno {{ new Date(finding.observedAt).toLocaleString('cs-CZ') }}</small>
          <dl class="finding-state">
            <div><dt>Očekávaný stav</dt><dd>{{ finding.expectedState }}</dd></div>
            <div><dt>Načtený stav routeru</dt><dd><pre>{{ finding.observedState }}</pre></dd></div>
          </dl>
          <span>{{ finding.remediation }}</span>
        </li>
      </ul>
    </section>
    </div>
    <div v-show="activeTab === 'settings'" id="panel-settings" class="tab-panel" role="tabpanel" aria-labelledby="tab-settings" tabindex="0">
    <section class="panel">
      <div><p class="kicker">Nastavení</p><h2>Import / export federace</h2></div>
      <p>Export obsahuje návrh uzlů a globální nastavení federace. Neobsahuje SSH hesla, uložené host keys, auditní výpisy ani runtime stav routerů.</p>
      <div class="node-actions">
        <button type="button" @click="doExportSettings">Exportovat nastavení</button>
        <button type="button" class="secondary" @click="settingsFileInput?.click()">Importovat nastavení</button>
        <input ref="settingsFileInput" type="file" accept=".json,application/json" hidden @change="doImportSettings" />
      </div>
      <small>Import sloučí drafty podle ID. Ostatní uzly, jejich přijetí do federace a lokální SSH důvěru zachová. Podpisový klíč notebooku není součástí exportu.</small>
    </section>
    </div>
    <div v-if="connectionNode" class="modal-backdrop">
      <section class="connection-dialog panel" role="dialog" aria-modal="true" aria-labelledby="connection-title">
        <h2 id="connection-title">{{ actionLabels[connectionAction] }} · {{ connectionNode.name }}</h2>
        <p>{{ connectionNode.sshUser }}@{{ connectionNode.sshHost }}:{{ connectionNode.sshPort }}</p>
        <div v-if="connectionAction === 'zerotier-setup'" class="setup-preview">
          <strong>Změny na routeru {{ connectionNode.name }}</strong>
          <ol>
            <li v-if="!ztStatuses[connectionNode.id]?.installed">Nainstalovat ZeroTier z repozitářů routeru.</li>
            <li>Zálohovat konfiguraci a uložit členství v síti <code>{{ ztNetworkForOperation }}</code>.</li>
            <li>Zapnout službu při startu routeru a spustit ji, pokud neběží.</li>
            <li>Připojit síť a načíst stav autorizace a adresy.</li>
          </ol>
          <p>Povolí spravované adresy a trasy této sítě. Převzetí výchozí trasy, veřejných rozsahů a DNS zůstane vypnuté. Existující členství v dalších sítích zachová.</p>
          <label class="trust-check"><input v-model="openCentralAfterSetup" type="checkbox" :disabled="submitting" />Po nastavení otevřít ZeroTier Central pro autorizaci.</label>
        </div>
        <div v-if="connectionAction === 'deploy' && plans[connectionNode.id]" class="setup-preview">
          <strong>Plán nasazení na {{ connectionNode.name }}</strong>
          <ol><li v-for="step in plans[connectionNode.id].steps" :key="step">{{ step }}</li></ol>
          <details><summary>Nastavení včetně draftů</summary><pre>{{ JSON.stringify(plans[connectionNode.id].config, null, 2) }}</pre></details>
          <label class="trust-check"><input v-model="deployConfirmed" type="checkbox" :disabled="submitting" />Potvrzuji instalaci / aktualizaci přes přímou LAN a aplikování plánu včetně předání síťových změn ostatním přijatým routerům přes ZeroTier.</label>
        </div>
        <p v-if="inspecting" role="status">Načítám otisk SSH klíče routeru…</p>
        <p v-if="connectionError" class="error connection-error" role="alert">{{ connectionError }}</p>
        <button v-if="!identity && !inspecting" @click="inspectHost">Zkusit načíst znovu</button>
        <form v-if="identity" class="connection-form" @submit.prevent="submitConnection">
          <p v-if="identity.trust === 'trusted'">SSH klíč odpovídá dříve potvrzenému routeru.</p>
          <p v-else-if="identity.trust === 'changed'" class="error">SSH klíč se změnil! Pokračujte pouze po ověření, proč router používá jiný klíč.</p>
          <p v-else>První připojení: porovnejte otisky s klíči routeru přes jeho konzoli nebo jiný důvěryhodný přístup.</p>
          <pre class="fingerprints">{{ identity.fingerprints }}</pre>
          <label v-if="identity.trust !== 'trusted'" class="trust-check"><input v-model="trustHostKey" type="checkbox" :disabled="submitting" />Ověřil(a) jsem otisky a důvěřuji tomuto routeru.</label>
          <label>SSH heslo<input v-model="password" type="password" autocomplete="off" required :disabled="submitting" /></label>
          <small>Heslo použijeme pouze pro tento pokus a neuložíme ho. {{ (connectionAction === 'zerotier-setup' || connectionAction === 'deploy') ? 'Instalace může trvat několik minut.' : 'Tato akce pouze načte nebo ověří stav routeru.' }}</small>
          <button :disabled="submitting || !password || (connectionAction === 'deploy' && !deployConfirmed) || (identity.trust !== 'trusted' && !trustHostKey)">{{ submitting ? (connectionAction === 'zerotier-setup' ? 'Nastavuji ZeroTier…' : 'Načítám…') : actionLabels[connectionAction] }}</button>
        </form>
        <button class="secondary" :disabled="submitting || inspecting" @click="closeConnection">Zavřít</button>
      </section>
    </div>
    <p v-if="message" class="message" role="status">{{ message }}</p>
  </main>
</template>
