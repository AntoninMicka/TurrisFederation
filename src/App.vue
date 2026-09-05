<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { auditNode, connectNode, inspectConnection, listNodes, saveNode } from "./backend";
import type { AuditFinding, FederationNode, HostIdentity } from "./domain";

const nodes = ref<FederationNode[]>([]);
const findings = ref<AuditFinding[]>([]);
const busyNodeId = ref("");
const message = ref("");
const connectionNode = ref<FederationNode | null>(null);
const connectionAction = ref<"connect" | "audit">("connect");
const identity = ref<HostIdentity | null>(null);
const password = ref("");
const trustHostKey = ref(false);
const connectionError = ref("");
const inspecting = ref(false);
const submitting = ref(false);
const saving = ref(false);
const statusLabels: Record<FederationNode["status"], string> = {
  draft: "Draft", observed: "SSH ověřeno", healthy: "V pořádku", drifted: "Odchylky", unreachable: "Připojení selhalo",
};
const draft = reactive<FederationNode>({
  id: crypto.randomUUID(), name: "", sshHost: "", sshPort: 22, sshUser: "root", lanCidrs: [], status: "draft",
});
const lanCidrsText = ref("");

onMounted(async () => {
  try { nodes.value = await listNodes(); }
  catch (error) { message.value = String(error); }
});

async function addDraft() {
  message.value = "";
  saving.value = true;
  try {
  draft.lanCidrs = lanCidrsText.value.split(",").map((item) => item.trim()).filter(Boolean);
  const saved = await saveNode({ ...draft, lanCidrs: [...draft.lanCidrs] });
  nodes.value = [...nodes.value.filter((node) => node.id !== saved.id), saved];
  Object.assign(draft, { id: crypto.randomUUID(), name: "", sshHost: "", sshPort: 22, sshUser: "root", lanCidrs: [], status: "draft" });
  lanCidrsText.value = "";
  message.value = "Draft uzlu byl uložen. Nyní se můžete připojit přes SSH.";
  } catch (error) { message.value = String(error); }
  finally { saving.value = false; }
}

async function openConnection(node: FederationNode, action: "connect" | "audit") {
  connectionNode.value = node;
  connectionAction.value = action;
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
  submitting.value = true;
  busyNodeId.value = node.id;
  connectionError.value = "";
  const credentials = { password: password.value, hostKey: host.hostKey, trustHostKey: trustHostKey.value };
  password.value = "";
  try {
    if (connectionAction.value === "audit") {
      findings.value = [];
      findings.value = await auditNode(node.id, credentials);
      message.value = findings.value.length ? `Audit ${node.name}: ${findings.value.length} položek.` : `Audit ${node.name} nezjistil odchylky.`;
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
    try { nodes.value = await listNodes(); }
    catch (error) { message.value = `Nelze obnovit seznam uzlů: ${String(error)}`; }
  }
}
</script>

<template>
  <main class="shell">
    <header><p class="kicker">Turris Omnia</p><h1>Federace routerů</h1><p>Navrhněte topologii, porovnejte ji se skutečným stavem a teprve potom materializujte změny.</p></header>
    <section class="summary"><article><strong>{{ nodes.length }}</strong><span>uzlů</span></article><article><strong>{{ findings.filter(f => f.severity === 'error').length }}</strong><span>kritických odchylek</span></article><article><strong>ZT + WG</strong><span>vrstvy spojení</span></article></section>
    <section class="panel">
      <div><p class="kicker">Návrh</p><h2>Nový uzel</h2></div>
      <form class="form" @submit.prevent="addDraft">
        <label>Název<input v-model="draft.name" required placeholder="Praha" /></label>
        <label>SSH adresa<input v-model="draft.sshHost" required placeholder="192.168.1.1" /></label>
        <label>SSH port<input v-model.number="draft.sshPort" type="number" min="1" max="65535" required /></label>
        <label>SSH uživatel<input v-model="draft.sshUser" required /></label>
        <label>LAN sítě<input v-model="lanCidrsText" required placeholder="192.168.10.0/24, 10.10.0.0/16" /></label>
        <label>Veřejný WireGuard endpoint<input v-model="draft.publicEndpoint" placeholder="vpn.example.cz:51820" /></label>
        <button :disabled="saving">{{ saving ? "Ukládám…" : "Uložit draft" }}</button>
      </form>
    </section>
    <section class="panel">
      <div><p class="kicker">Inventář</p><h2>Uzly federace</h2></div>
      <p v-if="!nodes.length" class="muted">Zatím není založen žádný uzel.</p>
      <div class="node-grid">
        <article v-for="node in nodes" :key="node.id" class="node">
          <div><span :class="['status', node.status]">{{ statusLabels[node.status] }}</span><h3>{{ node.name }}</h3><p>{{ node.sshUser }}@{{ node.sshHost }}:{{ node.sshPort }}</p><small>{{ node.lanCidrs.join(' · ') }}</small></div>
          <div class="node-actions">
            <button :disabled="!!busyNodeId || !!connectionNode" @click="openConnection(node, 'connect')">Připojit</button>
            <button class="secondary" :disabled="!!busyNodeId || !!connectionNode" @click="openConnection(node, 'audit')">Auditovat skutečný stav</button>
          </div>
        </article>
      </div>
    </section>
    <section v-if="findings.length" class="panel">
      <div><p class="kicker">Odchylky</p><h2>Co je potřeba opravit</h2></div>
      <ul>
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
    <div v-if="connectionNode" class="modal-backdrop">
      <section class="connection-dialog panel" role="dialog" aria-modal="true" aria-labelledby="connection-title">
        <h2 id="connection-title">{{ connectionAction === 'audit' ? 'SSH audit' : 'Připojení přes SSH' }} · {{ connectionNode.name }}</h2>
        <p>{{ connectionNode.sshUser }}@{{ connectionNode.sshHost }}:{{ connectionNode.sshPort }}</p>
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
          <small>Heslo použijeme pouze pro tento pokus a neuložíme ho. {{ connectionAction === 'audit' ? 'Audit načte stav routeru.' : 'Připojení ověří přihlášení, neotevírá trvalý terminál.' }}</small>
          <button :disabled="submitting || !password || (identity.trust !== 'trusted' && !trustHostKey)">{{ submitting ? 'Připojuji…' : connectionAction === 'audit' ? 'Připojit a auditovat' : 'Ověřit připojení' }}</button>
        </form>
        <button class="secondary" :disabled="submitting || inspecting" @click="closeConnection">Zavřít</button>
      </section>
    </div>
    <p v-if="message" class="message" role="status">{{ message }}</p>
  </main>
</template>
