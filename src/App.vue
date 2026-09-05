<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { auditNode, listNodes, saveNode } from "./backend";
import type { AuditFinding, FederationNode } from "./domain";

const nodes = ref<FederationNode[]>([]);
const findings = ref<AuditFinding[]>([]);
const busyNodeId = ref("");
const message = ref("");
const draft = reactive<FederationNode>({
  id: crypto.randomUUID(), name: "", sshHost: "", sshPort: 22, sshUser: "root", lanCidrs: [], status: "draft",
});
const lanCidrsText = ref("");

onMounted(async () => { nodes.value = await listNodes(); });

async function addDraft() {
  message.value = "";
  draft.lanCidrs = lanCidrsText.value.split(",").map((item) => item.trim()).filter(Boolean);
  const saved = await saveNode({ ...draft, lanCidrs: [...draft.lanCidrs] });
  nodes.value = [...nodes.value.filter((node) => node.id !== saved.id), saved];
  Object.assign(draft, { id: crypto.randomUUID(), name: "", sshHost: "", sshPort: 22, sshUser: "root", lanCidrs: [], status: "draft" });
  lanCidrsText.value = "";
  message.value = "Draft uzlu byl uložen. Před změnami spusťte audit.";
}

async function runAudit(node: FederationNode) {
  busyNodeId.value = node.id;
  message.value = `Načítám skutečný stav ${node.name} přes SSH…`;
  try {
    findings.value = await auditNode(node.id);
    nodes.value = await listNodes();
    message.value = findings.value.length ? `Audit našel ${findings.value.length} položek.` : "Uzel odpovídá aktuálnímu draftu.";
  } catch (error) {
    message.value = error instanceof Error ? error.message : String(error);
  } finally {
    busyNodeId.value = "";
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
        <label>SSH uživatel<input v-model="draft.sshUser" required /></label>
        <label>LAN sítě<input v-model="lanCidrsText" required placeholder="192.168.10.0/24, 10.10.0.0/16" /></label>
        <label>Veřejný WireGuard endpoint<input v-model="draft.publicEndpoint" placeholder="vpn.example.cz:51820" /></label>
        <button>Uložit draft</button>
      </form>
    </section>
    <section class="panel">
      <div><p class="kicker">Inventář</p><h2>Uzly federace</h2></div>
      <p v-if="!nodes.length" class="muted">Zatím není založen žádný uzel.</p>
      <div class="node-grid">
        <article v-for="node in nodes" :key="node.id" class="node">
          <div><span :class="['status', node.status]">{{ node.status }}</span><h3>{{ node.name }}</h3><p>{{ node.sshUser }}@{{ node.sshHost }}:{{ node.sshPort }}</p><small>{{ node.lanCidrs.join(' · ') }}</small></div>
          <button :disabled="busyNodeId === node.id" @click="runAudit(node)">{{ busyNodeId === node.id ? 'Kontroluji…' : 'Auditovat skutečný stav' }}</button>
        </article>
      </div>
    </section>
    <section v-if="findings.length" class="panel"><div><p class="kicker">Materializační plán</p><h2>Co je potřeba opravit</h2></div><ul><li v-for="finding in findings" :key="finding.id" :class="finding.severity"><strong>{{ finding.component }} · {{ finding.summary }}</strong><span>{{ finding.remediation }}</span></li></ul></section>
    <p v-if="message" class="message">{{ message }}</p>
  </main>
</template>

