<script setup lang="ts">
import { computed } from "vue";
import type { NotebookSyncStatus } from "./backend";
import type { DeploymentOverview, FederationNode, NotebookDiagnostics, ZeroTierSettings } from "./domain";

const props = defineProps<{
  nodes: FederationNode[];
  deployment: DeploymentOverview | null;
  settings: ZeroTierSettings;
  notebook: NotebookSyncStatus | null;
  diagnostics: NotebookDiagnostics | null;
  loading: boolean;
  diagnosticsLoading: boolean;
}>();

defineEmits<{ refresh: []; diagnose: [] }>();

const deploymentLabels: Record<string, string> = {
  pending: "Čeká na aplikování",
  error: "Chyba agenta",
  confirming: "Čeká na potvrzení",
  waiting_peers: "Čeká na protějšky",
  active: "Spojení ověřeno",
  rollback: "Obnovena záloha",
  revoked: "Členství odvoláno",
};

const notebookState = computed(() => {
  if (props.notebook?.service?.active) return "Backend běží";
  if (props.notebook?.service?.installed) return "Služba neběží";
  if (props.notebook) return "Backend běží pouze s UI";
  return "Stav není načtený";
});

const lastChecked = computed(() => {
  const timestamps = Object.values(props.deployment?.nodes ?? {})
    .map(report => report.checkedAt)
    .filter((value): value is number => typeof value === "number");
  if (!timestamps.length) return "Dosud neověřeno";
  return new Date(Math.max(...timestamps) * 1000).toLocaleString("cs-CZ");
});

function membership(node: FederationNode) {
  const report = props.deployment?.nodes[node.id];
  if (!report?.enrolled) return "Draft";
  if (report.reachable === false) return "Nedostupný · poslední známý stav";
  return deploymentLabels[report.state ?? ""] ?? "Přijatý uzel";
}

function diagnostic(nodeId: string) {
  return props.diagnostics?.nodes[nodeId]?.zerotier;
}

function diagnosticLabel(nodeId: string) {
  const result = diagnostic(nodeId);
  if (!result?.samples.length || Date.now() / 1000 - result.checkedAt > 120) return "● Bez aktuálního měření";
  const replies = result.samples.filter(Boolean).length;
  return `● ${result.successPercent?.toFixed(1)} % · ${replies}/${result.samples.length} odpovědí`;
}

function diagnosticClass(nodeId: string) {
  const result = diagnostic(nodeId);
  if (!result?.samples.length || Date.now() / 1000 - result.checkedAt > 120 || result.successPercent === null) return "unknown";
  if (result.successPercent >= 95) return "green";
  if (result.successPercent >= 80) return "yellow";
  return "red";
}
</script>

<template>
  <section class="overview-page" aria-labelledby="overview-title">
    <div class="overview-heading">
      <div>
        <p class="kicker">Turris Federation · přehled sítě</p>
        <h2 id="overview-title">Tento notebook</h2>
        <p class="muted">Poslední zaznamenaný stav. Načtení přehledu neprovádí nový audit ani ping sítě.</p>
      </div>
      <button type="button" class="secondary" :disabled="loading" @click="$emit('refresh')">
        {{ loading ? "Načítám…" : "Obnovit stav" }}
      </button>
    </div>

    <div class="overview-cards">
      <article><span>Stav tohoto notebooku</span><strong>{{ notebookState }}</strong></article>
      <article><span>Přijatá revize</span><strong>{{ deployment?.revision || "—" }}</strong></article>
      <article><span>Spravované uzly</span><strong>{{ nodes.length }}</strong></article>
    </div>
    <p class="muted">Poslední kontrola routeru: {{ lastChecked }}</p>

    <section class="overview-section">
      <div class="overview-section-heading">
        <h3>Uzly federace</h3>
        <button type="button" class="secondary" :disabled="diagnosticsLoading || !deployment?.revision" @click="$emit('diagnose')">
          {{ diagnosticsLoading ? "Měřím…" : "Spustit ping · 5 paketů" }}
        </button>
      </div>
      <p v-if="!nodes.length" class="muted">Federace zatím neobsahuje žádné routery.</p>
      <div v-else class="overview-table-wrap">
        <table class="overview-table">
          <thead><tr><th>Uzel</th><th>ZeroTier</th><th>WireGuard</th><th>LAN sítě</th><th>Dostupní hosté</th><th>Stav / členství</th><th>Ping ZeroTier</th><th>Ping WireGuard</th></tr></thead>
          <tbody>
            <tr v-for="node in nodes" :key="node.id">
              <td><strong>{{ node.name }}</strong></td>
              <td><code>{{ node.zeroTierAddress || "—" }}</code></td>
              <td><code>{{ node.wireguardAddress || "—" }}</code></td>
              <td><span v-for="cidr in node.lanCidrs" :key="cidr" class="overview-line">{{ cidr }}</span><span v-if="!node.lanCidrs.length">—</span></td>
              <td>
                <ul v-if="deployment?.nodes[node.id]?.hosts?.length" class="overview-hosts">
                  <li v-for="host in deployment.nodes[node.id].hosts" :key="host.address"><code>{{ host.address }}</code><small v-if="host.name">{{ host.name }}</small></li>
                </ul>
                <span v-else>—</span>
              </td>
              <td><span class="overview-badge">{{ membership(node) }}</span></td>
              <td><span :class="['overview-signal', diagnosticClass(node.id)]">{{ diagnosticLabel(node.id) }}</span></td>
              <td><span class="overview-signal unknown">Notebook nepoužívá WireGuard</span></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="muted">Katalog obsahuje pasivně známé sousedy v LAN prefixech oznamujícího uzlu; neprovádí aktivní skenování a nesdílí MAC adresy. Členství vychází z přijaté konfigurace. Ping se spouští pouze tlačítkem a míří výhradně na ZeroTier adresy přijatých routerů z podepsané revize. Notebook WireGuard v této verzi nepoužívá a dostupnost neodhaduje z jiných stavů.</p>
    </section>

    <section class="overview-section">
      <h3>Síť a správa</h3>
      <p>ZeroTier Network ID: <code>{{ settings.networkId || "—" }}</code></p>
      <p>Notebook je koncový uzel v ZeroTier. Neroutuje provoz mezi VPN a fyzickou sítí a neinzeruje svou LAN.</p>
      <p class="muted">Změny konfigurace, audity a nasazení jsou oddělené v administračních záložkách.</p>
    </section>
  </section>
</template>
