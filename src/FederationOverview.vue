<script setup lang="ts">
import { computed } from "vue";
import type { NotebookSyncStatus } from "./backend";
import type { DiagnosticMeasurement, NotebookVpnDiagnostics, NotebookVpnPlan, NotebookVpnStatus, ReadOnlyNode, ReadOnlyOverview } from "./domain";

const props = defineProps<{
  overview: ReadOnlyOverview | null;
  notebook: NotebookSyncStatus | null;
  loading: boolean;
  diagnosticsLoading: boolean;
  vpnPlan: NotebookVpnPlan | null;
  vpnStatus: NotebookVpnStatus | null;
  vpnDiagnostics: NotebookVpnDiagnostics | null;
  vpnBusy: boolean;
  vpnError: string;
  serviceBusy: boolean;
  serviceError: string;
  vpnConfirmed: boolean;
}>();

defineEmits<{ refresh: []; diagnose: []; serviceInstall: []; serviceRemove: []; vpnPreview: []; vpnInstall: []; vpnRollback: []; "update:vpnConfirmed": [value: boolean] }>();

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
  if (props.notebook?.service?.active && props.notebook?.service?.enabled) return "Backend běží a má autostart";
  if (props.notebook?.service?.active) return "Backend běží bez autostartu";
  if (props.notebook?.service?.installed) return "Služba neběží";
  if (props.notebook) return "Backend běží pouze s UI";
  return "Stav není načtený";
});

const lastChecked = computed(() => {
  const timestamps = (props.overview?.nodes ?? [])
    .map(node => node.checkedAt)
    .filter((value): value is number => typeof value === "number");
  if (!timestamps.length) return "Dosud neověřeno";
  return new Date(Math.max(...timestamps) * 1000).toLocaleString("cs-CZ");
});

function membership(node: ReadOnlyNode) {
  if (!node.enrolled) return "Draft";
  if (node.reachable === false) return "Nedostupný · poslední známý stav";
  return deploymentLabels[node.state ?? ""] ?? "Přijatý uzel";
}

function diagnostic(nodeId: string) {
  return props.overview?.diagnostics.nodes[nodeId]?.zerotier;
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

function vpnDiagnostic(nodeId: string) {
  return props.vpnDiagnostics?.nodes[nodeId];
}

function measurementLabel(result?: DiagnosticMeasurement) {
  if (!result?.samples.length || Date.now() / 1000 - result.checkedAt > 120) return "● Bez aktuálního měření";
  const replies = result.samples.filter(Boolean).length;
  return `● ${result.successPercent?.toFixed(1)} % · ${replies}/${result.samples.length} odpovědí`;
}

function measurementClass(result?: DiagnosticMeasurement) {
  if (!result?.samples.length || Date.now() / 1000 - result.checkedAt > 120 || result.successPercent === null) return "unknown";
  if (result.successPercent >= 95) return "green";
  if (result.successPercent >= 80) return "yellow";
  return "red";
}

function handshakeLabel(nodeId: string) {
  const state = vpnDiagnostic(nodeId)?.handshakeState;
  if (state === "recent") return "Handshake je aktuální";
  if (state === "stale") return "Handshake je zastaralý";
  if (state === "never") return "Handshake dosud neproběhl";
  return "Handshake nelze ověřit";
}

const vpnDiagnosticFresh = computed(() =>
  !!props.vpnDiagnostics && props.vpnDiagnostics.revision === props.overview?.revision
    && Date.now() / 1000 - props.vpnDiagnostics.checkedAt <= 120,
);

const profileLabel = computed(() => ({
  active: "aktivní", inactive: "neaktivní", missing: "chybí", unknown: "nelze ověřit",
})[props.vpnDiagnostics?.profile ?? "unknown"]);

function presenceLabel(value: boolean | null, positive: string) {
  return value === true ? positive : value === false ? "chybí" : "nelze ověřit";
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
      <article><span>Přijatá revize</span><strong>{{ overview?.revision || "—" }}</strong></article>
      <article><span>Spravované uzly</span><strong>{{ overview?.nodes.length ?? 0 }}</strong></article>
      <article><span>Notebooky</span><strong>{{ overview?.notebooks.length ?? 0 }}</strong></article>
    </div>
    <p class="muted">Poslední kontrola routeru: {{ lastChecked }}</p>

    <section class="overview-section">
      <div class="overview-section-heading">
        <h3>Backend tohoto notebooku</h3>
        <div class="node-actions">
          <button v-if="!notebook?.service?.installed" type="button" :disabled="serviceBusy" @click="$emit('serviceInstall')">Nainstalovat službu</button>
          <button v-else-if="!notebook.service.active || !notebook.service.enabled" type="button" :disabled="serviceBusy" @click="$emit('serviceInstall')">Opravit a spustit službu</button>
          <button v-if="notebook?.service?.installed" type="button" class="secondary" :disabled="serviceBusy" @click="$emit('serviceRemove')">Zastavit a odstranit službu</button>
        </div>
      </div>
      <p v-if="serviceError || notebook?.serviceError" class="error">{{ serviceError || notebook?.serviceError }}</p>
      <p class="muted">Uživatelský notebook nepotřebuje adresu místní LAN. Jeho stabilní ZeroTier a WireGuard adresy pocházejí z podepsané topologie; změna Wi‑Fi ani fyzické sítě jeho identitu nemění.</p>
    </section>

    <section class="overview-section">
      <div class="overview-section-heading">
        <h3>Uzly federace</h3>
        <button type="button" class="secondary" :disabled="diagnosticsLoading || !overview?.revision" @click="$emit('diagnose')">
          {{ diagnosticsLoading ? "Měřím…" : "Spustit místní kontrolu · 5 paketů" }}
        </button>
      </div>
      <p v-if="!overview?.nodes.length" class="muted">Federace zatím neobsahuje žádné routery.</p>
      <div v-else class="overview-table-wrap">
        <table class="overview-table">
          <thead><tr><th>Uzel</th><th>ZeroTier</th><th>WireGuard</th><th>LAN sítě</th><th>Dostupní hosté</th><th>Stav / členství</th><th>Ping ZeroTier</th><th>Ping WireGuard</th></tr></thead>
          <tbody>
            <tr v-for="node in overview?.nodes ?? []" :key="node.id">
              <td><strong>{{ node.name }}</strong></td>
              <td><code>{{ node.zeroTierAddress || "—" }}</code></td>
              <td><code>{{ node.wireguardAddress || "—" }}</code></td>
              <td><span v-for="cidr in node.lanCidrs" :key="cidr" class="overview-line">{{ cidr }}</span><span v-if="!node.lanCidrs.length">—</span></td>
              <td>
                <ul v-if="node.hosts.length" class="overview-hosts">
                  <li v-for="host in node.hosts" :key="host.address"><code>{{ host.address }}</code><small v-if="host.name">{{ host.name }}</small></li>
                </ul>
                <span v-else>—</span>
              </td>
              <td><span class="overview-badge">{{ membership(node) }}</span></td>
              <td><span :class="['overview-signal', diagnosticClass(node.id)]">{{ diagnosticLabel(node.id) }}</span></td>
              <td>
                <span :class="['overview-signal', measurementClass(vpnDiagnostic(node.id)?.wireguard)]">{{ measurementLabel(vpnDiagnostic(node.id)?.wireguard) }}</span>
                <small class="overview-line">{{ handshakeLabel(node.id) }}</small>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="muted">Katalog obsahuje pasivně známé sousedy v LAN prefixech oznamujícího uzlu; neprovádí aktivní skenování a nesdílí MAC adresy. Členství vychází z přijaté konfigurace. Ping se spouští pouze tlačítkem a míří výhradně na ZeroTier a WireGuard adresy přijatých routerů z podepsané revize. Výsledek platí jen pro tento notebook a po 120 sekundách se označí jako zastaralý.</p>
    </section>

    <section class="overview-section">
      <h3>Notebooky federace</h3>
      <p v-if="!overview?.notebooks.length" class="muted">V podepsané topologii zatím není žádný notebook.</p>
      <div v-else class="overview-table-wrap">
        <table class="overview-table">
          <thead><tr><th>Notebook</th><th>Role</th><th>ZeroTier</th><th>WireGuard</th><th>Dostupnost</th></tr></thead>
          <tbody>
            <tr v-for="item in overview?.notebooks ?? []" :key="item.id">
              <td><strong>{{ item.name }}</strong><small v-if="item.id === notebook?.id" class="overview-line">Tento notebook</small></td>
              <td>{{ item.role === "administrator" ? "Administrátor" : "Uživatel" }}</td>
              <td><code>{{ item.zeroTierAddress || "čeká na přidělení" }}</code></td>
              <td><code>{{ item.wireguardAddress || "čeká na přidělení" }}</code></td>
              <td><span class="overview-signal unknown">Ověřuje se pouze místně</span></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="muted">Notebook je koncový uzel bez inzerované LAN. Přehled nezobrazuje ani neodhaduje aktuální dostupnost jiných notebooků.</p>
    </section>

    <section class="overview-section">
      <h3>Síť a správa</h3>
      <p>ZeroTier Network ID: <code>{{ overview?.networkId || "—" }}</code></p>
      <p>Notebook je koncový uzel v ZeroTier. Neroutuje provoz mezi VPN a fyzickou sítí a neinzeruje svou LAN.</p>
      <p class="muted">Změny konfigurace, audity a nasazení jsou oddělené v administračních záložkách.</p>
    </section>

    <section class="overview-section">
      <div class="overview-section-heading">
        <h3>VPN tohoto notebooku</h3>
        <button type="button" class="secondary" :disabled="vpnBusy" @click="$emit('vpnPreview')">
          {{ vpnBusy ? "Pracuji…" : "Zobrazit instalační plán" }}
        </button>
      </div>
      <p v-if="vpnError" class="error">{{ vpnError }}</p>
      <p><strong>{{ vpnStatus?.state === "installed" ? "VPN profil je nainstalovaný" : vpnStatus?.state === "rolled_back" ? "Předchozí profil byl obnoven" : vpnStatus?.state === "error" ? "Poslední instalace selhala" : "VPN profil zatím není nainstalovaný" }}</strong></p>
      <p v-if="vpnStatus?.address">Adresa: <code>{{ vpnStatus.address }}</code></p>
      <template v-if="vpnDiagnostics">
        <p :class="vpnDiagnosticFresh ? '' : 'warning'">Místní kontrola revize {{ vpnDiagnostics.revision }}: profil {{ profileLabel }}, rozhraní {{ presenceLabel(vpnDiagnostics.interfacePresent, "nalezeno") }}, adresa {{ presenceLabel(vpnDiagnostics.addressAssigned, "odpovídá") }}, routy {{ vpnDiagnostics.routesActive }}/{{ vpnDiagnostics.routesExpected }}.</p>
        <p v-if="vpnDiagnostics.forwarding.ipv4 !== false || vpnDiagnostics.forwarding.ipv6 !== false" class="error">Nelze potvrdit vypnutý IPv4 a IPv6 forwarding.</p>
        <p v-if="vpnDiagnostics.missingRoutes.length" class="warning">Chybějící routy: <code>{{ vpnDiagnostics.missingRoutes.join(", ") }}</code></p>
        <p v-if="vpnDiagnostics.unknownRoutes.length" class="warning">Routy, které nelze ověřit: <code>{{ vpnDiagnostics.unknownRoutes.join(", ") }}</code></p>
        <p v-if="!vpnDiagnosticFresh" class="muted">Výsledek je starší než 120 sekund; spusťte novou místní kontrolu.</p>
      </template>
      <template v-if="vpnPlan">
        <p>Revize {{ vpnPlan.revision }} · podklad <code>{{ vpnPlan.underlayDevice }}</code> · rozhraní <code>{{ vpnPlan.interfaceName }}</code> · adresa <code>{{ vpnPlan.address }}</code></p>
        <p>Routy: <code>{{ vpnPlan.routes.join(", ") || "žádné" }}</code></p>
        <p v-if="vpnPlan.currentConnection" class="warning">Stávající profil bude před změnou zachovaný pro rollback.</p>
        <ol><li v-for="step in vpnPlan.steps" :key="step">{{ step }}</li></ol>
        <label class="trust-check"><input type="checkbox" :checked="vpnConfirmed" @change="$emit('update:vpnConfirmed', ($event.target as HTMLInputElement).checked)" />Rozumím systémovým změnám a chci vyvolat polkit potvrzení instalace.</label>
        <button type="button" :disabled="vpnBusy || !vpnConfirmed" @click="$emit('vpnInstall')">Nainstalovat a aktivovat VPN</button>
      </template>
      <button v-if="vpnStatus?.state === 'installed'" type="button" class="secondary" :disabled="vpnBusy" @click="$emit('vpnRollback')">Obnovit předchozí VPN profil</button>
      <p class="muted">Instalace nevytváří výchozí trasu, nezapíná forwarding a používá pouze routy z podepsané topologie. Privátní klíč se nepředává v argumentech procesu.</p>
    </section>
  </section>
</template>
