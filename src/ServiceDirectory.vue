<script setup lang="ts">
import { computed, ref } from "vue";
import { openServiceEndpoint } from "./backend";
import type { ReadOnlyOverview } from "./domain";

const props = defineProps<{ overview: ReadOnlyOverview | null; userCacheOnly?: boolean }>();
const serviceFilter = ref("");
const serviceProtocol = ref<"" | "tcp" | "http" | "https">("");
const serviceHostFilter = ref("");
const serviceRouterFilter = ref("");
const actionStatus = ref("");
const openingEndpoint = ref("");

const filteredServices = computed(() => (props.overview?.services ?? []).filter(service =>
  service.name.toLocaleLowerCase("cs-CZ").includes(serviceFilter.value.trim().toLocaleLowerCase("cs-CZ"))
  && (!serviceProtocol.value || service.protocol === serviceProtocol.value)
  && `${service.hostAddress} ${service.hostName ?? ""}`.toLocaleLowerCase("cs-CZ").includes(serviceHostFilter.value.trim().toLocaleLowerCase("cs-CZ"))
  && service.routerName.toLocaleLowerCase("cs-CZ").includes(serviceRouterFilter.value.trim().toLocaleLowerCase("cs-CZ")),
));

async function copyEndpoint(endpoint: string) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard API není dostupné");
    await navigator.clipboard.writeText(endpoint);
    actionStatus.value = `Zkopírováno: ${endpoint}`;
  } catch {
    const field = document.createElement("textarea");
    field.value = endpoint;
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand("copy");
    field.remove();
    actionStatus.value = copied ? `Zkopírováno: ${endpoint}` : "Endpoint se nepodařilo zkopírovat. Zkopírujte jej přímo z tabulky.";
  }
}

async function openEndpoint(endpoint: string) {
  openingEndpoint.value = endpoint;
  try {
    await openServiceEndpoint(endpoint);
    actionStatus.value = `Otevřeno v systémovém prohlížeči: ${endpoint}`;
  } catch (error) {
    actionStatus.value = `Endpoint nelze otevřít: ${String(error)}`;
  } finally {
    openingEndpoint.value = "";
  }
}
</script>

<template>
  <section class="overview-page" aria-labelledby="service-directory-title">
    <section class="overview-section">
      <div class="overview-section-heading">
        <div><p class="kicker">Federované služby</p><h2 id="service-directory-title">Zlaté stránky služeb</h2><p class="muted">Ověřené definice přijatých routerů; nejde o potvrzení aktuální dostupnosti služby.</p></div>
        <span class="overview-badge">{{ filteredServices.length }}/{{ overview?.services.length ?? 0 }}</span>
      </div>
      <div class="service-filters">
        <label>Služba<input v-model="serviceFilter" type="search" placeholder="Ollama"></label>
        <label>Protokol<select v-model="serviceProtocol"><option value="">všechny</option><option value="tcp">tcp</option><option value="http">http</option><option value="https">https</option></select></label>
        <label>Host<input v-model="serviceHostFilter" type="search" placeholder="192.168.1.20 nebo název"></label>
        <label>Router<input v-model="serviceRouterFilter" type="search" placeholder="Lokalita"></label>
      </div>
      <p v-if="actionStatus" class="muted" role="status">{{ actionStatus }}</p>
      <p v-if="!filteredServices.length" class="muted">Filtru neodpovídá žádná ověřená služba.</p>
      <div v-else class="overview-table-wrap">
        <table class="overview-table">
          <thead><tr><th>Služba</th><th>Endpoint</th><th>Host</th><th>Router</th><th>Čerstvost</th><th>Akce</th></tr></thead>
          <tbody>
            <tr v-for="service in filteredServices" :key="`${service.routerId}:${service.id}`">
              <td><strong>{{ service.name }}</strong><small class="overview-line">{{ service.protocol }}</small></td>
              <td><code>{{ service.endpoint }}</code></td>
              <td>{{ service.hostName || service.hostAddress }}<small v-if="service.hostName" class="overview-line">{{ service.hostAddress }}</small></td>
              <td>{{ service.routerName }}<small class="overview-line">{{ service.routeAdvertised ? "Trasa je v podepsané topologii" : "Trasa není inzerovaná" }}</small></td>
              <td><span :class="['overview-badge', { stale: service.stale }]">{{ service.stale ? "Zastaralé" : "Aktuální" }}</span><small class="overview-line">{{ new Date(service.observedAt * 1000).toLocaleString("cs-CZ") }}</small></td>
              <td><div class="node-actions"><button type="button" class="secondary" @click="copyEndpoint(service.endpoint)">Kopírovat endpoint</button><button v-if="service.protocol === 'http' || service.protocol === 'https'" type="button" :disabled="!!openingEndpoint" @click="openEndpoint(service.endpoint)">{{ openingEndpoint === service.endpoint ? "Otevírám…" : "Otevřít v prohlížeči" }}</button></div></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="userCacheOnly" class="warning">Uživatelský notebook nyní zobrazuje pouze katalog, který už má v místní ověřené cache. Automatický autentizovaný přenos katalogu bez administrátorské cache zatím není implementovaný.</p>
    </section>
  </section>
</template>
