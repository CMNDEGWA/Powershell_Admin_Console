<script setup>
import { computed, onMounted, ref } from 'vue'

const health = ref('Checking')
const machine = ref(null)
const summaryError = ref('')
const audits = ref([])
const selectedAudit = ref(null)
const auditError = ref('')
const auditLoading = ref(false)
const openEventLogs = ref([])
const tasks = ref([])
const history = ref([])
const taskResult = ref(null)
const taskLoading = ref(false)
const pageError = ref('')

const snapshot = computed(() => selectedAudit.value?.snapshot ?? null)
const findings = computed(() => snapshot.value?.recommendations ?? [])

async function apiRequest(path, options = {}) {
  const response = await fetch(path, options)
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

async function refreshMachineSummary() {
  summaryError.value = ''
  try {
    const data = await apiRequest('/api/system/summary')
    machine.value = data.machine
  } catch (err) {
    machine.value = null
    summaryError.value = err.message
  }
}

async function loadAudits() {
  const data = await apiRequest('/api/audits?limit=20')
  audits.value = data.audits
  const selectedId = selectedAudit.value?.id
  const nextId = audits.value.some((item) => item.id === selectedId)
    ? selectedId
    : audits.value[0]?.id
  if (nextId) await loadAudit(nextId)
  else selectedAudit.value = null
}

async function loadDashboard() {
  pageError.value = ''
  const results = await Promise.allSettled([
    apiRequest('/api/health'),
    apiRequest('/api/tasks'),
    apiRequest('/api/history?limit=10'),
    loadAudits(),
  ])
  if (results[0].status === 'fulfilled') health.value = results[0].value.status
  else {
    health.value = 'Unavailable'
    pageError.value = results[0].reason.message
  }
  if (results[1].status === 'fulfilled') tasks.value = results[1].value.tasks
  if (results[2].status === 'fulfilled') history.value = results[2].value.history
  if (results[3].status === 'rejected' && !pageError.value) pageError.value = results[3].reason.message
  await refreshMachineSummary()
}

async function loadAudit(id) {
  const data = await apiRequest(`/api/audits/${id}`)
  selectedAudit.value = data
  openEventLogs.value = []
}

async function runAudit() {
  auditLoading.value = true
  auditError.value = ''
  try {
    selectedAudit.value = await apiRequest('/api/audits', { method: 'POST' })
    await refreshMachineSummary()
    await loadAudits()
  } catch (err) {
    auditError.value = err.message
  } finally {
    auditLoading.value = false
  }
}

async function downloadPdf() {
  if (!selectedAudit.value) return
  auditError.value = ''
  try {
    const response = await fetch(`/api/audits/${selectedAudit.value.id}/pdf`)
    if (!response.ok) throw new Error(`PDF export failed (${response.status})`)
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `pac-audit-${selectedAudit.value.id}.pdf`
    anchor.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    auditError.value = err.message
  }
}

async function deleteAudit(id) {
  if (!window.confirm('Delete this saved audit and its collected system data?')) return
  auditError.value = ''
  try {
    await apiRequest(`/api/audits/${id}`, { method: 'DELETE' })
    if (selectedAudit.value?.id === id) selectedAudit.value = null
    await loadAudits()
  } catch (err) {
    auditError.value = err.message
  }
}

async function runTask(task) {
  taskLoading.value = true
  pageError.value = ''
  taskResult.value = null
  try {
    taskResult.value = await apiRequest(`/api/tasks/${encodeURIComponent(task.id)}/run`, { method: 'POST' })
    const data = await apiRequest('/api/history?limit=10')
    history.value = data.history
  } catch (err) {
    pageError.value = err.message
  } finally {
    taskLoading.value = false
  }
}

function collectorData(name) {
  return snapshot.value?.collectors?.[name]?.data ?? null
}

function asList(value) {
  if (value == null) return []
  return Array.isArray(value) ? value : [value]
}

function entries(value) {
  return value && typeof value === 'object' ? Object.entries(value) : []
}

function formatDate(value) {
  if (!value) return 'Not available'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatBytes(value) {
  if (!Number.isFinite(Number(value))) return 'Not available'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let amount = Number(value)
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024
    unit += 1
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

function statusClass(status) {
  return {
    succeeded: 'text-bg-success',
    partial: 'text-bg-warning',
    failed: 'text-bg-danger',
    denied: 'text-bg-secondary',
    unavailable: 'text-bg-secondary',
  }[status] || 'text-bg-secondary'
}

function severityClass(severity) {
  return {
    critical: 'text-bg-dark',
    high: 'text-bg-danger',
    medium: 'text-bg-warning',
    low: 'text-bg-info',
  }[severity] || 'text-bg-secondary'
}

function toggleEventLog(name, event) {
  if (event.target.open && !openEventLogs.value.includes(name)) {
    openEventLogs.value = [...openEventLogs.value, name]
  } else if (!event.target.open) {
    openEventLogs.value = openEventLogs.value.filter((item) => item !== name)
  }
}

onMounted(loadDashboard)
</script>

<template>
  <div class="min-vh-100 bg-body-tertiary">
    <nav class="navbar navbar-dark bg-dark">
      <div class="container-fluid px-3 px-lg-4">
        <span class="navbar-brand fw-semibold">PAC <span class="text-secondary">| System Audit</span></span>
        <span class="badge" :class="health === 'ok' ? 'text-bg-success' : 'text-bg-secondary'">
          Backend {{ health }}
        </span>
      </div>
    </nav>

    <main class="container-fluid px-3 px-lg-4 py-4">
      <div v-if="pageError" class="alert alert-warning" role="alert">
        <strong>Notice:</strong> {{ pageError }}
      </div>

      <section class="overview-section mb-5" aria-labelledby="overview-title">
        <div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-3">
          <div>
            <p class="section-kicker mb-1">MACHINE PROFILE</p>
            <h1 id="overview-title" class="h3 mb-1">System overview</h1>
            <p v-if="machine" class="text-secondary mb-0">{{ machine.platform }} · Scanned {{ formatDate(machine.collectedAt) }}</p>
            <p v-else class="text-secondary mb-0">System information is not available.</p>
          </div>
          <button class="btn btn-outline-secondary" :disabled="health !== 'ok'" @click="refreshMachineSummary">
            Refresh scan
          </button>
        </div>

        <div v-if="summaryError" class="alert alert-warning" role="alert">
          <strong>System scan unavailable:</strong> {{ summaryError }}
          <div class="small mt-1">Windows uses PowerShell 7; Linux and macOS use native system tools.</div>
        </div>

        <div v-if="machine">
          <div v-if="machine.administrator === false" class="alert alert-info" role="status">
            A full audit requires administrator/root privileges. The system overview remains available without elevation.
          </div>
          <div v-if="machine.supportedTarget === false" class="alert alert-warning" role="status">
            No audit collector is available for this operating system.
          </div>

          <div class="row g-3 mb-4">
            <div class="col-12 col-md-6 col-xl-3">
              <div class="overview-value">
                <span class="overview-label">Computer</span>
                <strong>{{ machine.hostname || 'Not available' }}</strong>
                <span>{{ machine.hardware?.manufacturer }} {{ machine.hardware?.model }}</span>
              </div>
            </div>
            <div class="col-12 col-md-6 col-xl-3">
              <div class="overview-value">
                <span class="overview-label">Operating system</span>
                <strong>{{ machine.operatingSystem?.caption || 'Not available' }}</strong>
                <span>{{ machine.platform === 'windows' ? `Version ${machine.operatingSystem?.version} · Build ${machine.operatingSystem?.build}` : `Version ${machine.operatingSystem?.version} · Kernel ${machine.operatingSystem?.build}` }}</span>
              </div>
            </div>
            <div class="col-12 col-md-6 col-xl-3">
              <div class="overview-value">
                <span class="overview-label">Hardware</span>
                <strong>{{ machine.hardware?.processorNames?.[0] || 'Processor unavailable' }}</strong>
                <span>{{ machine.hardware?.logicalProcessors || '—' }} logical processors · {{ formatBytes(machine.hardware?.memoryBytes) }} RAM</span>
              </div>
            </div>
            <div class="col-12 col-md-6 col-xl-3">
              <div class="overview-value">
                <span class="overview-label">Last boot</span>
                <strong>{{ formatDate(machine.operatingSystem?.lastBootTime) }}</strong>
                <span>{{ machine.operatingSystem?.architecture }} · {{ machine.operatingSystem?.powershellVersion ? `PowerShell ${machine.operatingSystem.powershellVersion}` : 'Native collector' }} · Uptime {{ Math.floor((machine.operatingSystem?.uptimeSeconds || 0) / 3600) }} hours</span>
              </div>
            </div>
          </div>

          <div class="row g-4">
            <div class="col-12 col-xl-8">
              <h2 class="h5 mb-2">Network adapters</h2>
              <div class="table-responsive border rounded-2 bg-white">
                <table class="table table-sm table-hover align-middle mb-0">
                  <thead class="table-light">
                    <tr><th>Adapter</th><th>State</th><th>MAC address</th><th>IP addresses</th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="(adapter, index) in machine.networkAdapters" :key="`${adapter.name}-${index}`">
                      <td><strong>{{ adapter.name }}</strong><div class="small text-secondary">{{ adapter.description }}</div></td>
                      <td><span class="badge" :class="adapter.status === 'Up' ? 'text-bg-success' : 'text-bg-secondary'">{{ adapter.status }}</span></td>
                      <td class="font-monospace">{{ adapter.macAddress || '—' }}</td>
                      <td class="font-monospace small">
                        <div v-for="address in adapter.addresses" :key="address.address">{{ address.address }}</div>
                        <span v-if="!adapter.addresses?.length">—</span>
                      </td>
                    </tr>
                    <tr v-if="!machine.networkAdapters?.length"><td colspan="4" class="text-secondary py-3">No adapters returned.</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
            <div class="col-12 col-xl-4">
              <h2 class="h5 mb-2">{{ machine.remoteAccess?.name || 'Remote access' }}</h2>
              <dl class="rdp-summary mb-0">
                <div><dt>Configured</dt><dd>{{ machine.remoteAccess?.configuredEnabled === true ? 'Enabled' : machine.remoteAccess?.configuredEnabled === false ? 'Disabled' : 'Not assessed' }}</dd></div>
                <div><dt>Service</dt><dd>{{ machine.remoteAccess?.serviceState || 'Not available' }} · {{ machine.remoteAccess?.serviceStartMode || '—' }}</dd></div>
                <div><dt>Inbound firewall rule</dt><dd>{{ machine.remoteAccess?.enabledInboundFirewallRule === true ? 'Enabled rule found' : machine.remoteAccess?.enabledInboundFirewallRule === false ? 'No enabled rule found' : 'Not assessed' }}</dd></div>
                <div><dt>Firewall rules detected</dt><dd>{{ machine.remoteAccess?.firewallRules?.length ?? 'Not assessed' }}</dd></div>
              </dl>
              <p class="small text-secondary mt-2 mb-0">Configuration, service state, and firewall exposure are reported separately when available.</p>
            </div>
          </div>
        </div>
      </section>

      <section class="audit-section mb-5" aria-labelledby="audit-title">
        <div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
          <div>
            <p class="section-kicker mb-1">READ-ONLY COLLECTION</p>
            <h2 id="audit-title" class="h3 mb-1">System audit</h2>
            <p class="text-secondary mb-0">Review the collected configuration, security findings, and event-log coverage.</p>
          </div>
          <button class="btn btn-primary" :disabled="auditLoading || health !== 'ok' || machine?.supportedTarget !== true || machine?.administrator !== true" @click="runAudit">
            {{ auditLoading ? 'Collecting system data…' : 'Run full audit' }}
          </button>
        </div>
        <div v-if="auditError" class="alert alert-warning" role="alert">{{ auditError }}</div>

        <div class="row g-4">
          <aside class="col-12 col-lg-3" aria-label="Saved audits">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <h3 class="h6 mb-0">Saved audits</h3>
              <span class="small text-secondary">{{ audits.length }}</span>
            </div>
            <div class="saved-audit-list">
              <div v-for="audit in audits" :key="audit.id" class="saved-audit-row" :class="{ selected: selectedAudit?.id === audit.id }">
                <button class="saved-audit-select" @click="loadAudit(audit.id)">
                  <strong>#{{ audit.id }} · {{ formatDate(audit.started_at) }}</strong>
                  <span class="badge mt-1" :class="statusClass(audit.status)">{{ audit.status }}</span>
                </button>
                <button class="btn btn-sm btn-outline-danger" :aria-label="`Delete audit ${audit.id}`" @click="deleteAudit(audit.id)">Delete</button>
              </div>
              <p v-if="audits.length === 0" class="text-secondary small p-3 mb-0">No saved audits yet.</p>
            </div>
          </aside>

          <div class="col-12 col-lg-9">
            <div v-if="selectedAudit && snapshot">
              <div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-3">
                <div>
                  <h3 class="h5 mb-1">Audit #{{ selectedAudit.id }}</h3>
                  <p class="small text-secondary mb-0">Completed {{ formatDate(selectedAudit.finished_at) }} · Schema {{ selectedAudit.schema_version }}</p>
                </div>
                <div class="d-flex gap-2">
                  <span class="badge align-self-center" :class="statusClass(selectedAudit.status)">{{ selectedAudit.status }}</span>
                  <button class="btn btn-outline-primary btn-sm" @click="downloadPdf">Download PDF</button>
                </div>
              </div>

              <div v-if="snapshot.error_code" class="alert alert-danger">Collection failed. Error code: {{ snapshot.error_code }}</div>
              <div v-if="selectedAudit.status === 'partial'" class="alert alert-warning">Some collectors or event logs could not be read. Review coverage before interpreting findings.</div>

              <section class="mb-4">
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <h4 class="h6 mb-0">Recommendations</h4>
                  <span class="small text-secondary">{{ findings.length }} findings</span>
                </div>
                <div v-if="findings.length" class="finding-list">
                  <article v-for="finding in findings" :key="finding.id" class="finding-row">
                    <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
                      <span class="badge" :class="severityClass(finding.severity)">{{ finding.severity }}</span>
                      <h5 class="h6 mb-0">{{ finding.title }}</h5>
                    </div>
                    <p class="mb-1">{{ finding.summary }}</p>
                    <p class="small mb-1"><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
                    <details class="small text-secondary">
                      <summary>Evidence · rule {{ finding.rule_version }}</summary>
                      <pre class="result-output mt-2">{{ JSON.stringify(finding.evidence, null, 2) }}</pre>
                    </details>
                  </article>
                </div>
                <p v-else class="text-secondary border rounded-2 bg-white p-3 mb-0">No findings were produced by the configured checks.</p>
              </section>

              <section class="mb-4">
                <h4 class="h6 mb-2">Collection coverage</h4>
                <div class="table-responsive border rounded-2 bg-white">
                  <table class="table table-sm align-middle mb-0">
                    <thead class="table-light"><tr><th>Collector</th><th>Status</th><th>Details</th></tr></thead>
                    <tbody>
                      <tr v-for="(collector, name) in snapshot.collectors" :key="name">
                        <td>{{ name }}</td>
                        <td><span class="badge" :class="statusClass(collector.status)">{{ collector.status }}</span></td>
                        <td>
                          <span v-if="name === 'eventLogs' && Array.isArray(collector.data)">
                            {{ collector.data.length }} channels · {{ collector.data.reduce((sum, log) => sum + (log.collectedCount || 0), 0) }} records collected
                          </span>
                          <span v-else>{{ collector.errorCode || 'Collected' }}</span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </section>

              <section v-if="collectorData('accountsAndGroups')" class="inventory-section mb-4">
                <h4 class="h6">Local accounts and groups</h4>
                <details class="inventory-detail">
                  <summary>{{ collectorData('accountsAndGroups').users?.length || 0 }} users · {{ collectorData('accountsAndGroups').groups?.length || 0 }} groups</summary>
                  <div class="table-responsive mt-2">
                    <table class="table table-sm table-striped"><thead><tr><th>User</th><th>Enabled</th><th>Last sign-in</th></tr></thead>
                      <tbody><tr v-for="user in collectorData('accountsAndGroups').users" :key="user.Name"><td>{{ user.Name }}</td><td>{{ user.Enabled ? 'Yes' : 'No' }}</td><td>{{ formatDate(user.LastLogon) }}</td></tr></tbody>
                                          <tbody><tr v-for="user in collectorData('accountsAndGroups').users" :key="user.Name"><td>{{ user.Name }}</td><td>{{ user.Enabled === null ? 'Unknown' : user.Enabled ? 'Yes' : 'No' }}</td><td>{{ formatDate(user.LastLogon) }}</td></tr></tbody>
                    </table>
                  </div>
                  <div v-for="group in collectorData('accountsAndGroups').groups" :key="group.name" class="small mb-1"><strong>{{ group.name }}:</strong> {{ group.members?.map((member) => member.name || member.errorCode).join(', ') || 'No members returned' }}</div>
                </details>
              </section>

              <section v-if="collectorData('services')" class="inventory-section mb-4">
                <h4 class="h6">Services</h4>
                <details class="inventory-detail"><summary>{{ asList(collectorData('services')).length }} services</summary>
                  <div class="table-responsive mt-2"><table class="table table-sm table-striped"><thead><tr><th>Name</th><th>State</th><th>Startup</th><th>Account</th></tr></thead>
                    <tbody><tr v-for="service in asList(collectorData('services')).slice(0, 250)" :key="service.Name"><td>{{ service.DisplayName }}</td><td>{{ service.State }}</td><td>{{ service.StartMode }}</td><td>{{ service.StartName }}</td></tr></tbody>
                  </table></div>
                  <p v-if="asList(collectorData('services')).length > 250" class="small text-secondary">Showing first 250 entries. All collected entries are retained in this audit.</p>
                </details>
              </section>

              <section v-if="collectorData('installedSoftware')" class="inventory-section mb-4">
                <h4 class="h6">Installed software</h4>
                <details class="inventory-detail"><summary>{{ asList(collectorData('installedSoftware')).length }} entries</summary>
                  <div class="table-responsive mt-2"><table class="table table-sm table-striped"><thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Scope</th></tr></thead>
                    <tbody><tr v-for="(software, index) in asList(collectorData('installedSoftware')).slice(0, 250)" :key="`${software.name}-${index}`"><td>{{ software.name }}</td><td>{{ software.version }}</td><td>{{ software.publisher }}</td><td>{{ software.scope }}</td></tr></tbody>
                  </table></div>
                </details>
              </section>

              <section v-if="collectorData('updates')" class="inventory-section mb-4">
                <h4 class="h6">Updates</h4>
                <details class="inventory-detail"><summary>{{ collectorData('updates').installedHotfixes?.length || 0 }} hotfixes · {{ collectorData('updates').pendingUpdates?.length || 0 }} pending</summary>
                  <h5 class="small fw-semibold mt-3">Pending updates</h5>
                  <ul class="small"><li v-for="(update, index) in collectorData('updates').pendingUpdates" :key="`${update.title}-${index}`">{{ update.title }}</li><li v-if="!collectorData('updates').pendingUpdates?.length">None reported</li></ul>
                  <h5 class="small fw-semibold">Recent update history</h5>
                  <ul class="small"><li v-for="(update, index) in collectorData('updates').updateHistory?.slice(0, 30)" :key="`${update.Title}-${index}`">{{ formatDate(update.Date) }} · {{ update.Title }} · result {{ update.ResultCode }}</li></ul>
                </details>
              </section>

              <section v-if="collectorData('firewall')" class="inventory-section mb-4">
                <h4 class="h6">Firewall</h4>
                <details class="inventory-detail"><summary>{{ collectorData('firewall').profiles?.length || 0 }} profiles · {{ collectorData('firewall').rules?.length || 0 }} rules</summary>
                  <div class="table-responsive mt-2"><table class="table table-sm"><thead><tr><th>Profile</th><th>Enabled</th><th>Inbound default</th><th>Outbound default</th></tr></thead>
                    <tbody><tr v-for="profile in collectorData('firewall').profiles" :key="profile.Name"><td>{{ profile.Name }}</td><td>{{ profile.Enabled }}</td><td>{{ profile.DefaultInboundAction }}</td><td>{{ profile.DefaultOutboundAction }}</td></tr></tbody>
                  </table></div>
                </details>
              </section>

              <section v-if="collectorData('security')" class="inventory-section mb-4">
                <h4 class="h6">Security settings</h4>
                <dl class="security-values"><div v-for="(value, key) in entries(collectorData('security'))" :key="key"><dt>{{ key }}</dt><dd>{{ typeof value === 'object' ? JSON.stringify(value) : String(value) }}</dd></div></dl>
              </section>

              <section v-if="collectorData('scheduledTasks')" class="inventory-section mb-4">
                <h4 class="h6">Scheduled tasks</h4>
                <details class="inventory-detail"><summary>{{ asList(collectorData('scheduledTasks')).length }} tasks</summary>
                  <div class="table-responsive mt-2"><table class="table table-sm table-striped"><thead><tr><th>Task</th><th>State</th><th>Principal</th><th>Run level</th></tr></thead>
                    <tbody><tr v-for="(task, index) in asList(collectorData('scheduledTasks')).slice(0, 250)" :key="`${task.taskPath}-${task.taskName}-${index}`"><td>{{ task.taskPath }}{{ task.taskName }}</td><td>{{ task.state }}</td><td>{{ task.principal }}</td><td>{{ task.runLevel }}</td></tr></tbody>
                  </table></div>
                </details>
              </section>

              <section v-if="collectorData('eventLogs')" class="inventory-section mb-4">
                <h4 class="h6">Event logs</h4>
                <details v-for="log in asList(collectorData('eventLogs'))" :key="log.channel" class="inventory-detail" @toggle="toggleEventLog(log.channel, $event)">
                  <summary>{{ log.channel }} · {{ log.collectedCount || 0 }} / {{ log.recordCount || 0 }} records<span v-if="log.truncated"> · capped</span></summary>
                  <div v-if="openEventLogs.includes(log.channel)" class="table-responsive mt-2 event-log-table">
                    <table class="table table-sm table-striped"><thead><tr><th>Time</th><th>Event</th><th>Level</th><th>Provider / message</th></tr></thead>
                      <tbody><tr v-for="event in log.events" :key="event.recordId"><td>{{ formatDate(event.timeCreated) }}</td><td>{{ event.eventId }}</td><td>{{ event.level }}</td><td><strong>{{ event.provider }}</strong><div>{{ event.message }}</div></td></tr></tbody>
                    </table>
                  </div>
                </details>
              </section>
            </div>
            <p v-else class="text-secondary border rounded-2 bg-white p-3 mb-0">Select a saved audit or run a new one to view results.</p>
          </div>
        </div>
      </section>

      <section class="mb-5">
        <h2 class="h5 mb-3">Approved diagnostic tasks</h2>
        <div v-if="tasks.length" class="row g-3">
          <div v-for="task in tasks" :key="task.id" class="col-12 col-md-6 col-xl-4">
            <div class="card h-100"><div class="card-body d-flex flex-column">
              <h3 class="h6">{{ task.name }}</h3><p class="small text-secondary">{{ task.description }}</p>
              <button class="btn btn-outline-primary mt-auto" :disabled="taskLoading || health !== 'ok'" @click="runTask(task)">{{ taskLoading ? 'Running…' : 'Run diagnostic' }}</button>
            </div></div>
          </div>
        </div>
        <pre v-if="taskResult" class="result-output mt-3">{{ taskResult.stdout || '(No output)' }}</pre>
      </section>

      <section>
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h2 class="h5 mb-0">Recent task history</h2><span class="text-secondary small">{{ history.length }} records</span>
        </div>
        <div class="table-responsive border rounded-2 bg-white">
          <table class="table table-hover align-middle mb-0"><thead class="table-light"><tr><th>Task</th><th>Started</th><th>Status</th><th>Exit code</th></tr></thead>
            <tbody>
              <tr v-for="entry in history" :key="entry.id"><td>{{ entry.task_id }}</td><td>{{ formatDate(entry.started_at) }}</td><td><span class="badge" :class="statusClass(entry.status)">{{ entry.status }}</span></td><td>{{ entry.returncode ?? '—' }}</td></tr>
              <tr v-if="history.length === 0"><td colspan="4" class="text-center text-secondary py-4">No execution history yet.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <footer class="text-secondary small mt-5">PAC v0.1.0 · Local system audit · Read-only collection</footer>
    </main>
  </div>
</template>