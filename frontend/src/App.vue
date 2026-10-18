<script setup>
import { onMounted, ref } from 'vue'

const health = ref('Checking…')
const tasks = ref([])
const history = ref([])
const result = ref(null)
const error = ref('')
const loading = ref(false)

async function apiRequest(path, options = {}) {
  const response = await fetch(path, options)
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data.detail || `Request failed (${response.status})`)
  }

  return data
}

async function loadDashboard() {
  error.value = ''

  try {
    const [healthData, taskData, historyData] = await Promise.all([
      apiRequest('/api/health'),
      apiRequest('/api/tasks'),
      apiRequest('/api/history?limit=10'),
    ])

    health.value = healthData.status
    tasks.value = taskData.tasks
    history.value = historyData.history
  } catch (err) {
    health.value = 'Unavailable'
    error.value = err.message
  }
}

async function runTask(task) {
  loading.value = true
  error.value = ''
  result.value = null

  try {
    result.value = await apiRequest(
      `/api/tasks/${encodeURIComponent(task.id)}/run`,
      { method: 'POST' },
    )

    await loadDashboard()
  } catch (err) {
    error.value = err.message
    await loadDashboard()
  } finally {
    loading.value = false
  }
}

function formatDate(value) {
  if (!value) return '—'

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

onMounted(loadDashboard)
</script>

<template>
  <div class="min-vh-100 bg-body-tertiary">
    <nav class="navbar navbar-dark bg-dark">
      <div class="container">
        <span class="navbar-brand fw-semibold">
          PAC <span class="text-secondary">| Administration Console</span>
        </span>
        <span class="badge" :class="health === 'ok' ? 'text-bg-success' : 'text-bg-secondary'">
          Backend: {{ health }}
        </span>
      </div>
    </nav>

    <main class="container py-4 py-md-5">
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-4">
        <div>
          <h1 class="h3 mb-1">System overview</h1>
          <p class="text-secondary mb-0">
            Run approved diagnostic tasks and review execution history.
          </p>
        </div>

        <button class="btn btn-outline-secondary" @click="loadDashboard">
          Refresh
        </button>
      </div>

      <div v-if="error" class="alert alert-warning" role="alert">
        <strong>Notice:</strong> {{ error }}
        <div class="small mt-1">
          Confirm that the FastAPI server is running on 127.0.0.1:8000.
        </div>
      </div>

      <section class="mb-5">
        <h2 class="h5 mb-3">Approved tasks</h2>

        <div v-if="tasks.length" class="row g-3">
          <div v-for="task in tasks" :key="task.id" class="col-12 col-md-6 col-lg-4">
            <div class="card h-100 shadow-sm">
              <div class="card-body d-flex flex-column">
                <div class="d-flex justify-content-between gap-2">
                  <h3 class="h6">{{ task.name }}</h3>
                  <span class="badge text-bg-light">{{ task.id }}</span>
                </div>

                <p class="text-secondary small">{{ task.description }}</p>

                <button
                  class="btn btn-primary mt-auto"
                  :disabled="loading || health !== 'ok'"
                  @click="runTask(task)"
                >
                  {{ loading ? 'Running…' : 'Run diagnostic' }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <p v-else class="text-secondary">
          No tasks loaded. Check the backend connection and refresh.
        </p>
      </section>

      <section v-if="result" class="mb-5">
        <h2 class="h5 mb-3">Latest execution result</h2>
        <div class="card shadow-sm">
          <div class="card-body">
            <p class="mb-2">
              Task: <strong>{{ result.task_id }}</strong>
            </p>
            <p class="mb-2">
              Exit code:
              <span :class="result.returncode === 0 ? 'text-success' : 'text-danger'">
                {{ result.returncode }}
              </span>
            </p>
            <h3 class="h6 mt-3">Standard output</h3>
            <pre class="result-output">{{ result.stdout || '(No output)' }}</pre>

            <template v-if="result.stderr">
              <h3 class="h6 mt-3">Standard error</h3>
              <pre class="result-output">{{ result.stderr }}</pre>
            </template>
          </div>
        </div>
      </section>

      <section>
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h2 class="h5 mb-0">Recent task history</h2>
          <span class="text-secondary small">{{ history.length }} records</span>
        </div>

        <div class="card shadow-sm">
          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light">
                <tr>
                  <th scope="col">Task</th>
                  <th scope="col">Started</th>
                  <th scope="col">Status</th>
                  <th scope="col">Exit code</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="entry in history" :key="entry.id">
                  <td>{{ entry.task_id }}</td>
                  <td>{{ formatDate(entry.started_at) }}</td>
                  <td>
                    <span
                      class="badge"
                      :class="entry.status === 'succeeded' ? 'text-bg-success' : 'text-bg-danger'"
                    >
                      {{ entry.status }}
                    </span>
                  </td>
                  <td>{{ entry.returncode ?? '—' }}</td>
                </tr>

                <tr v-if="history.length === 0">
                  <td colspan="4" class="text-center text-secondary py-4">
                    No execution history yet.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <footer class="text-secondary small mt-5">
        PAC v0.1.0 · Local development · Only registered tasks are available.
      </footer>
    </main>
  </div>
</template>