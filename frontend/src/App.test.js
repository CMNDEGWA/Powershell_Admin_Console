// @vitest-environment jsdom
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'

function jsonResponse(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  }
}

describe('audit dashboard', () => {
  let deleted
  let auditCreateError
  let partialAudit

  beforeEach(() => {
    deleted = false
    auditCreateError = false
    partialAudit = false
    window.confirm = vi.fn(() => true)
    globalThis.fetch = vi.fn(async (url, options = {}) => {
      if (url === '/api/health') return jsonResponse({ status: 'ok' })
      if (url === '/api/tasks') return jsonResponse({ tasks: [] })
      if (url === '/api/history?limit=10') return jsonResponse({ history: [] })
      if (url === '/api/system/summary') {
        return jsonResponse({ machine: { platform: 'linux', supportedTarget: true, administrator: true, networkAdapters: [] } })
      }
      if (url === '/api/storage') return jsonResponse({ database_bytes: 4096, audit_count: deleted ? 0 : 1 })
      if (url === '/api/audits?limit=20') {
        return jsonResponse({ audits: deleted ? [] : [{ id: 7, started_at: '2026-10-19T10:00:00Z', status: 'succeeded' }] })
      }
      if (url === '/api/audits' && options.method === 'POST') {
        if (auditCreateError) return jsonResponse({ detail: 'Audit approval was denied.' }, 403)
        return jsonResponse({}, 201)
      }
      if (url === '/api/audits/7' && options.method === 'DELETE') {
        deleted = true
        return jsonResponse({}, 204)
      }
      if (url === '/api/audits/7') {
        return jsonResponse({
          id: 7,
          status: partialAudit ? 'partial' : 'succeeded',
          finished_at: '2026-10-19T10:00:01Z',
          schema_version: 1,
          snapshot: {
            machine: {},
            collectors: partialAudit ? { firewall: { status: 'unavailable', errorCode: 'tool_unavailable' } } : {},
            recommendations: [],
          },
        })
      }
      throw new Error(`Unexpected request: ${options.method || 'GET'} ${url}`)
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows saved audit storage usage', async () => {
    const wrapper = mount(App)
    await flushPromises()

    expect(wrapper.text()).toContain('Local database: 4.0 KB · 1 saved audits')
    expect(wrapper.findAll('[aria-label="Delete audit 7"]')).toHaveLength(1)
    wrapper.unmount()
  })

  it('deletes an audit and refreshes the saved list', async () => {
    const wrapper = mount(App)
    await flushPromises()

    await wrapper.get('[aria-label="Delete audit 7"]').trigger('click')
    await flushPromises()

    expect(window.confirm).toHaveBeenCalledOnce()
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/audits/7', { method: 'DELETE' })
    expect(wrapper.text()).toContain('No saved audits yet.')
    expect(wrapper.text()).toContain('0 saved audits')
    wrapper.unmount()
  })

  it('shows partial collection coverage instead of implying a clean audit', async () => {
    partialAudit = true
    const wrapper = mount(App)
    await flushPromises()

    expect(wrapper.text()).toContain('Some collectors or event logs could not be read.')
    expect(wrapper.text()).toContain('unavailable')
    wrapper.unmount()
  })

  it('shows a clear error when the audit request is denied', async () => {
    auditCreateError = true
    const wrapper = mount(App)
    await flushPromises()

    await wrapper.get('.audit-section button.btn-primary').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Audit approval was denied.')
    wrapper.unmount()
  })
})