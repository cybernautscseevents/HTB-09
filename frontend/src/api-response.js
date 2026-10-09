const ACTIONS = new Set(['ALLOW', 'SANITIZE', 'BLOCK'])

export async function readJsonResponse(response, label, options = {}) {
  const body = await response.text()
  let data = null
  let parseFailed = false

  if (body.trim()) {
    try {
      const parsed = JSON.parse(body)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed
      else parseFailed = true
    } catch {
      parseFailed = true
    }
  }

  if (!response.ok) {
    const detail = typeof data?.detail === 'string' ? data.detail : null
    if (options.allowHttpErrorPayload && data) return data
    const status = `${label} failed (HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ''}).`
    throw new Error(detail || `${status}${parseFailed ? ' The server returned an unreadable response.' : !body.trim() ? ' The server returned an empty response.' : ''}`)
  }

  if (!data) {
    const reason = body.trim() ? 'invalid JSON response' : 'empty response'
    throw new Error(`The ${label} returned an ${reason}.`)
  }
  return data
}

export function requireScanResult(value, label = 'security service') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`The ${label} returned an incomplete scan result.`)
  }
  const result = value
  if (typeof result.threat_detected !== 'boolean'
    || typeof result.threat_type !== 'string'
    || typeof result.risk_score !== 'number'
    || !Number.isFinite(result.risk_score)
    || typeof result.severity !== 'string'
    || !ACTIONS.has(result.action)
    || !Array.isArray(result.reasons)) {
    throw new Error(`The ${label} returned an incomplete scan result.`)
  }
  return result
}
