import test from 'node:test'
import assert from 'node:assert/strict'
import { readJsonResponse, requireScanResult } from './api-response.js'

const validVerdict = {
  threat_detected: false,
  threat_type: 'None',
  risk_score: 0,
  severity: 'Low',
  action: 'ALLOW',
  reasons: [],
}

test('rejects an empty successful response', async () => {
  await assert.rejects(readJsonResponse(new Response('', { status: 200 }), 'Security scan'), /empty response/)
})

test('rejects invalid JSON in a successful response', async () => {
  await assert.rejects(readJsonResponse(new Response('{oops', { status: 200 }), 'Security scan'), /invalid JSON/)
})

test('reports HTTP errors with a server detail when available', async () => {
  const response = new Response(JSON.stringify({ detail: 'Invalid policy' }), { status: 422 })
  await assert.rejects(readJsonResponse(response, 'Document scan'), /Invalid policy/)
})

test('can return a structured HTTP error payload when the caller must inspect a partial result', async () => {
  const payload = { blocked: false, security: validVerdict, model: { called: true, error: 'Model unavailable' } }
  const body = JSON.stringify(payload)
  const response = new Response(body, { status: 503, statusText: 'Service Unavailable' })
  assert.deepEqual(await readJsonResponse(response, 'Security scan', { allowHttpErrorPayload: true }), payload)
  await assert.rejects(readJsonResponse(new Response(body, { status: 503 }), 'Security scan'), /HTTP 503/)
})

test('still rejects empty and non-JSON error payloads when partial results are allowed', async () => {
  await assert.rejects(readJsonResponse(new Response('', { status: 503 }), 'Security scan', { allowHttpErrorPayload: true }), /HTTP 503.*empty response/)
  await assert.rejects(readJsonResponse(new Response('unavailable', { status: 503 }), 'Security scan', { allowHttpErrorPayload: true }), /HTTP 503.*unreadable response/)
})

test('reports HTTP errors when the body is empty or unreadable', async () => {
  await assert.rejects(readJsonResponse(new Response('', { status: 503 }), 'Batch scan'), /HTTP 503.*empty response/)
  await assert.rejects(readJsonResponse(new Response('not-json', { status: 502 }), 'Batch scan'), /HTTP 502.*unreadable response/)
})

test('accepts valid JSON and a complete ALLOW verdict', async () => {
  const data = await readJsonResponse(new Response(JSON.stringify(validVerdict), { status: 200 }), 'Security scan')
  assert.deepEqual(requireScanResult(data), validVerdict)
})

test('rejects incomplete verdicts instead of treating them as ALLOW', () => {
  assert.throws(() => requireScanResult({ action: 'ALLOW' }), /incomplete scan result/)
  assert.throws(() => requireScanResult({ ...validVerdict, action: 'UNKNOWN' }), /incomplete scan result/)
})
