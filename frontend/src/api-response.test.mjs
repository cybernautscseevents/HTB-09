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
