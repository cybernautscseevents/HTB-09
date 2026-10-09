export function readJsonResponse(response: Response, label: string, options?: { allowHttpErrorPayload?: boolean }): Promise<Record<string, unknown>>
export function requireScanResult(value: unknown, label?: string): Record<string, unknown>
