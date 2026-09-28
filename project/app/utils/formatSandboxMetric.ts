/**
 * Rendering helper for rule-sandbox validation metrics. Every metric in
 * `RuleSandboxMetrics` carries a companion boolean inside `measured` — when the
 * API reports `measured:false` for a key, the metric was NOT measured in that
 * run and MUST be rendered as 未测量, never as 0 (the backend may legitimately
 * store 0/absent values it could not measure).
 *
 * Pure util so it can be unit tested without mounting a page.
 */

export const UNMEASURED_SANDBOX_TEXT = '未测量'

export interface SandboxMetricView {
  /** Display text; equals 未测量 when the metric was not measured. */
  text: string
  /** Whether the API reported an actual measurement for this metric. */
  measured: boolean
}

/**
 * Formats one sandbox metric value. `measured` comes from
 * `metrics.measured[key]`; when it is false (or the value is null/undefined) the
 * result is 未测量 regardless of the numeric payload — a fabricated 0 is never
 * shown for an unmeasured metric.
 */
export function formatSandboxMetric(
  value: number | null | undefined,
  measured: boolean | undefined,
): SandboxMetricView {
  if (!measured || value === null || value === undefined) {
    return { text: UNMEASURED_SANDBOX_TEXT, measured: false }
  }
  const text = Number.isInteger(value)
    ? new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 0 }).format(value)
    : new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 4 }).format(value)
  return { text, measured: true }
}
