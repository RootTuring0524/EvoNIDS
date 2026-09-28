import type { SensorMetric } from '../../shared/types/security'

/**
 * Rendering helper for backend `SensorMetric` telemetry. A metric with
 * `measured: false` (or `value: null`) is an explicit "not measured" state and
 * MUST be rendered as 未测量 — never as 0 or as an empty dash.
 *
 * Kept as a pure util so it can be unit tested without mounting a page.
 */

export const UNMEASURED_TEXT = '未测量'

const UNIT_LABELS: Record<string, string> = {
  ratio: '%',
  ms: '毫秒',
  seconds: '秒',
  gaps: '次',
}

/** Localised unit label; unknown units fall back to the raw API unit string. */
export function sensorMetricUnitLabel(unit: string): string {
  return UNIT_LABELS[unit] ?? unit
}

function formatNumber(value: number, maxFractionDigits: number): string {
  return new Intl.NumberFormat('zh-CN', { maximumFractionDigits: maxFractionDigits }).format(value)
}

export interface SensorMetricView {
  /** Display text (no unit suffix); equals 未测量 when the metric was not measured. */
  text: string
  /** Whether the API reported an actual measurement for this window. */
  measured: boolean
  /** Localised unit label (e.g. 毫秒, 秒, %, 次). */
  unit: string
  /** Backend explanation, shown under the value when present. */
  note: string | null
}

/**
 * Formats one SensorMetric. `ratio` values are emitted as a percentage by
 * multiplying the API ratio by 100 — a deterministic unit conversion, not
 * invented data. All other values are rendered verbatim from the API.
 */
export function formatSensorMetric(metric: SensorMetric): SensorMetricView {
  const { value, measured, unit, note } = metric
  if (!measured || value === null) {
    return { text: UNMEASURED_TEXT, measured: false, unit: sensorMetricUnitLabel(unit), note }
  }
  const localizedUnit = sensorMetricUnitLabel(unit)
  if (unit === 'ratio') {
    return { text: formatNumber(value * 100, 2), measured: true, unit: localizedUnit, note }
  }
  // Keep at most 2 decimals: latency/skew may be fractional, counters stay integral.
  const text = Number.isInteger(value)
    ? formatNumber(value, 0)
    : formatNumber(value, 2)
  return { text, measured: true, unit: localizedUnit, note }
}
