// Console timestamps arrive in two shapes: fixed mock samples use
// 'YYYY-MM-DD HH:mm:ss' while the FastAPI contract emits ISO-8601 instants.
// Rendering the raw tail of either string leaks UTC offsets or dates, so both
// pages funnel through this formatter instead of slicing.
export function formatTimestamp(value: string, mode: 'time' | 'datetime' = 'time') {
  const normalized = value.includes('T') ? value : value.replace(' ', 'T')
  const date = new Date(normalized)
  if (Number.isNaN(date.getTime())) return value
  const time = date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  if (mode === 'time') return time
  return `${date.toLocaleDateString('zh-CN')} ${time}`
}
