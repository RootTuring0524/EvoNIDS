/**
 * Mapping helper for claim → evidence deep links. Every evidence id cited by an
 * investigation claim becomes a NuxtLink target under /evidence/<id> (the
 * evidence detail page). Pure util so the mapping can be unit tested without
 * mounting a component.
 */

export interface EvidenceLinkTarget {
  id: string
  /** Router path of the evidence detail page for this evidence record. */
  to: string
}

/** Router path of one evidence record detail page. */
export function evidenceDetailPath(id: string): string {
  return `/evidence/${encodeURIComponent(id)}`
}

/** Maps a single evidence id to its link target (drops empty ids). */
export function evidenceLinkTarget(id: string): EvidenceLinkTarget | null {
  if (!id) return null
  return { id, to: evidenceDetailPath(id) }
}

/** Maps every claim evidence id to a link target, preserving order. */
export function evidenceLinkTargets(ids: readonly string[]): EvidenceLinkTarget[] {
  return ids
    .map((id) => evidenceLinkTarget(id))
    .filter((target): target is EvidenceLinkTarget => target !== null)
}
