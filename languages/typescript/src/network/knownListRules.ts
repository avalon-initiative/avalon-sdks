// Client-side known-list rules: the diversity prefix derived from a node URL and the deterministic
// selection of a bounded list. Pure logic shared through conformance/vectors/known-list-selection.json.
// No DNS is resolved, so many domains pointing at one machine look diverse.

export const DEFAULT_KNOWN_LIST_CAPACITY = 5
export const DEFAULT_KNOWN_LIST_ANCHOR_CAPACITY = 2
export const DEFAULT_KNOWN_LIST_MAX_PER_PREFIX = 2

export interface KnownListCandidate {
  witnessKeyId: string
  baseUrl: string
  isAnchor: boolean
}

function validPort(port: string): boolean {
  return /^[0-9]{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535
}

function validHostname(host: string): boolean {
  return (
    host.length > 0 &&
    host.split('.').every((label) => /^[a-z0-9-]+$/.test(label) && !label.startsWith('-') && !label.endsWith('-'))
  )
}

function ipv4Octets(host: string): number[] | null {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) return null
    octets.push(Number(part))
  }
  return octets
}

function ipv6FirstGroups(inner: string): number[] | null {
  const halves = inner.split('::')
  if (halves.length > 2) return null
  const groups = (text: string): string[] | null => {
    if (text === '') return []
    const parts = text.split(':')
    return parts.every((g) => /^[0-9a-f]{1,4}$/.test(g)) ? parts : null
  }
  const head = groups(halves[0])
  if (!head) return null
  let all: string[]
  if (halves.length === 2) {
    const tail = groups(halves[1])
    if (!tail || head.length + tail.length > 7) return null
    all = [...head, ...new Array<string>(8 - head.length - tail.length).fill('0'), ...tail]
  } else {
    if (head.length !== 8) return null
    all = head
  }
  return all.slice(0, 3).map((g) => parseInt(g, 16))
}

/**
 * The diversity prefix for `baseUrl`, or null when it is not an acceptable node URL: http(s), an
 * authority with optional port and at most one trailing slash, no userinfo, path, query or fragment.
 * IPv4 gives `v4:a.b.c.0/24`, bracketed IPv6 `v6:g1:g2:g3::/48`, a hostname `host:` plus its last two labels.
 */
export function diversityPrefixForUrl(baseUrl: string): string | null {
  if (!/^[\x21-\x7e]*$/.test(baseUrl)) return null
  const lower = baseUrl.toLowerCase()
  const rest = lower.startsWith('http://') ? lower.slice(7) : lower.startsWith('https://') ? lower.slice(8) : null
  if (rest === null) return null
  const cut = rest.search(/[/?#]/)
  if (cut >= 0 && rest.slice(cut) !== '/') return null
  const authority = cut >= 0 ? rest.slice(0, cut) : rest
  if (authority === '' || authority.includes('@')) return null

  let host: string
  let port: string | undefined
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']')
    if (close < 0) return null
    host = authority.slice(0, close + 1)
    const tail = authority.slice(close + 1)
    if (tail !== '') {
      if (!tail.startsWith(':')) return null
      port = tail.slice(1)
    }
  } else {
    const parts = authority.split(':')
    if (parts.length > 2) return null
    host = parts[0]
    port = parts[1]
  }
  if (port !== undefined && !validPort(port)) return null

  if (host.startsWith('[')) {
    const inner = host.slice(1, -1)
    if (inner.includes('.')) return null
    const g = ipv6FirstGroups(inner)
    return g ? `v6:${g[0].toString(16)}:${g[1].toString(16)}:${g[2].toString(16)}::/48` : null
  }

  if (host.endsWith('.')) host = host.slice(0, -1)
  if (/^[0-9.]+$/.test(host) && host.includes('.')) {
    const o = ipv4Octets(host)
    return o ? `v4:${o[0]}.${o[1]}.${o[2]}.0/24` : null
  }
  if (!validHostname(host)) return null
  return `host:${host.split('.').slice(-2).join('.')}`
}

/**
 * Admitted witness key ids, in admission order. Anchors are considered first, then the rest, each in
 * the given order; a candidate is refused when already present, over the anchor cap, over capacity,
 * or when its prefix already holds `maxPerPrefix` slots. Callers shuffle the non-anchors first.
 */
export function selectKnownList(
  candidates: KnownListCandidate[],
  capacity: number = DEFAULT_KNOWN_LIST_CAPACITY,
  anchorCapacity: number = DEFAULT_KNOWN_LIST_ANCHOR_CAPACITY,
  maxPerPrefix: number = DEFAULT_KNOWN_LIST_MAX_PER_PREFIX,
): string[] {
  const anchorCap = Math.min(anchorCapacity, capacity)
  const slots: Array<{ id: string; prefix: string; isAnchor: boolean }> = []
  for (const passAnchor of [true, false]) {
    for (const candidate of candidates.filter((c) => c.isAnchor === passAnchor)) {
      const prefix = diversityPrefixForUrl(candidate.baseUrl)
      if (prefix === null) continue
      if (slots.some((s) => s.id === candidate.witnessKeyId)) continue
      if (candidate.isAnchor && slots.filter((s) => s.isAnchor).length >= anchorCap) continue
      if (slots.length >= capacity) continue
      if (slots.filter((s) => s.prefix === prefix).length >= maxPerPrefix) continue
      slots.push({ id: candidate.witnessKeyId, prefix, isAnchor: candidate.isAnchor })
    }
  }
  return slots.map((s) => s.id)
}
