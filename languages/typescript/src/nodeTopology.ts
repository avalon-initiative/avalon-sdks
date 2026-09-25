import { request } from './http.js'
import type { components } from './generated.js'

export type Topology = components['schemas']['TopologyResponse']
export type Neighbor = components['schemas']['Neighbor']
export type KnownPeer = components['schemas']['KnownPeer']
export type MirrorSource = components['schemas']['MirrorSource']
export type ObservedLatency = components['schemas']['ObservedLatency']
export type NetworkCoordinate = components['schemas']['Coordinate']
export type ProbeResult = components['schemas']['ProbeResponse']
export type TraceResult = components['schemas']['TraceResponse']
export type TraceHop = components['schemas']['TraceHop']
export type TraceStopReason = components['schemas']['StopReason']

/** `GET /nodes/topology` on `nodeUrl`: that node's own view of its neighbors,
 * known peers and mirror sources. Public, unauthenticated, no credentials sent. */
export function getTopology(nodeUrl: string, options: { limit?: number; signal?: AbortSignal } = {}): Promise<Topology> {
  const query = options.limit === undefined ? undefined : { limit: String(options.limit) }
  return request<Topology>(nodeUrl, '/nodes/topology', { query, signal: options.signal })
}

/** `POST /nodes/probe`: `nodeUrl` measures its round trip to `target`, which
 * must be in its peer table. `samples` is 1 to 3 (server default 1). */
export function probeNode(nodeUrl: string, target: string, samples?: number): Promise<ProbeResult> {
  const body: components['schemas']['ProbeRequest'] = { target }
  if (samples !== undefined) body.samples = samples
  return request<ProbeResult>(nodeUrl, '/nodes/probe', { method: 'POST', body })
}

/** `POST /nodes/trace`: the overlay route from `nodeUrl` to `target`. Every hop is
 * self-reported by the node it names, so the path is advisory and not verified.
 * `ttl` is 1 to 16 (server default 12). */
export function traceRoute(nodeUrl: string, target: string, options: { ttl?: number } = {}): Promise<TraceResult> {
  const body: components['schemas']['TraceRequest'] = { target }
  if (options.ttl !== undefined) body.ttl = options.ttl
  return request<TraceResult>(nodeUrl, '/nodes/trace', { method: 'POST', body })
}
