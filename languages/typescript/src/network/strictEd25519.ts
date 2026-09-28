// Cofactorless Ed25519 verification with a canonical S and a byte-exact R, the same acceptance
// rule as the server's ed25519-dalek `verify`: [S]B - [k]A must encode to exactly the
// signature's R bytes and S must be below the group order. noble's own `verify` is cofactored
// (ZIP-215), so it accepts signatures the server rejects.
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'

const Point = ed25519.Point
const GROUP_ORDER = Point.Fn.ORDER

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let value = 0n
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i])
  return value
}

/** Decodes exactly `[0-9a-fA-F]*` of even length, like Rust `hex::decode`; null otherwise. */
export function strictHexToBytes(hex: unknown): Uint8Array | null {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Whether `key` is acceptable as the key of a `node:` shard: a canonical encoding (y below
 * 2^255-19, and no sign bit on x = 0) of a point that is not of small order.
 */
export function isAcceptableShardKey(key: Uint8Array): boolean {
  if (key.length !== 32) return false
  try {
    return !Point.fromBytes(key, false).isSmallOrder()
  } catch {
    return false
  }
}

/** Cofactorless verification of `signature` (64 bytes) over `message` under `publicKey`; never throws. */
export function verifyCofactorless(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (publicKey.length !== 32 || signature.length !== 64) return false
    const r = signature.slice(0, 32)
    const s = bytesToBigIntLE(signature.slice(32))
    if (s >= GROUP_ORDER) return false
    // Accepts every encoding dalek decompresses (y >= p, x = 0 with the sign bit); the
    // challenge hash uses the key's exact bytes.
    const a = Point.fromBytes(publicKey, true)
    const k = bytesToBigIntLE(sha512(concatBytes(r, publicKey, message))) % GROUP_ORDER
    const sb = s === 0n ? Point.ZERO : Point.BASE.multiplyUnsafe(s)
    const ka = k === 0n ? Point.ZERO : a.multiplyUnsafe(k)
    const recomputed = sb.subtract(ka).toBytes()
    if (recomputed.length !== r.length) return false
    let diff = 0
    for (let i = 0; i < r.length; i += 1) diff |= recomputed[i] ^ r[i]
    return diff === 0
  } catch {
    return false
  }
}
