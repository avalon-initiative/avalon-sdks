// Mirrors crates/sdk/src/lib.rs's `SdkError` — every outcome a call against
// a real avalon-server can produce, protocol-level rather than a raw
// fetch Response a caller would have to know HTTP to interpret.

export class AvalonSdkError extends Error {
  /** The server's stable, machine-readable error code (for example
   * `ROLLBACK_NOT_REVERSIBLE`), when the failing response carried one.
   * Branch on this rather than on the error class when several distinct
   * failures share one HTTP status. */
  code?: string
  /** The HTTP status of the failing response, when the error came from one. */
  status?: number
  /** Server-requested delay in seconds from a numeric `Retry-After` header
   * (set on 429 responses); absent for the HTTP-date form or no header. */
  retryAfterSeconds?: number
}

/** The session token itself was rejected (expired, unknown, malformed). */
export class UnauthorizedError extends AvalonSdkError {
  constructor() {
    super('unauthorized')
    this.name = 'UnauthorizedError'
  }
}

/** The session token is fine but this integrator/action isn't granted what
 * it needs — thrown client-side by `IntegratorSession`'s own capability
 * check before any request is made, or surfaced from a 403 response. */
export class CapabilityNotGrantedError extends AvalonSdkError {
  constructor(public readonly capability: string) {
    super(`capability not granted: ${capability}`)
    this.name = 'CapabilityNotGrantedError'
  }
}

/** A referenced resource doesn't exist — carries the server's own message. */
export class NotFoundError extends AvalonSdkError {
  constructor(message: string) {
    super(`not found: ${message}`)
    this.name = 'NotFoundError'
  }
}

/** The request conflicts with existing state. */
export class ConflictError extends AvalonSdkError {
  constructor(message: string) {
    super(`conflict: ${message}`)
    this.name = 'ConflictError'
  }
}

/** The server made a final decision not to apply the request — malformed
 * input, a signature that doesn't verify, a business-rule violation. Never
 * worth retrying unchanged. */
export class RejectedError extends AvalonSdkError {
  constructor(public readonly reason: string) {
    super(`rejected: ${reason}`)
    this.name = 'RejectedError'
  }
}

/** A connection error, timeout, or 5xx — a node hiccup, not this request
 * being wrong. */
export class UnavailableError extends AvalonSdkError {
  constructor(public readonly detail: string) {
    super(`avalon-server unavailable: ${detail}`)
    this.name = 'UnavailableError'
  }
}

/** The response didn't parse as the shape this call expected. */
export class ProtocolError extends AvalonSdkError {
  constructor(message: string) {
    super(`unexpected response from avalon-server: ${message}`)
    this.name = 'ProtocolError'
  }
}

/** HTTP 429: a server rate limit rejected the request. Subclasses
 * `ProtocolError`, which 429 previously surfaced as, so existing
 * `instanceof ProtocolError` handling keeps working. */
export class RateLimitedError extends ProtocolError {
  constructor(message: string) {
    super(message)
    this.message = `rate limited: ${message}`
    this.name = 'RateLimitedError'
  }
}

/** The server rejected a conversation read/send with "not a participant" —
 * deliberately carries nothing beyond that: never reveal a
 * block, not even indirectly. */
export class NotConversationParticipantError extends AvalonSdkError {
  constructor() {
    super('not a participant in this conversation')
    this.name = 'NotConversationParticipantError'
  }
}

/** `IntegratorSession.issueAchievement` needs this integrator's own slug
 * and signing key configured — thrown, without any HTTP call, when a
 * caller reaches for issuance without having supplied them. */
export class MissingIssuerCredentialsError extends AvalonSdkError {
  constructor() {
    super("this integrator's slug/signingKey were not configured")
    this.name = 'MissingIssuerCredentialsError'
  }
}

/** A device-pairing/cross-device login was explicitly denied from the
 * approving device. */
export class DeviceLoginDeniedError extends AvalonSdkError {
  constructor() {
    super('device pairing was denied')
    this.name = 'DeviceLoginDeniedError'
  }
}

/** A device-pairing/cross-device login's TTL elapsed before it was
 * approved or denied. */
export class DeviceLoginExpiredError extends AvalonSdkError {
  constructor() {
    super('device pairing expired before it was approved')
    this.name = 'DeviceLoginExpiredError'
  }
}

/** A signature-required `AccountSession` method was called on a session
 * with no local signing key. */
export class NoLocalSigningKeyError extends AvalonSdkError {
  constructor(method: string) {
    super(`${method} requires a local signing key — this AccountSession has none`)
    this.name = 'NoLocalSigningKeyError'
  }
}

function errorForStatus(status: number, message: string): AvalonSdkError {
  switch (status) {
    case 401:
      return new UnauthorizedError()
    case 403:
      return new CapabilityNotGrantedError(message)
    case 404:
      return new NotFoundError(message)
    case 409:
      return new ConflictError(message)
    case 429:
      return new RateLimitedError(message)
    case 400:
    case 422:
      return new RejectedError(message)
    default:
      if (status >= 500) {
        return new UnavailableError(message)
      }
      return new ProtocolError(message)
  }
}

/** Parses `Retry-After` as integer delta-seconds; the HTTP-date form and
 * anything non-numeric yield `undefined`. */
export function parseRetryAfter(value: string | null | undefined): number | undefined {
  if (value == null || !/^\s*\d+\s*$/.test(value)) {
    return undefined
  }
  return Number.parseInt(value, 10)
}

/** Translates a non-success `Response` into the matching typed error,
 * mirroring `crate::http::map_error_response`. Reads the body once as
 * `{ error?: string, code?: string }`, falling back to status text. */
export async function mapErrorResponse(response: Response): Promise<AvalonSdkError> {
  let serverMessage: string | undefined
  let code: string | undefined
  try {
    const body = (await response.json()) as { error?: string; code?: string }
    serverMessage = body.error
    code = body.code
  } catch {
    // Non-JSON or empty body — fall through to a status-only message.
  }
  const message = code ?? serverMessage ?? response.statusText ?? `HTTP ${response.status}`

  const error = errorForStatus(response.status, message)
  error.status = response.status
  const retryAfter = parseRetryAfter(response.headers?.get('retry-after'))
  if (retryAfter !== undefined) {
    error.retryAfterSeconds = retryAfter
  }
  if (code !== undefined) {
    error.code = code
  }
  return error
}
