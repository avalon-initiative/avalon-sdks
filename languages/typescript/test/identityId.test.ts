import { describe, expect, it } from 'vitest'
import { mapErrorResponse, RejectedError, UnknownIdSchemeRejectedError } from '../src/errors.js'
import { isIdentityId, parseIdentityId, UnknownIdSchemeError } from '../src/identityId.js'

const ID = '7c26a0e34260b2c5bb6a795e29cdfe878c907df4bf8c7425c5a8ce00235558e9'

function thrown(run: () => unknown): unknown {
  try {
    run()
  } catch (error) {
    return error
  }
  return undefined
}

describe('parseIdentityId', () => {
  it('accepts the canonical form and rejects a trailing newline', () => {
    expect(parseIdentityId(ID)).toBe(ID)
    expect(isIdentityId(`${ID}\n`)).toBe(false)
    expect(thrown(() => parseIdentityId(`${ID}\n`))).toMatchObject({ name: 'UnknownIdSchemeError', length: 65 })
  })

  it('reports another length as an unknown scheme carrying the length', () => {
    expect(thrown(() => parseIdentityId(ID.slice(1)))).toMatchObject({ length: 63 })
    expect(thrown(() => parseIdentityId(''))).toMatchObject({ length: 0 })
    expect(thrown(() => parseIdentityId(ID.slice(1)))).toBeInstanceOf(UnknownIdSchemeError)
  })

  it('counts UTF-8 bytes, not UTF-16 units', () => {
    // 32 two-byte characters are 64 bytes (malformed), 33 are 66 bytes (unknown scheme).
    const malformed = thrown(() => parseIdentityId('é'.repeat(32)))
    expect(malformed).toBeInstanceOf(TypeError)
    expect(malformed).not.toBeInstanceOf(UnknownIdSchemeError)
    expect(thrown(() => parseIdentityId('é'.repeat(33)))).toMatchObject({ length: 66 })
  })

  it('keeps 64 non-hex characters as the generic invalid case', () => {
    const error = thrown(() => parseIdentityId(ID.toUpperCase()))
    expect(error).toBeInstanceOf(TypeError)
    expect(error).not.toBeInstanceOf(UnknownIdSchemeError)
  })
})

describe('UNKNOWN_ID_SCHEME server code', () => {
  it('maps a 400 to a typed rejection carrying the length', async () => {
    const body = { error: 'unknown identity id scheme: 63 characters; a newer version may be required', code: 'UNKNOWN_ID_SCHEME' }
    const error = await mapErrorResponse(new Response(JSON.stringify(body), { status: 400 }))
    expect(error).toBeInstanceOf(UnknownIdSchemeRejectedError)
    expect(error).toBeInstanceOf(RejectedError)
    expect(error).toMatchObject({ code: 'UNKNOWN_ID_SCHEME', status: 400, length: 63 })
  })

  it('leaves INVALID_IDENTITY_ID a plain rejection', async () => {
    const response = new Response(JSON.stringify({ error: 'bad', code: 'INVALID_IDENTITY_ID' }), { status: 400 })
    const error = await mapErrorResponse(response)
    expect(error).toBeInstanceOf(RejectedError)
    expect(error).not.toBeInstanceOf(UnknownIdSchemeRejectedError)
  })
})
