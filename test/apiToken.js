'use strict'

const assert = require('assert')

const models = require('../lib/models')
const apiToken = require('../lib/web/auth/apiToken')

function fakeReq (authorization) {
  return { get: name => name.toLowerCase() === 'authorization' ? authorization : undefined }
}

function fakeRes () {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    set (name, value) { this.headers[name] = value; return this },
    status (code) { this.statusCode = code; return this },
    json (body) { this.body = body; return this }
  }
}

// runs the middleware to completion and tells whether it let the request through
function run (check, authorization) {
  return new Promise(function (resolve) {
    const req = fakeReq(authorization)
    const res = fakeRes()
    const done = passed => resolve({ passed, req, res })
    res.json = function (body) { this.body = body; done(false); return this }
    check(req, res, () => done(true))
  })
}

describe('api token', function () {
  let user

  beforeEach(async function () {
    await models.sequelize.sync({ force: true })
    user = await models.User.create({ profileid: 'p1', profile: JSON.stringify({ username: 'alice', provider: 'oauth2' }) })
  })

  it('stores only the hash of a generated token', async function () {
    const { token, expiresAt } = await apiToken.issueToken(user)
    assert.match(token, /^hdt_[A-Za-z0-9_-]{43}$/)
    const stored = await models.User.findByPk(user.id)
    assert.strictEqual(stored.apiTokenHash, apiToken.hashToken(token))
    assert.ok(!JSON.stringify(stored.toJSON()).includes(token))
    assert.strictEqual(expiresAt.getTime() - stored.apiTokenCreatedAt.getTime(), apiToken.TOKEN_LIFETIME)
  })

  it('finds the user of a token and rejects malformed ones', async function () {
    const { token } = await apiToken.issueToken(user)
    assert.strictEqual((await apiToken.findUserByToken(token)).id, user.id)
    assert.strictEqual(await apiToken.findUserByToken(token.slice(0, -1)), null)
    assert.strictEqual(await apiToken.findUserByToken('hdt_' + 'A'.repeat(43)), null)
    assert.strictEqual(await apiToken.findUserByToken(apiToken.hashToken(token)), null)
    assert.strictEqual(await apiToken.findUserByToken(undefined), null)
  })

  it('invalidates the old token on rotation and restarts the lifetime', async function () {
    const first = await apiToken.issueToken(user, 1000)
    const second = await apiToken.issueToken(user, 5000)
    assert.strictEqual(await apiToken.findUserByToken(first.token), null)
    assert.strictEqual((await apiToken.findUserByToken(second.token)).id, user.id)
    assert.strictEqual(second.expiresAt.getTime(), 5000 + apiToken.TOKEN_LIFETIME)
  })

  it('revokes the token', async function () {
    const { token } = await apiToken.issueToken(user)
    await apiToken.revokeToken(user)
    assert.strictEqual(await apiToken.findUserByToken(token), null)
    assert.strictEqual(apiToken.tokenInfo(user), null)
  })

  it('expires exactly after 30 days', async function () {
    await apiToken.issueToken(user, 0)
    assert.strictEqual(apiToken.isTokenExpired(user, apiToken.TOKEN_LIFETIME - 1), false)
    assert.strictEqual(apiToken.isTokenExpired(user, apiToken.TOKEN_LIFETIME), true)
    assert.strictEqual(apiToken.tokenInfo(user, apiToken.TOKEN_LIFETIME).expired, true)
  })

  describe('middleware', function () {
    let token
    let now
    let allowed
    let check

    beforeEach(async function () {
      ({ token } = await apiToken.issueToken(user, 0))
      now = 1000
      allowed = true
      check = apiToken.createApiTokenCheck({ isAllowed: () => allowed, now: () => now })
    })

    it('lets a valid token through and sets the user', async function () {
      const { passed, req } = await run(check, 'Bearer ' + token)
      assert.strictEqual(passed, true)
      assert.strictEqual(req.apiUser.id, user.id)
    })

    it('rejects a missing header', async function () {
      const { passed, res } = await run(check, undefined)
      assert.strictEqual(passed, false)
      assert.strictEqual(res.statusCode, 401)
      assert.strictEqual(res.headers['WWW-Authenticate'], 'Bearer')
    })

    it('rejects a wrong token', async function () {
      const { passed, res } = await run(check, 'Bearer hdt_' + 'B'.repeat(43))
      assert.strictEqual(passed, false)
      assert.strictEqual(res.statusCode, 401)
    })

    it('rejects an expired token with its own message', async function () {
      now = apiToken.TOKEN_LIFETIME
      const { passed, res } = await run(check, 'Bearer ' + token)
      assert.strictEqual(passed, false)
      assert.strictEqual(res.statusCode, 401)
      assert.strictEqual(res.body.error, 'token expired')
    })

    it('rejects a user who may no longer log in', async function () {
      allowed = false
      const { passed, res } = await run(check, 'Bearer ' + token)
      assert.strictEqual(passed, false)
      assert.strictEqual(res.statusCode, 401)
    })

    it('answers 503 when the access check fails', async function () {
      check = apiToken.createApiTokenCheck({ isAllowed: () => Promise.reject(new Error('down')), now: () => now })
      const { passed, res } = await run(check, 'Bearer ' + token)
      assert.strictEqual(passed, false)
      assert.strictEqual(res.statusCode, 503)
    })
  })
})
