'use strict'

const assert = require('assert')

const { createMembershipChecker } = require('../lib/web/auth/oauth2/recheck')

const URL_ORGS = 'https://forge.example.org/api/v1/user/orgs'
const silentLogger = { info () {}, warn () {} }

// fake node-oauth client: `members` maps access tokens to their organization
// names, `httpError` forces an error on the organization endpoint
function fakeClient (options) {
  const client = {
    calls: 0,
    refreshes: 0,
    get (url, accessToken, cb) {
      client.calls++
      if (options.httpError) return cb(options.httpError)
      if (!(accessToken in options.members)) return cb({ statusCode: 401, data: 'expired' })
      const page = parseInt(new URL(url).searchParams.get('page'), 10)
      const orgs = page === 1 ? options.members[accessToken].map(username => ({ username })) : []
      cb(null, JSON.stringify(orgs))
    },
    getOAuthAccessToken (refreshToken, params, cb) {
      client.refreshes++
      assert.strictEqual(params.grant_type, 'refresh_token')
      if (options.refreshError) return cb(options.refreshError)
      cb(null, 'new-access', 'new-refresh')
    }
  }
  return client
}

function fakeUser (accessToken) {
  return {
    id: 'user-1',
    accessToken,
    refreshToken: 'refresh',
    saved: 0,
    save () {
      this.saved++
      return Promise.resolve(this)
    }
  }
}

function checker (client, clock) {
  return createMembershipChecker({
    oauth2Client: client,
    workspacesURL: URL_ORGS,
    workspace: 'Aquila-consortium',
    interval: 1000,
    logger: silentLogger,
    now: () => clock.time
  })
}

describe('oauth2 createMembershipChecker', function () {
  it('checks on first use, then caches the result for the interval', async function () {
    const clock = { time: 0 }
    const client = fakeClient({ members: { access: ['Aquila-consortium'] } })
    const isStillMember = checker(client, clock)
    const user = fakeUser('access')

    assert.strictEqual(await isStillMember(user), true)
    clock.time = 999
    assert.strictEqual(await isStillMember(user), true)
    assert.strictEqual(client.calls, 1)
  })

  it('ends the session once the user has left the workspace', async function () {
    const clock = { time: 0 }
    const members = { access: ['Aquila-consortium'] }
    const client = fakeClient({ members })
    const isStillMember = checker(client, clock)
    const user = fakeUser('access')

    assert.strictEqual(await isStillMember(user), true)
    members.access = ['other']
    clock.time = 1000
    assert.strictEqual(await isStillMember(user), false)
  })

  it('refreshes an expired access token and saves the new tokens', async function () {
    const clock = { time: 0 }
    const client = fakeClient({ members: { 'new-access': ['Aquila-consortium'] } })
    const user = fakeUser('expired')

    assert.strictEqual(await checker(client, clock)(user), true)
    assert.strictEqual(client.refreshes, 1)
    assert.strictEqual(user.accessToken, 'new-access')
    assert.strictEqual(user.refreshToken, 'new-refresh')
    assert.strictEqual(user.saved, 1)
  })

  it('ends the session when the refresh token is rejected', async function () {
    const clock = { time: 0 }
    const client = fakeClient({ members: {}, refreshError: { statusCode: 400, data: 'invalid_grant' } })

    assert.strictEqual(await checker(client, clock)(fakeUser('expired')), false)
  })

  it('keeps the session and retries later when Forgejo is unreachable', async function () {
    const clock = { time: 0 }
    const client = fakeClient({ members: {}, httpError: { statusCode: 502, data: 'bad gateway' } })
    const isStillMember = checker(client, clock)
    const user = fakeUser('access')

    assert.strictEqual(await isStillMember(user), true)
    assert.strictEqual(client.calls, 1)
    clock.time = 59 * 1000
    await isStillMember(user)
    assert.strictEqual(client.calls, 1)
    clock.time = 60 * 1000
    await isStillMember(user)
    assert.strictEqual(client.calls, 2)
  })

  it('shares one check between concurrent requests', async function () {
    const clock = { time: 0 }
    const client = fakeClient({ members: { 'new-access': ['Aquila-consortium'] } })
    const isStillMember = checker(client, clock)
    const user = fakeUser('expired')

    const results = await Promise.all([isStillMember(user), isStillMember(user), isStillMember(user)])
    assert.deepStrictEqual(results, [true, true, true])
    assert.strictEqual(client.refreshes, 1)
  })
})
