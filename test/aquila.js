'use strict'

const assert = require('assert')

const { fetchSuperuser, createSuperuserRefresher } = require('../lib/web/auth/oauth2/aquila')

const URL_STATUS = 'https://www.example.org/dynamic/admin/members/superuser_status.php'
const silentLogger = { info () {} }

// fake fetch answering with `status` and `body`, recording its calls
function fakeFetch (status, body) {
  const calls = []
  const impl = function (url, options) {
    calls.push({ url, options })
    if (status instanceof Error) return Promise.reject(status)
    return Promise.resolve({
      status,
      json: () => Promise.resolve(body)
    })
  }
  impl.calls = calls
  return impl
}

function fakeUser (login, superuser) {
  return {
    id: 'user-1',
    profile: JSON.stringify({ username: login, provider: 'oauth2' }),
    superuser,
    saved: 0,
    save () {
      this.saved++
      return Promise.resolve(this)
    }
  }
}

describe('aquila fetchSuperuser', function () {
  it('sends the login and the bearer secret', async function () {
    const fetchImpl = fakeFetch(200, { username: 'jane', superuser: true })
    assert.strictEqual(await fetchSuperuser({ url: URL_STATUS, token: 's3cret', login: 'jane doe', fetchImpl }), true)
    assert.strictEqual(fetchImpl.calls[0].url, URL_STATUS + '?username=jane+doe')
    assert.strictEqual(fetchImpl.calls[0].options.headers.Authorization, 'Bearer s3cret')
  })

  it('reports a plain member as not a superuser', async function () {
    const fetchImpl = fakeFetch(200, { username: 'john', superuser: false })
    assert.strictEqual(await fetchSuperuser({ url: URL_STATUS, token: 't', login: 'john', fetchImpl }), false)
  })

  it('treats an unknown member as not a superuser', async function () {
    const fetchImpl = fakeFetch(404, { error: 'unknown member' })
    assert.strictEqual(await fetchSuperuser({ url: URL_STATUS, token: 't', login: 'nobody', fetchImpl }), false)
  })

  it('rejects on any other HTTP status', async function () {
    const fetchImpl = fakeFetch(500, {})
    await assert.rejects(fetchSuperuser({ url: URL_STATUS, token: 't', login: 'jane', fetchImpl }), /HTTP 500/)
  })

  it('rejects an answer without a boolean superuser', async function () {
    const fetchImpl = fakeFetch(200, { superuser: 'yes' })
    await assert.rejects(fetchSuperuser({ url: URL_STATUS, token: 't', login: 'jane', fetchImpl }))
  })
})

describe('aquila createSuperuserRefresher', function () {
  it('stores a new superuser status and saves the user', async function () {
    const user = fakeUser('jane', false)
    const refresh = createSuperuserRefresher({ url: URL_STATUS, token: 't', logger: silentLogger, fetchImpl: fakeFetch(200, { superuser: true }) })
    await refresh(user)
    assert.strictEqual(user.superuser, true)
    assert.strictEqual(user.saved, 1)
  })

  it('does not save when the status is unchanged', async function () {
    const user = fakeUser('jane', true)
    const refresh = createSuperuserRefresher({ url: URL_STATUS, token: 't', logger: silentLogger, fetchImpl: fakeFetch(200, { superuser: true }) })
    await refresh(user)
    assert.strictEqual(user.saved, 0)
  })

  it('keeps the stored status when aquila-website is unreachable', async function () {
    const user = fakeUser('jane', true)
    const refresh = createSuperuserRefresher({ url: URL_STATUS, token: 't', logger: silentLogger, fetchImpl: fakeFetch(new Error('ECONNREFUSED')) })
    await assert.rejects(refresh(user))
    assert.strictEqual(user.superuser, true)
    assert.strictEqual(user.saved, 0)
  })

  it('clears the flag when aquila-website is not configured', async function () {
    const user = fakeUser('jane', true)
    const fetchImpl = fakeFetch(200, { superuser: true })
    const refresh = createSuperuserRefresher({ url: undefined, token: undefined, logger: silentLogger, fetchImpl })
    await refresh(user)
    assert.strictEqual(user.superuser, false)
    assert.strictEqual(fetchImpl.calls.length, 0)
  })
})
